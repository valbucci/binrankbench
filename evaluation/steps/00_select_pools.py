import json
import pandas as pd
from sqlalchemy import select, func, exists, case, and_, text
from sqlalchemy.orm import aliased, Session
import sys
import hashlib
import logging
from pathlib import Path

from tqdm import tqdm

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from binrankbench.common.hex import hexvalue_to_bytes, HexValue
from binrankbench.storage.models.core import (
    FunctionScalars,
    Function,
    FunctionName,
    Binary,
    Project,
)
from binrankbench.storage.models.signatures.bytes import (
    FunctionByteSig,
    ByteFingerprint,
    ByteSequence,
)
from binrankbench.storage.models.signatures.catalog1 import FunctionCatalog1
from binrankbench.storage.models.signatures.machoke import FunctionMachoke
from binrankbench.storage.models.signatures.fss import FunctionFSSOriginal
from binrankbench.storage.models.signatures.ccbhash import FunctionCCBHash
from binrankbench.storage.models.dataset import BinaryDatasetTag, Dataset
from binrankbench.storage.session import get_engine, make_session_factory
from evaluation.utils.logging_utils import setup_logging
from evaluation.utils.constants import BUCKET_LABELS
from evaluation.utils.context import INTERMEDIATE_DIR, FIXTURES_DIR
from evaluation.utils.fixtures_common import compute_boundaries_from_nbbs

setup_logging(__file__)


class HashIndexer:
    """Global tracker to assign consistent integer IDs to unique blake2b hashes."""

    def __init__(self):
        self.hash_to_id: dict[bytes, int] = {}
        self.current_id = 0

    def get_id(self, hash_item: HexValue | float) -> int:
        if pd.isna(hash_item) or not hash_item:
            return -1  # Special ID for missing/empty byte sequences

        if not isinstance(hash_item, bytes):
            if isinstance(hash_item, float):
                return self.get_id(int(hash_item))
            else:
                hash_item = hexvalue_to_bytes(hash_item)

        if hash_item not in self.hash_to_id:
            self.hash_to_id[hash_item] = self.current_id
            self.current_id += 1
        return self.hash_to_id[hash_item]


def get_pic_hash(raw, mask):
    """Hash Position-Indepondent Code (PIC) using blake2b.
    Used to deduplicate trivial function pairs."""
    if pd.isna(raw) or pd.isna(mask) or not raw or not mask:
        return None
    if len(raw) != len(mask):
        logging.error(
            f"Length mismatch: raw({len(raw)}) vs mask({len(mask)}). Skipping hash."
        )
        return None

    # Apply PIC mask
    masked_bytes = bytes(r & m for r, m in zip(raw, mask))
    return hashlib.blake2b(masked_bytes, digest_size=16).hexdigest()


def process_dataframe_hashes(df: pd.DataFrame, indexer: HashIndexer) -> pd.DataFrame:
    print(f"  -> Applying bitwise masks and hashing {len(df)} rows...")
    df.loc[:, "PIC_hash"] = [
        get_pic_hash(r, m) for r, m in zip(df["raw_bytes"], df["mask_bytes"])
    ]
    print("  -> Mapping hashes to integer indices (Missing data -> -1)...")
    df.loc[:, "PIC_id"] = [indexer.get_id(h) for h in df["PIC_hash"]]
    df.drop(columns=["raw_bytes", "mask_bytes"], inplace=True)
    initial_len = len(df)
    df = df[df["PIC_id"] != -1].copy()
    if len(df) < initial_len:
        print(
            f"  -> Dropped {initial_len - len(df)} rows due to missing/invalid byte masks."
        )
    return df


def fetch_bytes_in_chunks(session: Session, function_ids: list[int], chunk_size=50000):
    print(
        f"  -> Fetching bytes for {len(function_ids)} functions in chunks of {chunk_size}..."
    )
    RawByteSeq = aliased(ByteSequence, name="raw_byte_seq")
    MaskByteSeq = aliased(ByteSequence, name="mask_byte_seq")
    records = []
    for i in tqdm(
        range(0, len(function_ids), chunk_size), desc="Fetching bytes chunks"
    ):
        chunk = function_ids[i : i + chunk_size]
        stmt = (
            select(
                Function.id.label("function_id"),
                FunctionScalars.nbbs.label("nbbs"),
                RawByteSeq.bytes_sequence.label("raw_bytes"),
                MaskByteSeq.bytes_sequence.label("mask_bytes"),
            )
            .select_from(Function)
            .outerjoin(Function.scalars)
            .outerjoin(Function.byte_sig)
            .outerjoin(FunctionByteSig.fingerprint)
            .outerjoin(RawByteSeq, ByteFingerprint.raw_bytes_id == RawByteSeq.id)
            .outerjoin(MaskByteSeq, ByteFingerprint.nibble_mask_id == MaskByteSeq.id)
            .where(Function.id.in_(chunk))
        )
        chunked_records = session.execute(stmt).mappings().all()
        records.extend(chunked_records)
    return pd.DataFrame(records)


def fetch_dataframe_in_chunks(session: Session, stmt, chunk_size=100000):
    """Safely loads a large SQLAlchemy statement into a Pandas DataFrame."""
    chunked_statement = stmt.execution_options(yield_per=chunk_size)
    result = session.execute(chunked_statement).mappings()
    return pd.DataFrame(result.all())


class AttritionTracker:
    """Tracks function counts and retention percentages across filtering stages."""

    def __init__(self, name: str, baseline_stage: int = 0):
        self.name = name
        self.stages = []
        self.baseline_stage = baseline_stage
        self.baseline_count = None

    def add_stage(self, label: str, count: int):
        self.stages.append({"Stage": label, "Count": count})
        if len(self.stages) - 1 == self.baseline_stage:
            self.baseline_count = count

    def to_dataframe(self):
        df = pd.DataFrame(self.stages)
        if self.baseline_count and self.baseline_count > 0:
            df.loc[:, "Step Retention %"] = (df["Count"] / self.baseline_count) * 100
        else:
            df.loc[:, "Step Retention %"] = 100.0
        return df

    def save(self, path: Path):
        self.to_dataframe().to_csv(path, index=False)
        print(f"\n[!] Attrition report saved to: {path.name}")


def run_strategy_audit(session, baseline_ids):
    """Ensures that all strategies are available for the given function IDs.
    
    Returns counts of functions with each strategy and final list of functions 
    that have all strategies (gold standard).
    """
    if not baseline_ids:
        return (0, 0, 0, 0, 0), []
    subq_cat = exists().where(FunctionCatalog1.function_id == Function.id)
    subq_machoke = exists().where(FunctionMachoke.function_id == Function.id)
    subq_fss = exists().where(FunctionFSSOriginal.function_id == Function.id)
    subq_ccb = exists().where(FunctionCCBHash.function_id == Function.id)
    subq_zig = exists().where(FunctionByteSig.function_id == Function.id)
    is_gold = and_(subq_zig, subq_cat, subq_machoke, subq_fss, subq_ccb)
    
    total_cat, total_machoke, total_fss, total_ccb, total_gold = 0, 0, 0, 0, 0
    gold_ids = []
    chunk_size = 30000
    for i in tqdm(
        range(0, len(baseline_ids), chunk_size), desc="  -> Auditing strategies"
    ):
        chunk = baseline_ids[i : i + chunk_size]
        # Get counts for the stages
        stmt_counts = (
            select(
                func.sum(case((and_(subq_zig, subq_cat), 1), else_=0)),
                func.sum(case((and_(subq_zig, subq_machoke), 1), else_=0)),
                func.sum(case((and_(subq_zig, subq_fss), 1), else_=0)),
                func.sum(case((and_(subq_zig, subq_ccb), 1), else_=0)),
                func.sum(case((is_gold, 1), else_=0)),
            )
            .select_from(Function)
            .where(Function.id.in_(chunk))
        )
        res = session.execute(stmt_counts).fetchone()
        if res:
            total_cat += (res[0] or 0)
            total_machoke += (res[1] or 0)
            total_fss += (res[2] or 0)
            total_ccb += (res[3] or 0)
            total_gold += (res[4] or 0)
        
        # Collect IDs for the Gold Standard
        stmt_ids = select(Function.id).where(Function.id.in_(chunk), is_gold)
        gold_ids.extend(session.execute(stmt_ids).scalars().all())
        
    return (total_cat, total_machoke, total_fss, total_ccb, total_gold), gold_ids


def write_bucket_boundaries(nbbs: list[int]) -> None:
    """Query Dataset-1 percentiles and write evaluation/fixtures/bucket_boundaries.json."""
    FIXTURES_DIR.mkdir(exist_ok=True)
    boundaries = compute_boundaries_from_nbbs(nbbs)
    out = FIXTURES_DIR / "bucket_boundaries.json"
    out.write_text(json.dumps({"bucket_labels": BUCKET_LABELS, "boundaries": boundaries}, indent=2))
    print(f"  -> Bucket boundaries written: {out}")


def generate_evaluation_pools(session):
    INTERMEDIATE_DIR.mkdir(exist_ok=True)
    # Prevent shared memory exhaustion during large joins
    session.execute(text("SET max_parallel_workers_per_gather = 0;"))

    # We get the clean function name by stripping autogenerated radare2 prefix 'sym.'
    clean_name = func.replace(FunctionName.name, "sym.", "")
    # real_binname follows the last underscore character
    real_binname = func.substr(Binary.bin_name, func.strpos(Binary.bin_name, "_") + 1)

    # Trackers for both pools
    tracker1 = AttritionTracker("Tier 1 - Target Pool", baseline_stage=4)
    tracker2 = AttritionTracker("Tier 2 - Haystack Pool", baseline_stage=4)

    # 0. Total Population
    q_total = (
        select(func.count(Function.id))
        .join(BinaryDatasetTag, Function.binary_id == BinaryDatasetTag.binary_id)
        .join(Dataset, BinaryDatasetTag.dataset_id == Dataset.id)
        .where(Dataset.name == "cisco-talos_dataset1")
    )
    total_pop = session.execute(q_total).scalar()
    tracker1.add_stage("0. Total Dataset Population", total_pop)
    tracker2.add_stage("0. Total Dataset Population", total_pop)

    print("\n[+] Universal Filtering: Extraction and Structural Qualification...")
    # 1. Structural Qualification (nbbs >= 5)
    stmt_meta = (
        select(
            Function.id.label("function_id"),
            Function.binary_id,
            Project.name.label("project_name"),
            real_binname.label("real_binname"),
            clean_name.label("func_name"),
        )
        .select_from(Function)
        .outerjoin(FunctionName, Function.name_id == FunctionName.id)
        .join(Binary, Function.binary_id == Binary.id)
        .join(Project, Binary.project_id == Project.id)
        .join(FunctionScalars, Function.id == FunctionScalars.function_id)
        .join(BinaryDatasetTag, Binary.id == BinaryDatasetTag.binary_id)
        .join(Dataset, BinaryDatasetTag.dataset_id == Dataset.id)
        .where(
            FunctionScalars.nbbs >= 5,
            Dataset.name == "cisco-talos_dataset1",
        )
    )
    df_meta = fetch_dataframe_in_chunks(session, stmt_meta)
    tracker1.add_stage("1. Structural Qualification (nbbs >= 5)", len(df_meta))
    tracker2.add_stage("1. Structural Qualification (nbbs >= 5)", len(df_meta))

    # 2. Isolation (Unique to Binary)
    print("  -> Enforcing Code-Reuse Prevention (Isolation)...")
    named_mask = df_meta["func_name"].notna()
    df_meta.loc[named_mask, "bin_appearance_count"] = df_meta[named_mask].groupby("func_name")[
        "real_binname"
    ].transform("nunique")
    df_isolated = df_meta[~named_mask | (df_meta["bin_appearance_count"] == 1)].copy()
    tracker1.add_stage("2. Isolation (Unique to Binary)", len(df_isolated))
    tracker2.add_stage("2. Isolation (Unique to Binary)", len(df_isolated))

    # 3. Zignature Availability
    print("  -> Verifying Machine Code availability (Zignatures)...")
    valid_ids = df_isolated["function_id"].tolist()
    df_bytes = fetch_bytes_in_chunks(session, valid_ids)
    # Merging bytes drops functions without zignatures (inner join)
    df_with_zig = pd.merge(df_isolated, df_bytes, on="function_id", how="inner")
    tracker1.add_stage("3. Zignature Availability", len(df_with_zig))
    tracker2.add_stage("3. Zignature Availability", len(df_with_zig))

    # 4. [Baseline] Unique PIC Signatures (Deduplication)
    print("  -> Applying PIC-Hash Deduplication...")
    indexer = HashIndexer()
    df_with_hashes = process_dataframe_hashes(df_with_zig, indexer)
    df_dedup = df_with_hashes.drop_duplicates(subset=["PIC_id"], keep="first").copy()
    tracker1.add_stage("4. [Baseline] Unique PIC Signatures", len(df_dedup))
    tracker2.add_stage("4. [Baseline] Unique PIC Signatures", len(df_dedup))

    # 5-9. Integrity Audit (Strategy Coverage)
    print("\n[+] Integrity Audit: Algorithmic Artefact Coverage...")
    baseline_ids = df_dedup["function_id"].tolist()
    counts, gold_ids = run_strategy_audit(session, baseline_ids)
    
    stages = [
        ("5. Coverage: has Catalog1", counts[0]),
        ("6. Coverage: has Machoke", counts[1]),
        ("7. Coverage: has FSS", counts[2]),
        ("8. Coverage: has CCBHash", counts[3]),
        ("9. ALL STRATEGIES AVAILABLE", counts[4]),
    ]
    for label, count in stages:
        tracker1.add_stage(label, count)
        tracker2.add_stage(label, count)

    # Save Tier 2 Attrition and Pool
    tracker2.save(INTERMEDIATE_DIR / "tier2_attrition.csv")
    df_tier2_final = df_dedup[df_dedup["function_id"].isin(gold_ids)].copy()
    # Save Tier 2 Pool with nbbs for later bucketing
    df_tier2_final[["function_id", "nbbs", "PIC_id", "PIC_hash"]].to_csv(
        INTERMEDIATE_DIR / "tier2_pool.csv", index=False
    )
    print(f"  -> Tier 2 Pool saved: {len(df_tier2_final)} unique signatures.")

    # --- TIER 1 SPECIFIC ---
    # 10. Persistence Thresholding (Only on Gold Standard survivors)
    print("\n[+] Target Isolation: Persistence Thresholding...")
    df_gold = df_dedup[df_dedup["function_id"].isin(gold_ids)].copy()
    df_gold.loc[:, "persistence_count"] = df_gold.groupby(
        ["project_name", "real_binname", "func_name"]
    )["binary_id"].transform("nunique")
    df_tier1_final = df_gold[df_gold["persistence_count"] >= 2].copy()
    tracker1.add_stage("10. Persistence Thresholding (Vars >= 2)", len(df_tier1_final))

    tracker1.save(INTERMEDIATE_DIR / "tier1_attrition.csv")
    # Save Tier 1 Pool without nbbs as bucketing on this pool is not performed
    df_tier1_final[["function_id", "PIC_id", "PIC_hash"]].to_csv(
        INTERMEDIATE_DIR / "tier1_pool.csv", index=False
    )
    print(f"  -> Tier 1 Pool saved: {len(df_tier1_final)} target functions.")

    print("\n[+] Computing bucket boundaries...")
    write_bucket_boundaries(df_tier2_final["nbbs"].tolist())


if __name__ == "__main__":
    engine = get_engine()
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as session:
        generate_evaluation_pools(session)

