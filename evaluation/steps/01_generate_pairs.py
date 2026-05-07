from sqlalchemy import select, func
import pandas as pd
import numpy as np
from sqlalchemy.orm import Session
from tqdm import tqdm
import sys
from pathlib import Path
from typing import TypedDict

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from binrankbench.storage.models.core import (
    Function, FunctionName, Binary, Project
)
from binrankbench.storage.models.signatures.bytes import (
    FunctionByteSig, ByteFingerprint
)
from binrankbench.storage.session import get_engine, make_session_factory
from evaluation.utils.logging_utils import setup_logging
from evaluation.utils.context import INTERMEDIATE_DIR, SIMILARITY_DIR, TIER1_POOL_CSV, TIER2_POOL_CSV
from evaluation.utils.constants import ARCH_FAMILY_MAP, BITNESS_MAP, RANDOM_SEED

log = setup_logging(__file__)
SIMILARITY_DIR.mkdir(parents=True, exist_ok=True)
TIER1_METADATA_CSV = INTERMEDIATE_DIR / "tier1_function_metadata.csv"

CONFIGS = {
    "1vN": {
        "n_positives": 14000,
        "n_distractors_per_anchor": 100, 
        "scenarios": ["XO", "XA", "XC", "XC_XB", "XA_XO", "XM", "XZ"]
    },
    "1v1": {
        "n_positives": 500000,
        "n_distractors_per_anchor": 1,
        "scenarios": ["arch", "bit", "comp", "ver", "opt", "XZ"]
    }
}


def fetch_function_metadata(session: Session, function_ids: list[int]) -> pd.DataFrame:
    """Fetch metadata for a list of function IDs."""
    clean_name = func.replace(FunctionName.name, "sym.", "")
    stmt = (
        select(
            Function.id.label("function_id"),
            Binary.bin_name,
            Project.name.label("project"),
            clean_name.label("func_name"),
            ByteFingerprint.raw_bytes_id,
            ByteFingerprint.nibble_mask_id,
        )
        .join(FunctionName, Function.name_id == FunctionName.id)
        .join(Binary, Function.binary_id == Binary.id)
        .join(Project, Binary.project_id == Project.id)
        .outerjoin(FunctionByteSig)
        .outerjoin(ByteFingerprint)
        .where(Function.id.in_(function_ids))
    )
    records = session.execute(stmt).mappings().all()
    return pd.DataFrame(records)


def fetch_function_metadata_in_chunks(session: Session, function_ids: list[int],
                                      chunk_size: int = 10_000) -> pd.DataFrame:
    records = []
    for i in tqdm(range(0, len(function_ids), chunk_size), desc="  -> Fetching metadata"):
        chunk = function_ids[i : i + chunk_size]
        chunk_results = fetch_function_metadata(session, chunk)
        records.extend(chunk_results.to_dict("records"))
    return pd.DataFrame(records)


class BinaryMetadata(TypedDict):
    index: int          # The index of the binary in the original DataFrame\
    real_binname: str   # The actual binary name (e.g. padlock.so)
    
    arch: str           # The architecture (e.g. x86, arm32, mips64)
    arch_family: str    # The architecture family (e.g. x86, arm, mips)
    bitness: int        # The bitness (32 or 64)
    
    compiler: str       # The compiler+version (e.g. clang-3.5)
    cc: str             # The compiler family (e.g. clang)
    version: str        # The compiler version (e.g. 3.5)
    
    opt: str            # The optimization level (e.g. O0, O1, O2, O3, Os)
    
def parse_binary_metadata(index: int, bin_name: str) -> BinaryMetadata:
    """Parse the binary name to extract metadata following Marcelli et al. (2022) 
    dataset convention.
    
    Example: arm32-clang-3.5-O0_padlock.so
    """
    # Make sure there is exactly one underscore in the bin_name
    if bin_name.count("_") != 1:
        raise ValueError(f"Invalid binary name format: {bin_name}. Expected exactly one underscore.")
    
    config, real_binname = bin_name.split("_")
    
    # Make sure there are exactly 3 hyphens in the config
    if config.count("-") != 3:
        raise ValueError(f"Invalid config format: {config}. Expected exactly three hyphens.")
    
    arch, comp, ver, opt = config.split("-")
    try:
        arch_family = ARCH_FAMILY_MAP[arch]
        bitness = BITNESS_MAP[arch]
    except KeyError:
        raise ValueError(f"Unknown architecture/bitness: {arch} in binary name: {bin_name}")
    
    return BinaryMetadata(
        index=index,
        real_binname=real_binname,
        arch=arch,
        arch_family=arch_family,
        bitness=bitness,
        compiler=f"{comp}-{ver}",
        cc=comp,
        version=ver,
        opt=opt
    )
    
    
def join_binary_metadata(df: pd.DataFrame) -> pd.DataFrame:
    """Join binary metadata to the DataFrame based on the 'bin_name' column."""
    # Convert from TypedDict to normal dict for joining later
    bin_meta_records = [parse_binary_metadata(idx, bn)
                        for idx, bn in zip(df.index, df['bin_name'])]
    df_bin_meta = pd.DataFrame(bin_meta_records)
    df_bin_meta.set_index('index', inplace=True)
    return df.join(df_bin_meta, how='left')


def generate_negatives(config_name: str, negatives_pool: pd.DataFrame, 
                      n_distractors: int, out_dir: Path, 
                      random_seed=RANDOM_SEED) -> None:
    """Generate a negative haystack of distractor functions."""
    log.info(f"[{config_name.upper()}] 1. Generating the Negative Haystack...")
    if len(negatives_pool) >= n_distractors:
        df_haystack = negatives_pool.sample(n=n_distractors, random_state=random_seed)
    else:
        log.warning(f"   [!] Only {len(negatives_pool)} valid distractors available but {n_distractors} requested!")
        df_haystack = negatives_pool.sample(frac=1, random_state=random_seed)

    df_haystack.to_csv(out_dir / "haystack_candidates.csv", index=False)
    log.info(f"   -> Saved {len(df_haystack)} haystack candidates.")
    
    
def generate_positives(positives_pool: pd.DataFrame, target_scenarios: list[str]) -> dict[str, pd.DataFrame]:
    """Generate positive candidate pairs for evaluation in a chunked manner."""
    # Self-Merge to form [A, B] pairs belonging to the same project & binary
    pairs = pd.merge(
        positives_pool, positives_pool,
        on=['project', 'real_binname', 'func_name'], 
        suffixes=('_A', '_B')
    )
    
    # Remove self-pairs and duplicates (A->B == B->A)
    # ALSO: Filter out trivial pairs with the same PIC hash
    pairs = pairs[
        (pairs['function_id_A'] < pairs['function_id_B']) & 
        (pairs['PIC_id_A'] != pairs['PIC_id_B'])
    ]
    
    m_same_arch_family = pairs['arch_family_A'] == pairs['arch_family_B']
    m_diff_arch_family = pairs['arch_family_A'] != pairs['arch_family_B']
    m_same_bits = pairs['bitness_A'] == pairs['bitness_B']
    m_diff_bits = pairs['bitness_A'] != pairs['bitness_B']
    m_same_cc = pairs['cc_A'] == pairs['cc_B']
    m_diff_cc = pairs['cc_A'] != pairs['cc_B']
    m_same_version = pairs['version_A'] == pairs['version_B']
    m_diff_version = pairs['version_A'] != pairs['version_B']
    m_same_opt  = pairs['opt_A'] == pairs['opt_B']
    m_diff_opt  = pairs['opt_A'] != pairs['opt_B']

    scenarios = {}
    # If compiler family is different the compiler version doesn't matter but we
    # still enforce it for consistency with the original methodology
    if "arch" in target_scenarios: scenarios["arch"] = pairs[m_diff_arch_family & m_same_bits & m_same_cc & m_same_version & m_same_opt]
    if "bit" in target_scenarios: scenarios["bit"] = pairs[m_same_arch_family & m_diff_bits & m_same_cc & m_same_version & m_same_opt]
    if "comp" in target_scenarios: scenarios["comp"] = pairs[m_same_arch_family & m_same_bits & m_diff_cc & m_diff_version & m_same_opt]
    if "ver" in target_scenarios: scenarios["ver"] = pairs[m_same_arch_family & m_same_bits & m_same_cc & m_diff_version & m_same_opt]
    if "opt" in target_scenarios: scenarios["opt"] = pairs[m_same_arch_family & m_same_bits & m_same_cc & m_same_version & m_diff_opt]
    if "XO" in target_scenarios: scenarios["XO"] = pairs[m_same_arch_family & m_same_bits & m_same_cc & m_same_version & m_diff_opt]
    if "XA" in target_scenarios: scenarios["XA"] = pairs[m_diff_arch_family & m_diff_bits & m_same_cc & m_same_version & m_same_opt]
    if "XA_XO" in target_scenarios: scenarios["XA_XO"] = pairs[m_diff_arch_family & m_diff_bits & m_same_cc & m_same_version & m_diff_opt]
    if "XC" in target_scenarios: scenarios["XC"] = pairs[m_same_arch_family & m_same_bits & m_diff_cc & m_diff_version & m_diff_opt]
    if "XC_XB" in target_scenarios: scenarios["XC_XB"] = pairs[m_same_arch_family & m_diff_bits & m_diff_cc & m_diff_version & m_diff_opt]
    if "XM" in target_scenarios: scenarios["XM"] = pairs
    if "XZ" in target_scenarios: scenarios["XZ"] = pairs[m_diff_arch_family & m_diff_bits & m_diff_cc & m_diff_version & m_diff_opt]
    
    return scenarios
    
    
def save_positives(config_name: str, scenarios_pools: dict[str, list[pd.DataFrame]],
                   out_dir: Path, n_positives: int, random_seed=RANDOM_SEED) -> None:
    """Save positive candidate pairs to CSV files."""
    log.info(f"[{config_name.upper()}] 3. Saving Candidates...")
    cols_to_save = [
        'function_id_A', 'function_id_B', 'func_name',
        'PIC_id_A', 'PIC_id_B',
        'arch_family_A', 'arch_family_B',
        'bitness_A', 'bitness_B',
        'cc_A', 'cc_B',
        'version_A', 'version_B',
        'opt_A', 'opt_B'
    ]
    
    for scenario, pool_chunks_list in scenarios_pools.items():
        # Merge pool chunks and sample to the requested number of positives
        if len(pool_chunks_list) > 0:
            final_df = pd.concat(pool_chunks_list, ignore_index=True)
            if len(final_df) > n_positives:
                final_df = final_df.sample(n=n_positives, random_state=random_seed)
        else:
            final_df = pd.DataFrame(columns=cols_to_save)

        if len(final_df) < n_positives:
            log.warning(f"   [!] Only found {len(final_df)} pairs for {scenario} across ALL valid functions.")

        filename = out_dir / f"candidates_positive_{scenario}.csv"
        final_df[cols_to_save].to_csv(filename, index=False)
        log.info(f"   -> Saved {len(final_df)} candidates for {scenario} to {filename.name}")

    

def generate_positives_in_chunks(config_name: str, positives_pool: pd.DataFrame, 
                                 n_positives: int, target_scenarios: list[str],
                                 out_dir: Path, chunk_size: int = 2000,
                                 random_seed: int = RANDOM_SEED) -> None:
    """Generate positive candidate pairs for evaluation."""
    
    log.info(f"[{config_name.upper()}] 2. Generating Intra-Binary Positive Pairs (Chunked)...")
    
    scenarios_pools = {k: [] for k in target_scenarios}
    scenarios_counts = {k: 0 for k in target_scenarios}
    
    unique_func_names = positives_pool['func_name'].unique().tolist()
    total_funcs = len(unique_func_names)
    np.random.seed(random_seed)
    np.random.shuffle(unique_func_names)
    
    for i in range(0, total_funcs, chunk_size):
        chunk_func_names = unique_func_names[i:i+chunk_size]
        df_chunk = positives_pool[positives_pool['func_name'].isin(chunk_func_names)]
        chunk_scenarios = generate_positives(df_chunk, target_scenarios)
        
        for name, pool in chunk_scenarios.items():
            if len(pool) == 0:
                continue
            # Sample at most n_positives from this chunk and copy to
            # release the reference to the large `pairs` DataFrame.
            take = min(len(pool), n_positives)
            chunk_sample = pool.sample(n=take, random_state=random_seed) if take < len(pool) else pool.copy()
            scenarios_pools[name].append(chunk_sample)
            scenarios_counts[name] += take
            # Compact when accumulated pairs exceed 3x quota to bound memory
            if scenarios_counts[name] > n_positives * 3:
                combined = pd.concat(scenarios_pools[name], ignore_index=True)
                scenarios_pools[name] = [combined.sample(n=n_positives * 2, random_state=random_seed)]
                scenarios_counts[name] = n_positives * 2

        log.info(f"   [Chunk {i//chunk_size + 1} / {(total_funcs + chunk_size - 1)//chunk_size}]")
        for scenario, count in scenarios_counts.items():
            log.info(f"      -> {scenario}: {count} pairs accumulated.")
    
    save_positives(config_name, scenarios_pools, out_dir, n_positives, 
                   random_seed=random_seed)
    
    

def generate_evaluation_datasets(session: Session, 
                                 tier1_csv: Path = TIER1_POOL_CSV, 
                                 tier2_csv: Path = TIER2_POOL_CSV,
                                 tier1_metadata_csv: Path = TIER1_METADATA_CSV
                                 ) -> None:
    
    log.info("1. Loading Sampling Pools...")
    df_tier2 = pd.read_csv(tier2_csv)
    tier2_ids = df_tier2["function_id"].tolist()
    # Tier 2 pool is a superset of Tier 1
    all_ids = tier2_ids
    log.info(f"   -> Found {len(all_ids)} Tier 2 functions with full coverage.")

    log.info("2. Fetching Metadata for Tier 1...")
    if not tier1_metadata_csv.is_file():
        df_tier1_raw = pd.read_csv(tier1_csv)
        tier1_ids = df_tier1_raw['function_id'].tolist()
        df_tier1_metadata = fetch_function_metadata_in_chunks(session, tier1_ids, chunk_size=10_000)
        # Merge with tier1_raw to get the PIC_id for trivial-pair removal
        df_tier1 = pd.merge(df_tier1_metadata,
                            df_tier1_raw[["function_id", "PIC_id"]],
                            on="function_id", how="left")
        df_tier1.to_csv(tier1_metadata_csv, index=False)
    else:
        df_tier1 = pd.read_csv(tier1_metadata_csv)
    
    log.info("3. Parsing Binary Compilation Metadata...")
    df_tier1 = join_binary_metadata(df_tier1)
    
    for config_name, c_params in CONFIGS.items():
        out_dir = SIMILARITY_DIR / config_name
        out_dir.mkdir(parents=True, exist_ok=True)
        n_positive_candidates = c_params["n_positives"]
        n_negative_candidates = n_positive_candidates * c_params["n_distractors_per_anchor"]
        target_scenarios = c_params["scenarios"]
        
        log.info(f"=========================================================")
        log.info(f" STARTING PIPELINE GENERATION: {config_name.upper()}")
        log.info(f"=========================================================")

        generate_negatives(config_name, df_tier2, n_negative_candidates, out_dir)
        generate_positives_in_chunks(config_name, df_tier1, n_positive_candidates,
                                     target_scenarios, out_dir)

    log.info("Dataset generation complete! Ready for hash intersection.")


if __name__ == "__main__":
    assert TIER1_POOL_CSV.is_file(), "Tier 1 pool CSV not found. Please run the previous step to generate it."
    assert TIER2_POOL_CSV.is_file(), "Tier 2 pool CSV not found. Please run the previous step to generate it."

    engine = get_engine()
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as session:
        generate_evaluation_datasets(session)