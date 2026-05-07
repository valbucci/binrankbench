"""
Compute similarity scores for all positive (same-function) pairs.

Reads candidate pairs produced by step 01 and writes two files per scenario:
  evaluation/intermediate/{config}/scored_positive_{sc}.csv   -- per-algorithm scores
  evaluation/intermediate/{config}/ablation_positive_{sc}.csv -- per-sub-hash CCBHash columns

Run from the project root:
    python -m evaluation --steps 2
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from binrankbench.storage.session import get_engine, make_session_factory
from binrankbench.modules import CCBHash, ByteSignature, FunctionSimSearch
from evaluation.utils.logging_utils import setup_logging
from evaluation.utils.helpers import _chunked_tqdm, _missing, fetch_fingerprints_in_chunks
from evaluation.utils.constants import (
    CAT1_NUM_PERMS, CCB_SUBHASH_COLS, CCB_NO_NAME_WEIGHTS, CCB_NON_NAME_COLS,
)
from evaluation.utils.context import SIMILARITY_DIR

log = setup_logging(__file__)

RESULTS_DIR = SIMILARITY_DIR


def compute_similarities(df_signatures: pd.DataFrame) -> pd.DataFrame:
    """Compute similarity scores for all positive pairs in the DataFrame."""
    
    # Machoke
    df_signatures.loc[:, "sim_machoke"] = df_signatures.apply(
        lambda r: 1.0 if (not _missing(r["machoke_A"]) and r["machoke_A"] == r["machoke_B"])
        else (np.nan if _missing(r["machoke_A"]) or _missing(r["machoke_B"]) else 0.0),
        axis=1,
    )

    # CCBHash
    def _ccb(row):
        if _missing(row["ccb_A"]) or _missing(row["ccb_B"]):
            return np.nan
        return CCBHash.hash_similarity(row["ccb_A"], row["ccb_B"], aligned_weights=CCB_NO_NAME_WEIGHTS)

    df_signatures.loc[:, "sim_ccbhash"] = df_signatures.apply(_ccb, axis=1)

    # FunctionSimSearch
    def _fss(h1, h2):
        if _missing(h1) or _missing(h2):
            return np.nan
        return FunctionSimSearch(h1[0], h1[1]).similarity(FunctionSimSearch(h2[0], h2[1]))

    df_signatures.loc[:, "sim_fsso"] = df_signatures.apply(lambda r: _fss(r["fsso_A"], r["fsso_B"]), axis=1)
    df_signatures.loc[:, "sim_fssm"] = df_signatures.apply(lambda r: _fss(r["fssm_A"], r["fssm_B"]), axis=1)
    df_signatures.loc[:, "sim_fssmw"] = df_signatures.apply(lambda r: _fss(r["fssmw_A"], r["fssmw_B"]), axis=1)

    # Catalog1
    def _cat1(row):
        if _missing(row["cat1_A"]) or _missing(row["cat1_B"]):
            return np.nan
        return sum(a == b for a, b in zip(row["cat1_A"], row["cat1_B"])) / CAT1_NUM_PERMS

    df_signatures.loc[:, "sim_cat1"] = df_signatures.apply(_cat1, axis=1)

    # ByteSignature (Position Independent Code)
    def _bysig(row):
        if _missing(row["bysig_A"]) or _missing(row["bysig_B"]):
            return np.nan
        sig_a = ByteSignature(row["bysig_A"][0], row["bysig_A"][1], cc=row["bysig_A"][2])
        sig_b = ByteSignature(row["bysig_B"][0], row["bysig_B"][1], cc=row["bysig_B"][2])
        return ByteSignature.compare(sig_a, sig_b, min_size=16, min_cc=10, mode="density")

    df_signatures.loc[:, "sim_bysig"] = df_signatures.apply(_bysig, axis=1)
    
    return df_signatures
    
    
def compute_ccbhash_ablation(df_signatures: pd.DataFrame) -> pd.DataFrame:
    ccb_cols = CCB_SUBHASH_COLS

    def _ablation(row):
        rec = {"function_id_A": row["function_id_A"],
               "function_id_B": row["function_id_B"]}
        if _missing(row["ccb_A"]) or _missing(row["ccb_B"]):
            for col in ccb_cols:
                rec[col] = np.nan
        else:
            for col, s1, s2 in zip(ccb_cols,
                                   CCBHash.split_digest(row["ccb_A"]), 
                                   CCBHash.split_digest(row["ccb_B"])):
                rec[col] = 1 if s1 == s2 else 0
        return rec

    df_ablation = pd.DataFrame(df_signatures.apply(_ablation, axis=1).tolist())
    return df_ablation


def compute_similarities_in_chunks(session, candidates_csv: Path,
                                   output_csv: Path, chunk_size: int = 5000
                                   ) -> None:
    log.info(f"Loading candidates from {candidates_csv.name}...")
    df = pd.read_csv(candidates_csv)
    unique_ids = pd.unique(df[["function_id_A", "function_id_B"]].values.ravel("K"))
    log.info(f"  {len(unique_ids)} unique functions to fetch.")

    log.info("Fetching fingerprints from DB...")
    fingerprints_list = fetch_fingerprints_in_chunks(session, unique_ids.tolist())
    fingerprints_df = pd.DataFrame(fingerprints_list)
    del fingerprints_list

    log.info("Mapping fingerprints to DataFrame...")
    df = df.merge(fingerprints_df.add_suffix("_A"), on="function_id_A", how="left")
    df = df.merge(fingerprints_df.add_suffix("_B"), on="function_id_B", how="left")

    log.info("Computing similarities...")
    df = compute_similarities(df)

    log.info("Computing CCBHash ablation sub-features...")
    df_ablation = compute_ccbhash_ablation(df)
    # UW variant: uniform weight across non-name sub-hashes
    df.loc[:, "sim_ccbhash_uw"] = df_ablation[CCB_NON_NAME_COLS].mean(axis=1)

    log.info("Saving results...")
    drop_cols = [
        "machoke_A", "machoke_B", "ccb_A", "ccb_B",
        "fsso_A", "fsso_B", "fssm_A", "fssm_B", "fssmw_A", "fssmw_B",
        "cat1_A", "cat1_B", "bysig_A", "bysig_B",
    ]
    df_out = df.drop(columns=drop_cols)
    df_out.to_csv(output_csv, index=False)

    ablation_csv = str(output_csv).replace("scored_positive_", "ablation_positive_")
    df_ablation.to_csv(ablation_csv, index=False)

    valid = df_out.dropna()
    log.info(f"  {len(df_out)} pairs written; {len(valid)} complete across all algorithms.")


if __name__ == "__main__":
    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    CONFIGS = {
        "1vN": ["XO", "XA", "XC", "XC_XB", "XA_XO", "XM", "XZ"],
        "1v1": ["arch", "bit", "comp", "ver", "opt", "XZ"],
    }

    with SessionLocal() as session:
        for config_name, scenarios in CONFIGS.items():
            for sc in scenarios:
                log.info(f"=== {config_name.upper()} / {sc} ===")
                t_path = RESULTS_DIR / config_name / f"candidates_positive_{sc}.csv"
                o_path = RESULTS_DIR / config_name / f"scored_positive_{sc}.csv"
                if t_path.exists():
                    compute_similarities_in_chunks(session, t_path, o_path)
                else:
                    log.warning(f"  SKIP: {t_path.name} not found (run step 01 first)")
