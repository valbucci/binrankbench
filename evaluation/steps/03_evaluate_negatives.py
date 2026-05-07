"""
1vN and 1v1 ranking evaluation against distractor (negative) candidates.

Reads positive pairs scored by step 02 and a haystack of negative candidates
produced by step 01. For each positive pair, computes per-algorithm scores
against N distractors (100 for 1vN, 1 for 1v1) and writes:
  evaluation/intermediate/similarity/{config}/all_scores_{scenario}.parquet
  evaluation/intermediate/similarity/{config}/ablation_negative_{scenario}.parquet
  evaluation/intermediate/similarity/1v1/auc.csv  (1v1 only)

Run from the project root:
    python -m evaluation --steps 3
"""
import sys
import json
import ast
import pandas as pd
import numpy as np
from numpy.typing import NDArray
from sqlalchemy.orm import Session
from tqdm import tqdm
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from binrankbench.storage.session import get_engine, make_session_factory
from binrankbench.modules import CCBHash, ByteSignature, FunctionSimSearch
from evaluation.utils.logging_utils import setup_logging
from evaluation.utils.helpers import fetch_fingerprints_in_chunks, _encode_for_csv, _decode_from_csv
from evaluation.utils.constants import (
    CAT1_NUM_PERMS, CCB_K, CCB_SUBHASH_COLS, CCB_NO_NAME_WEIGHTS_NP,
    CCB_NO_NAME_EQUAL_NP, ALGORITHMS
)
from evaluation.utils.context import SIMILARITY_DIR

log = setup_logging(__file__)

RESULTS_DIR = SIMILARITY_DIR
DIST_CCB_COLS = [f"distractor_{c}" for c in CCB_SUBHASH_COLS]
CONFIGS = {
    "1vN": {"scenarios": ["XO", "XA", "XC", "XC_XB", "XA_XO", "XM", "XZ"], "num_distractors": 100},
    "1v1": {"scenarios": ["arch", "bit", "comp", "ver", "opt", "XZ"], "num_distractors": 1},
}

# ---------------------------------------------------------------------------
# Scores Computation Utilities
# ---------------------------------------------------------------------------

@dataclass
class DistractorScores:
    anchor_fingerprints: pd.Series       # algorithm index, digest value
    haystack_fingerprints: pd.DataFrame  # algorithm attributes, digests rows

    _ccbhash_ablation: Optional[NDArray[np.int8]] = None


    def get_anchor_and_haystack(self, algorithm) -> tuple:
        if algorithm not in ALGORITHMS and algorithm != "ccb":
            # NOTE: This is disgusting
            # Consistency between ccb and ccbhash must be addressed, eventually
            raise NotImplementedError(f"Cannot fetch '{algorithm}'")

        try:
            anchor = self.anchor_fingerprints[algorithm]
            haystack = self.haystack_fingerprints[algorithm]
            return anchor, haystack
        except KeyError as e:
            raise RuntimeError(f"Algorithm '{algorithm}' is implemented but not in anchor or haystack") from e
    
    def _fss(self, fss_variant) -> NDArray[np.float32]:
        if fss_variant not in ("fsso", "fssm", "fssmw"):
            raise NotImplementedError(f"Unsupported FunctionSimSearch variant '{fss_variant}'")

        def get_obj(record: tuple[bytes, bytes]) -> FunctionSimSearch:
            return FunctionSimSearch(record[0], record[1])

        fss_anchor, fss_haystack = self.get_anchor_and_haystack(fss_variant)
        a_obj = get_obj(fss_anchor)
        return np.array([
            a_obj.similarity(get_obj(distractor)) 
            for distractor in fss_haystack
            ],
            dtype=np.float32
        )
    
    @property
    def _ccbhash(self) -> NDArray[np.int8]:

        def get_obj(record: str) -> CCBHash:
            return CCBHash(record)
        
        ccb_anchor, ccb_haystack = self.get_anchor_and_haystack("ccb")
        a_numpy = get_obj(ccb_anchor).to_numpy()
        h_numpy = np.vstack([
            get_obj(distractor).to_numpy()
            for distractor in ccb_haystack
            ],
            dtype=np.int64
        )
        return (h_numpy == a_numpy)
                
    @property
    def ccbhash_ablation(self) -> NDArray[np.int8]:
        if self._ccbhash_ablation is None:
            self._ccbhash_ablation = self._ccbhash
        return self._ccbhash_ablation
    
    @property
    def machoke(self) -> NDArray[np.float32]:
        machoke_anchor, machoke_haystack = self.get_anchor_and_haystack("machoke")
        return (machoke_anchor == machoke_haystack).to_numpy().astype(np.float32)

    @property
    def fsso(self) -> NDArray[np.float32]:
        return self._fss("fsso")
    
    @property
    def fssm(self) -> NDArray[np.float32]:
        return self._fss("fssm")
    
    @property
    def fssmw(self) -> NDArray[np.float32]:
        return self._fss("fssmw")
    
    @property
    def bysig(self) -> NDArray[np.float32]:       
        def get_obj(element: tuple[bytes, bytes, int]) -> ByteSignature:
            return ByteSignature(element[0], element[1], cc=element[2])
        
        bysig_anchor, bysig_haystack = self.get_anchor_and_haystack("bysig")
        a_obj = get_obj(bysig_anchor)
        return np.array([
            ByteSignature.compare(a_obj, get_obj(distractor), min_size=16, 
                                  min_cc=10, mode="density") 
            for distractor in bysig_haystack
            ],
            dtype=np.float32
        )
    
    @property
    def cat1(self) -> NDArray[np.float32]:
        cat1_anchor, cat1_haystack = self.get_anchor_and_haystack("cat1")
        subhash_matches = np.sum(
            np.vstack(cat1_haystack, dtype=np.int64
                     ) == np.array(cat1_anchor, dtype=np.int64), 
            axis=1
        ) 
        return (subhash_matches / CAT1_NUM_PERMS).astype(np.float32)
        
    @property
    def ccbhash_weighted(self) -> NDArray[np.float32]:
        weighted_slices = self.ccbhash_ablation * CCB_NO_NAME_WEIGHTS_NP
        return np.sum(weighted_slices, axis=1).astype(np.float32)
    
    @property
    def ccbhash_unweighted(self) -> NDArray[np.float32]:
        slices = self.ccbhash_ablation * CCB_NO_NAME_EQUAL_NP
        # Without function-name feature CCBHash has 12 sub-hashes; take the mean
        subhash_match_slices = np.sum(slices, axis=1).astype(np.float32)
        return subhash_match_slices / 12
    
    
def compute_distractor_scores(anchor_fingerprints: pd.Series, 
                              haystack_fingerprints: pd.DataFrame):
    """Compute similarity scores of ONE anchor against MANY distractors
    
    Args:
        anchor_fingerprints: pd.Series
            Index is algorithm name and value is the fingerprint digest
        
        haystack_fingerprints: pd.DataFrame
            Rows are distractors and attributes are different algorithm 
            fingerprint digests
    """
    num_distractors = len(haystack_fingerprints)
    scores = DistractorScores(anchor_fingerprints, haystack_fingerprints)
    scores_results = {
        "fsso": scores.fsso,
        "fssm": scores.fssm,
        "fssmw": scores.fssmw,
        "machoke": scores.machoke,
        "cat1": scores.cat1,
        "bysig": scores.bysig,
        "ccbhash": scores.ccbhash_weighted,
        "ccbhash_uw": scores.ccbhash_unweighted
    }
    
    # Transpose ablation matrix so that:
    # - Each row holds features instead of hashes and viceversa for columns
    # - Accessing hash n is done with second index now 
    #   - e.g. ccbhash_ablation[n][feat] -> ccbhash_ablation_t[feat][n]
    ccbhash_ablation_t = scores.ccbhash_ablation.T
    ablation_results = {
        ccb_col: feature_match_array
        for ccb_col, feature_match_array in zip(CCB_SUBHASH_COLS, 
                                                ccbhash_ablation_t)
    }
    
    # Double check that everything was computed as expected
    for algorithm, array in scores_results.items():
        actual_num = len(array)
        assert actual_num == num_distractors, \
            f"Expected {num_distractors} distractors for {algorithm}; got {actual_num} instead."
    
    for ccb_col, array in ablation_results.items():
        actual_num = len(array)
        assert actual_num == num_distractors, \
            f"Expected {num_distractors} distractors for ccbhash ablation column {ccb_col}; got {actual_num} instead."        
    
    # Everything is good return results
    return scores_results, ablation_results
    
    
def compute_all_scores(session: Session, scenario: str, num_distractors: int,
                       df_positives: pd.DataFrame, df_haystack: pd.DataFrame
                       ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Computes all the distractor similarity scores and merges them with the
       existing target similarity scores.
    
    Returns the all the similarity scores (anchor/target + anchor/haystack) and
      the all the anchor/haystack ccbhash feature ablation matrices.    
    """
    # Check the haystack is large enough
    haystack_ids = df_haystack["function_id"].unique().tolist()
    anchor_ids = df_positives["function_id_A"].unique().tolist()
    h_size = len(haystack_ids)
    if len(anchor_ids) * num_distractors > h_size:
        cap = h_size // num_distractors
        log.warning(f"  Haystack too small; capping targets to {cap}")
        df_positives = df_positives.iloc[:cap].copy()
        
    # Fetch all anchor fingerprints
    anchors_list = fetch_fingerprints_in_chunks(
        session, anchor_ids, desc=f"  Fetching {scenario} anchors"
    )
    df_anchors = pd.DataFrame(anchors_list)
    del anchors_list
    
    all_scores_results, haystack_ablation_results = [], []
    
    for i, (_, row) in enumerate(tqdm(df_positives.iterrows(), 
                                      total=len(df_positives), 
                                      desc=f"  Scoring {scenario}")):
        # Build a result dictionary for this anchor-target-haystack group
        anchor_id = row["function_id_A"]
        target_id = row["function_id_B"]
        result = {"function_id_A": anchor_id, "function_id_B": target_id}
        
        # Find range in the haystack where this anchor's distractors live
        z0 = i * num_distractors
        z1 = z0 + num_distractors
        haystack_group = df_haystack.iloc[z0:z1]
        anchor_fingerprints   = df_anchors[
            df_anchors["function_id"] == anchor_id
        ].squeeze()  # anchor_fingerprints is a Series because function_id is unique
        
        # Compute scores per algorithm and keep CCBHash ablation
        dist_scores, dist_ablation = compute_distractor_scores(
            anchor_fingerprints, haystack_group
        )
        
        # Now group together all the scores from positives + negatives
        for alg in ["fsso", "fssm", "fssmw", "machoke", "cat1", "bysig", "ccbhash", "ccbhash_uw"]:
            result[f"target_{alg}_sim"] = row[f"sim_{alg}"]
            result[f"distractor_{alg}_scores"] = dist_scores[alg]

        all_scores_results.append(result)
        haystack_ablation_results.append(dist_ablation)
        
    df_all_scores = pd.DataFrame(all_scores_results)
    df_haystack_ablation = pd.DataFrame(haystack_ablation_results)
    return df_all_scores, df_haystack_ablation


# ---------------------------------------------------------------------------
# Store / Load
# ---------------------------------------------------------------------------

# === Intermediate Haystack Cache ===
# NOTE: I made this just so I could fail fast. Tech debt from 
#       evaluation.helpers.fetch_fingerprints and previous steps make it
#       necessary as tuples are stored in DataFrame attributes (terrible idea)

def store_haystack_cache_csv(df: pd.DataFrame, cache_path: Path, cols_to_encode=None):
    if cols_to_encode is None:
        cols_to_encode = ["machoke","fsso","fssm","fssmw","cat1","bysig","ccb"]
    out = df.copy()
    for c in cols_to_encode:
        if c in out.columns:
            out.loc[:, c] = out[c].apply(lambda v: json.dumps(
                _encode_for_csv(v), separators=(",", ":"), ensure_ascii=False)
            )
    out.to_csv(cache_path, index=False, quoting=1)  # quoting=csv.QUOTE_MINIMAL

def load_haystack_cache_csv(cache_path: Path, cols_to_decode=None):
    if cols_to_decode is None:
        cols_to_decode = ["machoke","fsso","fssm","fssmw","cat1","bysig","ccb"]
    df = pd.read_csv(cache_path, engine="python", quotechar='"')
    for c in cols_to_decode:
        if c in df.columns:
            def _try_decode(s):
                if pd.isna(s):
                    return s
                try:
                    parsed = json.loads(s)
                except Exception:
                    # maybe it was a Python literal string like "(b'..', b'..')"
                    try:
                        parsed = ast.literal_eval(s)
                    except Exception:
                        return s
                return _decode_from_csv(parsed)
            df.loc[:, c] = df[c].apply(_try_decode)
    return df

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    with SessionLocal() as session:
        for config_name, conf in CONFIGS.items():
            num_distractors = conf["num_distractors"]
            haystack_candidates_path = RESULTS_DIR / config_name / "haystack_candidates.csv"
            haystack_fingerprints_path = RESULTS_DIR / config_name / "haystack_fingerprints.csv"

            if not (haystack_candidates_path.is_file()  or 
                    haystack_fingerprints_path.is_file()):
                log.warning(f"[!] Haystack not found for {config_name}. Run step 01 first.")
                continue

            log.info(f"{'='*60}")
            log.info(f" {config_name.upper()} (1 vs {num_distractors})")
            log.info(f"{'='*60}")

            # Check if cached fingerprints exist
            if haystack_fingerprints_path.is_file():
                # Cache exists; load the fingerprints
                df_haystack = load_haystack_cache_csv(haystack_fingerprints_path)
            else:
                # Cache doesn't exist load the ids and fetch the fingerprints from the DB
                df_haystack_raw = pd.read_csv(haystack_candidates_path)
                haystack_ids = df_haystack_raw["function_id"].tolist()
                del df_haystack_raw

                log.info(f"Fetching {len(haystack_ids)} haystack fingerprints...")
                haystack_list = fetch_fingerprints_in_chunks(
                    session, haystack_ids, desc="Fetching haystack"
                )
                df_haystack = pd.DataFrame(haystack_list)
                del haystack_list
                
                # Now cache the fingerprints for future runs
                store_haystack_cache_csv(df_haystack, haystack_fingerprints_path)

            auc_rows = []
            for scenario in conf["scenarios"]:
                in_positives_path = RESULTS_DIR / config_name / f"scored_positive_{scenario}.csv"
                out_scores_path = RESULTS_DIR / config_name / f"all_scores_{scenario}.parquet"
                out_ablation_path = RESULTS_DIR / config_name / f"ablation_negative_{scenario}.parquet"
                if not in_positives_path.exists():
                    log.warning(f"  SKIP {scenario}: {in_positives_path.name} not found")
                    continue
                
                if out_scores_path.exists() and out_ablation_path.exists():
                    log.info(f"  SKIP {scenario}: {out_scores_path.name} and {out_ablation_path.name} exist")
                    continue
                
                df_positives = pd.read_csv(in_positives_path)
                df_all_scores, df_haystack_ablation = compute_all_scores(
                    session, scenario, num_distractors, df_positives, df_haystack
                )
                log.info(f"  SUCCESS: Finished computing all scores and haystack ablation!")
                
                del df_positives # don't need it anymore
                
                df_all_scores.to_parquet(out_scores_path)
                df_haystack_ablation.to_parquet(out_ablation_path)
                log.info(f"  Written: {out_scores_path.name}, {out_ablation_path.name}")
