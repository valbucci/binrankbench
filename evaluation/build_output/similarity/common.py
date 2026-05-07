"""Shared rank-computation and data-loading utilities."""
import numpy as np
import pandas as pd
import sklearn.metrics

from evaluation.build_output._paths import SCORED_1VN, SCORED_1V1
from evaluation.utils.logging_utils import setup_logging


log = setup_logging(__file__)

ALGORITHMS = ["machoke", "ccbhash", "ccbhash_uw", "fsso", "fssm", "fssmw", "cat1", "bysig"]
BASE_ALGS  = [a for a in ALGORITHMS if a != "ccbhash_uw"]


# ---------------------------------------------------------------------------
# MRR@10 / Recall@K
# ---------------------------------------------------------------------------

RANK_SCENARIOS  = ["XA", "XC", "XO", "XC_XB", "XA_XO", "XZ"]
RANK_NEW_HDR = " & ".join([r"\textbf{Algorithm}"] + [
    r"\textbf{" + scenario.replace("_", "+") + "}"
    for scenario in RANK_SCENARIOS
]) + r" \\"



NEW_HDR = (
    r"\textbf{Algorithm} & \textbf{XA} & \textbf{XC} & \textbf{XO}"
    r" & \textbf{XC+XB} & \textbf{XA+XO} & \textbf{XZ} \\"
)

def compute_ranks(targets, distractors):
    return (distractors >= targets[:, None]).sum(axis=1) + 1


def load_scenario_ranks():
    """Load all 1vN ranking matrices and compute per-scenario per-algorithm ranks.

    Returns:
        ranks_data   : dict[scenario -> dict[alg -> np.ndarray of ranks]]
        mrr_metrics  : list of {Scenario, Algorithm, MRR@10} dicts
    """
    ranks_data = {s: {} for s in RANK_SCENARIOS}
    mrr_metrics = []
    for scenario in RANK_SCENARIOS:
        data_path = SCORED_1VN / f"all_scores_{scenario}.parquet"
        if not data_path.exists():
            print(f"  SKIP {scenario}: {data_path.name} not found")
            continue
        df_raw = pd.read_parquet(data_path)
        
        # Check that there are consistently 100 distractors for each anchor
        valid = np.logical_and.reduce(
            [df_raw[f"distractor_{a}_scores"].apply(len) == 100 for a in BASE_ALGS]
        )
        df = df_raw[valid].copy()
        if len(df) != len(df_raw):
            difference = len(df_raw) - len(df)
            log.warning(f"Missing distractors for {difference} anchors")
        # df = df.sample(n=min(n_sample, len(df)), random_state=42)
        
        print(f"  {scenario}: {len(df):,} pairs")
        for alg in ALGORITHMS:
            tgt  = df[f"target_{alg}_sim"].values
            dist = np.vstack(df[f"distractor_{alg}_scores"].values)
            
            try:
                rnks = compute_ranks(tgt, dist)
            except Exception as e:
                raise RuntimeError(f"Could not calculate the reciprocal ranks for {alg}") from e
            
            ranks_data[scenario][alg] = rnks
            rr10 = np.where(rnks <= 10, 1.0 / rnks, 0.0)
            mrr_metrics.append({"Scenario": scenario, "Algorithm": alg, 
                                "MRR@10": float(np.mean(rr10))})
    
    return ranks_data, mrr_metrics


# ---------------------------------------------------------------------------
# ROC-AUC
# ---------------------------------------------------------------------------

AUC_SCENARIOS  = ["opt", "ver", "comp", "bit", "arch", "XZ"]
AUC_NEW_HDR = " & ".join([r"\textbf{Algorithm}"] + [
    r"\textbf{" + scenario.capitalize() + "}" if scenario != "XZ" else r"\textbf{XZ}"
    for scenario in AUC_SCENARIOS
]) + r" \\"

def compute_auc(y_pos, y_neg) -> float:
    y_true = np.concatenate([np.ones_like(y_pos), np.zeros_like(y_neg)])
    y_score = np.concatenate([y_pos, y_neg])
    auc = float(sklearn.metrics.roc_auc_score(y_true, y_score))

    return auc


def load_scenario_auc():
    """Load all 1v1 equivalence matrices and compute per-scenario per-algorithm ROC-AUCs.

    Returns:
        auc_data   : dict[scenario -> dict[alg -> np.ndarray of AUCs]]
    """
    # auc_data = {s: {} for s in AUC_SCENARIOS}
    auc_data = []
    for scenario in AUC_SCENARIOS:
        data_path = SCORED_1V1 / f"all_scores_{scenario}.parquet"
        if not data_path.exists():
            print(f"  SKIP {scenario}: {data_path.name} not found")
            continue
        df_raw = pd.read_parquet(data_path)
        
        # Check that there is at least one distractor for each anchor
        valid = np.logical_and.reduce(
            [df_raw[f"distractor_{alg}_scores"].apply(len) == 1 for alg in BASE_ALGS]
        )
        df = df_raw[valid].copy()
        if len(df) != len(df_raw):
            difference = len(df_raw) - len(df)
            log.warning(f"Missing distractors for {difference} anchors")
        
        print(f"  {scenario}: {len(df):,} pairs")
        for alg in ALGORITHMS:
            try:
                y_pos = df[f"target_{alg}_sim"].fillna(0.0).to_numpy()
                y_neg = np.array([x[0] for x in df[f"distractor_{alg}_scores"]])
                auc = compute_auc(y_pos, y_neg)
            except Exception as e:
                raise RuntimeError(f"Could not calculate the ROC-AUC score for {alg}") from e
            
            auc_data.append({
                "Scenario": scenario,
                "Algorithm": alg,
                "ROC-AUC": auc
            })

    return auc_data
