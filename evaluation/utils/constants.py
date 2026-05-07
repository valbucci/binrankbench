"""Shared constants used by evaluation stages and output generation scripts."""
import numpy as np

from binrankbench.modules.ccbhash import (
    ALIGNED_WEIGHTS as _CCB_ALIGNED_WEIGHTS,
    SUBHASH_ORDER as CCB_SUBHASH_ORDER,
)
from evaluation.utils.labels import ALGORITHMS_NS

# ----------------------------------------------------------------------------
# Common constants for evaluation experiments
# ----------------------------------------------------------------------------
RANDOM_SEED = 42
ALGORITHMS = ("machoke", "ccbhash", "fsso", "fssm", "fssmw", "cat1", "bysig")
N_STRATEGIES = len(ALGORITHMS)

# ----------------------------------------------------------------------------
# Marcelli et al. (2022) configuration constants
# ----------------------------------------------------------------------------
NBBS_MIN     = 5
DATASET_NAME = "cisco-talos_dataset1"
ARCH_FAMILY_MAP: dict[str, str] = {
    "x86": "x86",  "x64": "x86",
    "arm32": "arm", "arm64": "arm",
    "mips32": "mips", "mips64": "mips",
}
BITNESS_MAP: dict[str, int] = {
    "x86": 32, "arm32": 32, "mips32": 32,
    "x64": 64, "arm64": 64, "mips64": 64,
}


# ---------------------------------------------------------------------------
# Algorithm-specific constants
# ---------------------------------------------------------------------------
CAT1_NUM_PERMS = 16

CCB_K = len(CCB_SUBHASH_ORDER)
CCB_SUBHASH_COLS    = [f"ccb_{feat}" for feat in CCB_SUBHASH_ORDER]
CCB_NON_NAME_COLS      = [f"ccb_{feat}" for feat in CCB_SUBHASH_ORDER if feat != "name"]
CCB_NON_NAME_DIST_COLS = [f"distractor_{c}" for c in CCB_NON_NAME_COLS]

CCB_NO_NAME_WEIGHTS = list(_CCB_ALIGNED_WEIGHTS)
CCB_NO_NAME_WEIGHTS[CCB_SUBHASH_ORDER.index("name")] = 0.0
CCB_NO_NAME_WEIGHTS_NP = np.array(CCB_NO_NAME_WEIGHTS, dtype=np.float32)

CCB_NO_NAME_EQUAL = [1.0] * len(_CCB_ALIGNED_WEIGHTS)
CCB_NO_NAME_EQUAL[CCB_SUBHASH_ORDER.index("name")] = 0.0
CCB_NO_NAME_EQUAL_NP = np.array(CCB_NO_NAME_EQUAL, dtype=np.float32)

# ---------------------------------------------------------------------------
# Scenario labels and groupings
# ---------------------------------------------------------------------------

SCENARIO_LABELS = {
    "XO": "XO", "XC": "XC", "XC_XB": "XC+XB",
    "XA": "XA", "XA_XO": "XA+XO", "XZ": "XZ",
}

ROBUSTNESS_COMPLEXITY_SCENARIOS = ["XA", "XC", "XZ"]

BUCKET_LABELS = [
    "P0-P10", "P10-P20", "P20-P30", "P30-P40", "P40-P50",
    "P50-P60", "P60-P70", "P70-P80", "P80-P90", "P90-P95", "P95-P99.5",
]

VARIATIONS = ["XA", "XO", "XC", "XC_XB", "XA_XO", "XM", "XZ"]

N_PER_BUCKET_ROBUSTNESS = 1_000

# Columns in scored_positive CSVs -> display labels for variation_robustness.
SCORE_COLS = {
    "sim_machoke":    ALGORITHMS_NS.machoke.score,
    "sim_ccbhash":    ALGORITHMS_NS.ccbhash_w.score,
    "sim_ccbhash_uw": ALGORITHMS_NS.ccbhash_u.score,
    "sim_fsso":       ALGORITHMS_NS.fsso.score,
    "sim_fssm":       ALGORITHMS_NS.fssm.score,
    "sim_fssmw":      ALGORITHMS_NS.fssmw.score,
    "sim_cat1":       ALGORITHMS_NS.cat1.score,
    "sim_bysig":      ALGORITHMS_NS.bysig_wc.score,
}

# Algorithm variants shown in the XO figure. h-dist and CCBHash (dist.) are excluded
# because they are on a different scale from the similarity metrics and would
# distort the shared y-axis. CCBHash (dist.) is a dissimilarity; h-dist is a
# raw bit count in [0, 128].
XO_ALGO_SPECS = [
    # (display_label, family_colour_key, linestyle)
    (ALGORITHMS_NS.machoke.score,          ALGORITHMS_NS.machoke.colour,   "solid"),
    (ALGORITHMS_NS.ccbhash_u.score,        ALGORITHMS_NS.ccbhash_u.colour, "dashed"),
    (ALGORITHMS_NS.ccbhash_w.score,        ALGORITHMS_NS.ccbhash_w.colour, "solid"),
    (ALGORITHMS_NS.fsso.hsim,              ALGORITHMS_NS.fsso.colour,      "solid"),
    (ALGORITHMS_NS.fsso.score,             ALGORITHMS_NS.fsso.colour,      "dashed"),
    (ALGORITHMS_NS.fssm.hsim,              ALGORITHMS_NS.fssm.colour,      "solid"),
    (ALGORITHMS_NS.fssm.score,             ALGORITHMS_NS.fssm.colour,      "dashed"),
    (ALGORITHMS_NS.fssmw.hsim,             ALGORITHMS_NS.fssmw.colour,     "solid"),
    (ALGORITHMS_NS.fssmw.score,            ALGORITHMS_NS.fssmw.colour,     "dashed"),
    ("ByteSig (no-check)",     "ByteSig",          "dotted"),
    ("ByteSig (with-check)",   "ByteSig",          "solid"),
    (ALGORITHMS_NS.cat1.score,             ALGORITHMS_NS.cat1.colour,      "solid"),
]

