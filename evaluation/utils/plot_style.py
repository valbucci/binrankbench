"""Centralized visual style definitions for all line plots.

Edit this file to update colours, markers, or linestyles across all figures.
"""
from evaluation.utils.labels import ALGORITHMS_NS

# One colour per algorithm family.  All line plots use this mapping so every
# figure shows the same colour for the same algorithm.
FAMILY_COLOURS: dict[str, str] = {
    "Machoke":  "#1f77b4",
    "CCBHash":  "#ff7f0e",
    "FSS":      "#2ca02c",
    "FSS-M":    "#d62728",
    "FSS-MW":   "#9467bd",
    "ByteSig":  "#8c564b",
    "Catalog1": "#e377c2",
}

# Per-algorithm style keyed by internal pipeline name.
# CCBHash-U shares the CCBHash colour but is drawn dashed so the two variants
# are distinguishable on shared axes.
ALG_STYLES: dict[str, dict] = {
    "machoke":    dict(color=FAMILY_COLOURS["Machoke"],  marker="o", linestyle="solid"),
    "ccbhash":    dict(color=FAMILY_COLOURS["CCBHash"],  marker="s", linestyle="solid"),
    "ccbhash_uw": dict(color=FAMILY_COLOURS["CCBHash"],  marker="P", linestyle="dashed"),
    "fsso":       dict(color=FAMILY_COLOURS["FSS"],      marker="^", linestyle="solid"),
    "fssm":       dict(color=FAMILY_COLOURS["FSS-M"],    marker="D", linestyle="solid"),
    "fssmw":      dict(color=FAMILY_COLOURS["FSS-MW"],   marker="v", linestyle="solid"),
    "cat1":       dict(color=FAMILY_COLOURS["Catalog1"], marker="p", linestyle="solid"),
    "bysig":      dict(color=FAMILY_COLOURS["ByteSig"],  marker="*", linestyle="solid"),
}

# Reverse lookup: display name or TeX label -> internal key.
_DISPLAY_TO_KEY: dict[str, str] = {
    ALGORITHMS_NS.machoke.base:    "machoke",
    ALGORITHMS_NS.machoke.score:   "machoke",
    ALGORITHMS_NS.ccbhash_w.base:  "ccbhash",
    ALGORITHMS_NS.ccbhash_w.score: "ccbhash",
    ALGORITHMS_NS.ccbhash_u.base:  "ccbhash_uw",
    ALGORITHMS_NS.ccbhash_u.score: "ccbhash_uw",
    ALGORITHMS_NS.fsso.base:       "fsso",
    ALGORITHMS_NS.fsso.score:      "fsso",
    ALGORITHMS_NS.fssm.base:       "fssm",
    ALGORITHMS_NS.fssm.score:      "fssm",
    ALGORITHMS_NS.fssmw.base:      "fssmw",
    ALGORITHMS_NS.fssmw.score:     "fssmw",
    ALGORITHMS_NS.cat1.base:       "cat1",
    ALGORITHMS_NS.cat1.score:      "cat1",
    ALGORITHMS_NS.bysig_wc.base:   "bysig",
    ALGORITHMS_NS.bysig_wc.score:  "bysig",
    # XO sensitivity variant labels
    "ByteSig (no-check)":  "bysig",
    "ByteSig (with-check)": "bysig",
    **{obj.hsim: key
       for obj, key in [(ALGORITHMS_NS.fsso, "fsso"), (ALGORITHMS_NS.fssm, "fssm"), (ALGORITHMS_NS.fssmw, "fssmw")]
       if obj.hsim is not None},
}


def algo_style(name: str) -> dict:
    """Return {color, marker, linestyle} for an algorithm by internal key or display name."""
    key = _DISPLAY_TO_KEY.get(name, name)
    return dict(ALG_STYLES.get(key, dict(color="#555555", marker="x", linestyle="solid")))
