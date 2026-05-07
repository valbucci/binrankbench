"""MRR@10 table for all 1vN scenarios → output/tables/tab_mrr10.tex"""
import matplotlib
matplotlib.use("Agg")
from evaluation.utils.mpl_compat import apply_patches as _apply_mpl_patches
_apply_mpl_patches()

import matplotlib.colors as mcolors
import numpy as np
import pandas as pd

from evaluation.build_output._paths import TABLES, generated_by
from evaluation.build_output.similarity.common import load_scenario_ranks, RANK_SCENARIOS, RANK_NEW_HDR
from evaluation.utils.labels import ALGORITHMS_NS


TEX_LABELS = {
    "bysig":      ALGORITHMS_NS.bysig_wc.tex,
    "machoke":    ALGORITHMS_NS.machoke.tex,
    "cat1":       ALGORITHMS_NS.cat1.tex,
    "fsso":       ALGORITHMS_NS.fsso.tex,
    "fssm":       ALGORITHMS_NS.fssm.tex,
    "fssmw":      ALGORITHMS_NS.fssmw.tex,
    "ccbhash_uw": ALGORITHMS_NS.ccbhash_u.tex,
    "ccbhash":    ALGORITHMS_NS.ccbhash_w.tex,
}


def build_mrr_table() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    print("Loading ranking matrices...")
    _, mrr_metrics = load_scenario_ranks()
    if not mrr_metrics:
        print("  No data; skipping tab_mrr10.tex")
        return

    df_mrr = pd.DataFrame(mrr_metrics)
    mrr_table = df_mrr.pivot(index="Algorithm", columns="Scenario", values="MRR@10")
    # Sort rows per mean  of attributes
    mrr_table["_m"] = mrr_table.mean(axis=1)
    mrr_table = mrr_table.sort_values("_m").drop(columns=["_m"])
    mrr_table = mrr_table.reindex(columns=RANK_SCENARIOS)
    mrr_table.index = mrr_table.index.map(lambda x: TEX_LABELS.get(x, x))
    mrr_table.index.name = None

    vmax = float(np.nanmax(mrr_table.values))
    norm = mcolors.TwoSlopeNorm(vmin=0.0, vcenter=0.1, vmax=vmax)
    latex = (
        mrr_table.style
        .background_gradient(cmap="pink", axis=None, gmap=norm(mrr_table.values))
        .format("{:.4f}")
        .to_latex(
            hrules=True,
            convert_css=True,
            caption=r"Mean Reciprocal Rank at $K{=}10$ (MRR@10) across all six scenarios. ",
            label="tab:mrr-10",
        )
    )

    clean = []
    for line in latex.split("\n"):
        s = line.strip()
        if s.startswith("Scenario &") and s.endswith(r"\\"):
            clean.append(RANK_NEW_HDR)
        elif s == r"Algorithm &  &  &  &  &  &  \\":
            continue
        else:
            clean.append(line)
    latex = "\n".join(clean).replace(r"{lrrrrrr}", r"{lcccccc}")
    latex = latex.replace(r"\begin{table}", r"\begin{table}[tp]", 1)
    latex = latex.replace(
        r"\begin{tabular}",
        "\\resizebox{\\linewidth}{!}{%\n\\begin{tabular}",
        1,
    )
    latex = latex.replace(r"\end{tabular}", "\\end{tabular}\n}%", 1)

    out = TABLES / "tab_mrr10.tex"
    out.write_text(generated_by(__file__) + latex)
    print(f"  Saved -> {out}")


if __name__ == "__main__":
    build_mrr_table()
