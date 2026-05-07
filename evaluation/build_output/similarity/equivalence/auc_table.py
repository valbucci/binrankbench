"""ROC-AUC table (1v1) → output/tables/tab_auc.tex"""
import matplotlib
matplotlib.use("Agg")
from evaluation.utils.mpl_compat import apply_patches as _apply_mpl_patches
_apply_mpl_patches()

import matplotlib.colors as mcolors
import numpy as np
import pandas as pd

from evaluation.build_output._paths import TABLES, generated_by
from evaluation.build_output.similarity.common import load_scenario_auc, AUC_SCENARIOS, AUC_NEW_HDR
from evaluation.utils.labels import ALGORITHMS_NS

COL_RENAME = {"arch": "Arch", "bit": "Bit", "comp": "Comp", "ver": "Ver", "opt": "Opt"}

TEX_LABELS = {
    "machoke":    ALGORITHMS_NS.machoke.tex,
    "ccbhash":    ALGORITHMS_NS.ccbhash_w.tex,
    "ccbhash_uw": ALGORITHMS_NS.ccbhash_u.tex,
    "fsso":       ALGORITHMS_NS.fsso.tex,
    "fssm":       ALGORITHMS_NS.fssm.tex,
    "fssmw":      ALGORITHMS_NS.fssmw.tex,
    "cat1":       ALGORITHMS_NS.cat1.tex,
    "bysig":      ALGORITHMS_NS.bysig_wc.tex,
}


def build_auc_table() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    
    print("Loading ROC-AUC ...")
    auc_data = load_scenario_auc()
    if not auc_data:
        print("  No data; skipping tab_auc.tex")
        return

    df_auc = pd.DataFrame(auc_data)
    auc_table = df_auc.pivot(index="Algorithm", columns="Scenario", values="ROC-AUC")
    # Sort rows per mean  of attributes
    auc_table["_m"] = auc_table.mean(axis=1)
    auc_table = auc_table.sort_values("_m").drop(columns=["_m"])
    auc_table = auc_table.reindex(columns=AUC_SCENARIOS)
    auc_table = auc_table.rename(columns=COL_RENAME)
    auc_table.index = auc_table.index.map(lambda x: TEX_LABELS.get(x, x))
    auc_table.index.name = None

    vmax = float(np.nanmax(auc_table.values))
    norm = mcolors.TwoSlopeNorm(vmin=0.48, vcenter=0.55, vmax=vmax)
    auc_table.index = auc_table.index.map(lambda x: TEX_LABELS.get(x, x))

    latex = (
        auc_table.style
        .background_gradient(cmap="pink", axis=None, gmap=norm(auc_table.values))
        .format("{:.4f}")
        .to_latex(
            hrules=True,
            convert_css=True,
            caption="Area Under the Receiver Operating Characteristic Curve (ROC-AUC).",
            label="tab:auc",
        )
    )
    
    clean = []
    for line in latex.split("\n"):
        s = line.strip()
        if s.startswith("Scenario &") and s.endswith(r"\\"):
            clean.append(AUC_NEW_HDR)
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

    out = TABLES / "tab_auc.tex"
    out.write_text(generated_by(__file__) + latex)
    print(f"  Saved -> {out}")


if __name__ == "__main__":
    build_auc_table()
