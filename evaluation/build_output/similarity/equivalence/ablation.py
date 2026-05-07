"""CCBHash subhash ablation: robustness + discernibility plots and table.

Writes:
  output/plots/ccbhash_ablation_robustness.pdf
  output/plots/ccbhash_ablation_discernibility.pdf
  output/tables/tab_ablation.tex
"""
import matplotlib
matplotlib.use("Agg")
from evaluation.utils.mpl_compat import apply_patches as _apply_mpl_patches
_apply_mpl_patches()

import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from evaluation.build_output._paths import SCORED_1V1, PLOTS, TABLES, generated_by
from evaluation.build_output.similarity.common import AUC_SCENARIOS, AUC_NEW_HDR

sns.set_theme(style="whitegrid")

COL_RENAME = {"arch": "Arch", "bit": "Bit", "comp": "Comp", "ver": "Ver", "opt": "Opt"}


CCB_FEATURES = [
    "ccb_opcodes", "ccb_cfg", "ccb_cc", "ccb_outdegree",
    "ccb_ninstructions", "ccb_call_graph", "ccb_var_args",
    "ccb_var_locals", "ccb_nvars", "ccb_nblocks", "ccb_indegree",
    "ccb_stackframe",
]
FEATURE_LABELS = {
    "ccb_opcodes":       "Opcodes",
    "ccb_cfg":           "CFG Topology",
    "ccb_cc":            "Cycl. Comp.",
    "ccb_outdegree":     "CG Outdegree",
    "ccb_ninstructions": "# Instructions",
    "ccb_call_graph":    "CG Topology",
    "ccb_var_args":      "Arg. Types",
    "ccb_var_locals":    "Var. Types",
    "ccb_nvars":         "# Args + Vars",
    "ccb_nblocks":       "# Basic Blocks",
    "ccb_indegree":      "CG Indegree",
    "ccb_stackframe":    "Stack Size",
}


def _load_tpr_disc():
    """Compute per-scenario TPR and discernibility for each CCBHash subhash."""
    positive_dfs: dict[str, pd.DataFrame] = {}
    for scenario in AUC_SCENARIOS:
        p = SCORED_1V1 / f"ablation_positive_{scenario}.csv"
        if p.exists():
            positive_dfs[scenario] = pd.read_csv(p)
        else:
            print(f"  WARNING: {p.name} not found. Run stage 02 first.")

    negative_dfs = []
    for scenario in AUC_SCENARIOS:
        p = SCORED_1V1 / f"ablation_negative_{scenario}.parquet"
        if not p.exists():
            continue
        neg = pd.read_parquet(p)
        neg.columns = [c.replace("distractor_", "") for c in neg.columns]
        if set(CCB_FEATURES).issubset(neg.columns):
            for col in CCB_FEATURES:
                neg.loc[:, col] = neg[col].apply(
                    lambda x: x[0] if isinstance(x, (list, np.ndarray)) else x
                ).astype(float)
            negative_dfs.append(neg[CCB_FEATURES])

    if not negative_dfs:
        raise RuntimeError("No ablation_negative parquets found. Run stage 03 first.")

    all_neg = pd.concat(negative_dfs, ignore_index=True).dropna()
    global_fpr = all_neg.mean() * 100

    tpr_rows, disc_rows = [], []
    for scenario, df in positive_dfs.items():
        valid = df.dropna(subset=CCB_FEATURES)
        tpr  = valid[CCB_FEATURES].mean() * 100
        disc = tpr - global_fpr
        tpr.name  = scenario
        disc.name = scenario
        tpr_rows.append(tpr)
        disc_rows.append(disc)

    tpr_df  = pd.DataFrame(tpr_rows).T.rename(index=FEATURE_LABELS).reindex(FEATURE_LABELS.values())
    disc_df = pd.DataFrame(disc_rows).T.rename(index=FEATURE_LABELS).reindex(FEATURE_LABELS.values())
    return tpr_df, disc_df


def build_ablation_plots() -> None:
    PLOTS.mkdir(parents=True, exist_ok=True)
    TABLES.mkdir(parents=True, exist_ok=True)

    tpr_df, disc_df = _load_tpr_disc()

    # Robustness heatmap
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(tpr_df, annot=True, fmt=".1f", cmap="YlGnBu",
                vmin=0, vmax=100,
                cbar_kws={"label": "True Positive Match Rate (%)"}, ax=ax)
    ax.set_title("CCBHash Subhash Robustness", pad=20, fontsize=16)
    ax.set_ylabel("CCBHash Features (Ordered by Weight)", labelpad=10, fontsize=14)
    ax.set_xlabel("Mutation Scenarios", labelpad=10, fontsize=14)
    plt.xticks(rotation=0)
    plt.yticks(rotation=0)
    fig.tight_layout()
    out = PLOTS / "ccbhash_ablation_robustness.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  Saved -> {out}")

    # Discernibility heatmap
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(disc_df, annot=True, fmt=".1f", cmap="RdYlGn",
                vmin=-25, vmax=100, center=0,
                cbar_kws={"label": "Discernibility (TPR - FPR) (%)"}, ax=ax)
    ax.set_title("CCBHash Subhash Discernibility (Informedness)", pad=20, fontsize=16)
    ax.set_ylabel("CCBHash Features (Ordered by Weight)", labelpad=10, fontsize=14)
    ax.set_xlabel("Mutation Scenarios", labelpad=10, fontsize=14)
    plt.xticks(rotation=0)
    plt.yticks(rotation=0)
    fig.tight_layout()
    out = PLOTS / "ccbhash_ablation_discernibility.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  Saved -> {out}")

    # LaTeX discernibility table
    disc_df.index.name = "Algorithm"
    disc_tex = disc_df.reindex(columns=AUC_SCENARIOS)
    disc_tex = disc_df.rename(columns=COL_RENAME)
    vmin = float(disc_tex.values.min())
    vmax = float(disc_tex.values.max())
    norm = mcolors.TwoSlopeNorm(vmin=vmin, vcenter=0.0, vmax=vmax)

    def _clean(x):
        return "0.0" if abs(x) < 0.05 else f"{x:.1f}"

    latex = (
        disc_tex.style
        .background_gradient(cmap="pink", axis=None, gmap=norm(disc_tex.values))
        .format(_clean)
        .to_latex(
            hrules=True,
            convert_css=True,
            caption=r"CCBHash Features Subhash Informedness (TPR $-$ FPR) (\%).",
            label="tab:ablation",
        )
    )
    clean = []
    for line in latex.split("\n"):
        s = line.strip()
        if s.startswith("& ") and s.endswith(r"\\"):
            clean.append(AUC_NEW_HDR)
        elif s == r"Algorithm &  &  &  &  &  &  \\":
            continue
        elif s.startswith("#"):
            clean.append("\\" + line)
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
    
    
    out = TABLES / "tab_ablation.tex"
    out.write_text(generated_by(__file__) + latex)
    print(f"  Saved -> {out}")


if __name__ == "__main__":
    build_ablation_plots()
