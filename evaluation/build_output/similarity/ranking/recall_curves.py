"""Recall@K curves for all 1vN scenarios → output/plots/Recall_Curves.pdf"""
import matplotlib
matplotlib.use("Agg")
from evaluation.utils.mpl_compat import apply_patches as _apply_mpl_patches
_apply_mpl_patches()

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.colors as mcolors
import numpy as np
import seaborn as sns

from evaluation.build_output._paths import PLOTS
from evaluation.build_output.similarity.common import (
    ALGORITHMS, load_scenario_ranks,
)
from evaluation.utils.labels import ALGORITHMS_NS
from evaluation.utils.constants import SCENARIO_LABELS
from evaluation.utils.plot_style import algo_style

sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)

SUBPLOT_ORDER = ["XA", "XC", "XO", "XC_XB", "XA_XO", "XZ"]

BETTER = {
    "bysig":      ALGORITHMS_NS.bysig_wc.base,
    "machoke":    ALGORITHMS_NS.machoke.base,
    "cat1":       ALGORITHMS_NS.cat1.base,
    "fsso":       ALGORITHMS_NS.fsso.base,
    "fssm":       ALGORITHMS_NS.fssm.base,
    "fssmw":      ALGORITHMS_NS.fssmw.base,
    "ccbhash_uw": ALGORITHMS_NS.ccbhash_u.base,
    "ccbhash":    ALGORITHMS_NS.ccbhash_w.base,
}
_ORDER = {v: i for i, v in enumerate(BETTER.values())}


def _plot_recall_curve(scenario: str, ranks_data: dict, K_max=100, ax=None, legend=True):
    if ax is None:
        _, ax = plt.subplots(figsize=(10, 8))
    lines   = []
    for alg in ALGORITHMS:
        rnks = ranks_data[scenario].get(alg)
        if rnks is None:
            continue
        xs = np.arange(1, K_max + 1)
        ys = (rnks[:, None] <= xs[None, :]).mean(axis=0)
        style = algo_style(alg)
        line, = ax.plot(xs, ys, color=style["color"], linewidth=2,
                        marker=style["marker"],
                        linestyle=style["linestyle"],
                        markevery=[0] + list(range(4, K_max, 5)),
                        markersize=6)
        lines.append((alg, line))
    ax.axvline(50, linestyle="--", color="black")
    ax.axhline(0.5, linestyle="--", color="black")
    ax.axvspan(0, 50, 0.5, 1.0, facecolor="#EEF7EE", zorder=0, alpha=0.7)
    ax.set_title(SCENARIO_LABELS.get(scenario, scenario), fontsize=14, fontweight="bold")
    ax.set_xlabel("Rank (K)", fontsize=12)
    ax.set_ylabel("Recall Rate", fontsize=12)
    ax.set_xlim(0, K_max + 0.1)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(10))
    ax.xaxis.set_minor_locator(ticker.MultipleLocator(5))
    ax.set_ylim(-0.01, 1.01)
    ax.yaxis.set_major_locator(ticker.MultipleLocator(0.1))
    ax.tick_params(axis="both", which="both", labelsize=8)
    ax.grid(True, linestyle="--", alpha=0.7)
    if legend:
        pairs = sorted(
            [(BETTER[alg], line) for alg, line in lines if alg in BETTER],
            key=lambda x: _ORDER[x[0]],
        )
        ax.legend(title="Algorithms", fontsize=10, title_fontsize=11,
                  bbox_to_anchor=(1, 1.02),
                  handles=[p[1] for p in pairs],
                  labels=[p[0] for p in pairs])


def build_recall_curves() -> None:
    PLOTS.mkdir(parents=True, exist_ok=True)
    print("Loading ranking matrices...")
    ranks_data, _ = load_scenario_ranks()

    fig, axes = plt.subplots(2, 3, figsize=(16, 8), sharex=True, sharey=True)
    for i, (ax, sc) in enumerate(zip(axes.flat, SUBPLOT_ORDER)):
        _plot_recall_curve(sc, ranks_data, ax=ax, legend=(i == 2))
    fig.tight_layout()
    out = PLOTS / "Recall_Curves.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved -> {out}")


if __name__ == "__main__":
    build_recall_curves()
