"""Dataset composition figure and attrition tables.

Writes:
  output/plots/project_distribution_layered.pdf
  output/tables/tab_dataset_attrition.tex
  output/tables/tab_hash_coverage.tex

Requires DB access (binrankbench SQLAlchemy models) for the distribution plot.
The attrition tables read pre-computed CSVs from evaluation/intermediate/ and need no DB.
"""
import matplotlib
matplotlib.use("Agg")
from evaluation.utils.mpl_compat import apply_patches as _apply_mpl_patches
_apply_mpl_patches()

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from sqlalchemy import select, func, and_, exists, case

from binrankbench.storage.session import get_engine, make_session_factory
from binrankbench.storage.models.core import (
    Function, Binary, Project, FunctionScalars,
)
from binrankbench.storage.models.dataset import BinaryDatasetTag, Dataset
from binrankbench.storage.models.signatures.bytes import FunctionByteSig
from binrankbench.storage.models.signatures.catalog1 import FunctionCatalog1
from binrankbench.storage.models.signatures.machoke import FunctionMachoke
from binrankbench.storage.models.signatures.fss import FunctionFSSOriginal
from binrankbench.storage.models.signatures.ccbhash import FunctionCCBHash

from evaluation.build_output._paths import INTERMEDIATE, PLOTS, TABLES, generated_by


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------

PROJ_ORDER = ["z3", "clamav", "openssl", "nmap", "curl", "unrar", "zlib"]

def build_project_distribution() -> None:
    """Bar chart of functions per project by tier (requires DB)."""
    PLOTS.mkdir(parents=True, exist_ok=True)

    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    with SessionLocal() as session:
        subq_cat     = exists().where(FunctionCatalog1.function_id == Function.id)
        subq_machoke = exists().where(FunctionMachoke.function_id == Function.id)
        subq_fss     = exists().where(FunctionFSSOriginal.function_id == Function.id)
        subq_ccb     = exists().where(FunctionCCBHash.function_id == Function.id)
        subq_zig     = exists().where(FunctionByteSig.function_id == Function.id)
        is_gold      = and_(subq_zig, subq_cat, subq_machoke, subq_fss, subq_ccb)

        stmt_counts = (
            select(
                Project.name.label("project_name"),
                func.count(Function.id).label("Total"),
                func.sum(case((is_gold, 1), else_=0)).label("Available"),
            )
            .select_from(Function)
            .join(Binary, Function.binary_id == Binary.id)
            .join(Project, Binary.project_id == Project.id)
            .join(FunctionScalars, Function.id == FunctionScalars.function_id)
            .join(BinaryDatasetTag, Binary.id == BinaryDatasetTag.binary_id)
            .join(Dataset, BinaryDatasetTag.dataset_id == Dataset.id)
            .where(
                Dataset.name == "cisco-talos_dataset1",
                FunctionScalars.nbbs >= 5,
            )
            .group_by(Project.name)
        )
        df_db = pd.DataFrame(
            session.execute(stmt_counts).all(),
            columns=["project_name", "Total", "Available"],
        )

        stmt_map = (
            select(Function.id.label("function_id"), Project.name.label("project_name"))
            .select_from(Function)
            .join(Binary, Function.binary_id == Binary.id)
            .join(Project, Binary.project_id == Project.id)
            .join(BinaryDatasetTag, Binary.id == BinaryDatasetTag.binary_id)
            .join(Dataset, BinaryDatasetTag.dataset_id == Dataset.id)
            .where(Dataset.name == "cisco-talos_dataset1")
        )
        df_map = pd.DataFrame(
            session.execute(stmt_map.execution_options(yield_per=100_000)).mappings()
        )

    t2_pool = pd.read_csv(INTERMEDIATE / "tier2_pool.csv")
    t1_pool = pd.read_csv(INTERMEDIATE / "tier1_pool.csv")

    df_t2 = (t2_pool.merge(df_map, on="function_id", how="inner")
             .groupby("project_name").size().reset_index(name="Tier 2"))
    df_t1 = (t1_pool.merge(df_map, on="function_id", how="inner")
             .groupby("project_name").size().reset_index(name="Tier 1"))

    df_plot = (df_db
               .merge(df_t2, on="project_name")
               .merge(df_t1, on="project_name"))
    df_plot.loc[:, "project_name"] = pd.Categorical(
        df_plot["project_name"], categories=PROJ_ORDER, ordered=True,
    )
    df_plot = df_plot.sort_values("project_name").reset_index(drop=True)

    sns.set_theme(style="whitegrid")
    fig, ax = plt.subplots(figsize=(8, 4))
    kw = dict(y="project_name", order=PROJ_ORDER, edgecolor="white", ax=ax)
    sns.barplot(data=df_plot, x="Total",     color="#bdbdbd", label="Missing Hashes",       **kw)
    sns.barplot(data=df_plot, x="Available", color="#eeb57f", label="All Hashes Available",  **kw)
    sns.barplot(data=df_plot, x="Tier 2",    color="#a6cee3", label="Negatives Pool", width=0.5,
                edgecolor="black", y="project_name", order=PROJ_ORDER, ax=ax)
    sns.barplot(data=df_plot, x="Tier 1",    color="#1f78b4", label="Positives Pool", width=0.25,
                edgecolor="black", y="project_name", order=PROJ_ORDER, ax=ax)

    ax.set_ylabel(None)
    ax.set_xlabel(r"Total Functions in Project (# Blocks > 5)", fontsize=12, fontweight="bold")

    def _humanize(x, _):
        if x == 0:       return "0.0"
        if x >= 1_000_000: return f"{int(x/1_000_000)}M"
        if x >= 1_000:     return f"{int(x/1_000)}K"
        return str(int(x))

    ax.xaxis.set_major_formatter(ticker.FuncFormatter(_humanize))
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_color("#cccccc")

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(dict(zip(labels, handles)).values(),
              dict(zip(labels, handles)).keys(),
              loc="lower right", framealpha=1.0)
    fig.tight_layout()
    out = PLOTS / "project_distribution_layered.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved -> {out}")


def build_complexity_distribution() -> None:
    """Intersecting histogram of function block sizes."""
    
    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    with SessionLocal() as session:
        stmt_nbbs = (
            select(
                Function.id,
                FunctionScalars.nbbs,
            )
            .select_from(Function)
            .join(Binary, Function.binary_id == Binary.id)
            .join(FunctionScalars, Function.id == FunctionScalars.function_id)
            .join(BinaryDatasetTag, Binary.id == BinaryDatasetTag.binary_id)
            .join(Dataset, BinaryDatasetTag.dataset_id == Dataset.id)
            .where(
                Dataset.name == "cisco-talos_dataset1",
                FunctionScalars.nbbs >= 5,
            )
        )
        stage1_df = pd.DataFrame(
            session.execute(stmt_nbbs).all(),
            columns=["function_id", "nbbs"],
        )
    stage1_nbbs = stage1_df["nbbs"].to_numpy()
    
    # Determine range between 5 basic blocks and striped outliers >95%
    tier1_df = pd.read_csv(INTERMEDIATE / "tier1_pool.csv")
    tier2_df = pd.read_csv(INTERMEDIATE / "tier2_pool.csv")
    tier1_nbbs = tier2_df[tier2_df["function_id"].isin(tier1_df["function_id"])]["nbbs"].to_numpy()
    tier2_nbbs = tier2_df["nbbs"].to_numpy()
    
    # Keep full data
    tier1_nbbs_full  = tier1_nbbs
    tier2_nbbs_full  = tier2_nbbs
    stage1_nbbs_full = stage1_nbbs

    # Compute percentiles from full data
    xmax = np.percentile(stage1_nbbs_full, 99)
    
    # Remove outliers
    tier1_nbbs  = tier1_nbbs[tier1_nbbs <= xmax]
    tier2_nbbs  = tier2_nbbs[tier2_nbbs <= xmax]
    stage1_nbbs = stage1_nbbs[stage1_nbbs <= xmax]
    
    # Build long-form dataframe for seaborn
    df = pd.DataFrame({
        "Number of Blocks": np.concatenate([ 
            stage1_nbbs, tier2_nbbs, tier1_nbbs
        ]),
        "pool": (["Qualified"] * len(stage1_nbbs)) +
                (["Negatives Pool"] * len(tier2_nbbs)) +
                (["Positives Pool"] * len(tier1_nbbs))
    })

    sns.set_theme(style="whitegrid")
    fig, ax = plt.subplots(figsize=(8, 4))
    
    sns.violinplot(data=df, y="pool", x="Number of Blocks", hue="pool", ax=ax,
                   cut=0, inner=None, orient="h"
    )
    ax.set_xlim(5, float(xmax))
    ax.set_ylabel(None)
    
    # Overlay true stats per group from *_full
    groups = {
        "Qualified":      stage1_nbbs_full,
        "Negatives Pool": tier2_nbbs_full,
        "Positives Pool": tier1_nbbs_full,
    }

    for i, (_, values) in enumerate(groups.items()):
        q1  = np.percentile(values, 25)
        q2  = np.percentile(values, 50)
        q3  = np.percentile(values, 75)
        p95 = np.percentile(values, 95)

        y = i

        ax.plot([q1, q3], [y, y], color="black", lw=3)
        ax.scatter([q2], [y], color="white", edgecolor="black", zorder=10)
        ax.scatter([p95], [y], color="red", s=30, zorder=10)
    
    fig.tight_layout()
    out = PLOTS / "function_blocks_stats.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved -> {out}")
    

# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def build_attrition_table() -> None:
    """Candidate pool attrition table (Table 5) → tab_dataset_attrition.tex"""
    TABLES.mkdir(parents=True, exist_ok=True)
    t2_csv = INTERMEDIATE / "tier2_attrition.csv"
    t1_csv = INTERMEDIATE / "tier1_attrition.csv"
    if not t2_csv.exists() or not t1_csv.exists():
        print(f"  WARNING: attrition CSVs not found in {INTERMEDIATE}. Run stage 00 first.")
        return

    df_t2  = pd.read_csv(t2_csv)
    df_t1  = pd.read_csv(t1_csv)
    initial = int(df_t2["Count"].iloc[0])

    universal_rows = [
        (0, "Initial radare2 Extraction",         df_t2["Count"].iloc[0]),
        (1, "Structural Qualification",            df_t2["Count"].iloc[1]),
        (2, "Isolation (Unique to Parent Binary)", df_t2["Count"].iloc[2]),
        (3, "PIC Signature Availability",          df_t2["Count"].iloc[3]),
        (4, "PIC-Hash Deduplication",              df_t2["Count"].iloc[4]),
        (5, "Algorithmic Artefact Coverage",       df_t2["Count"].iloc[9]),
    ]
    t1_count = int(df_t1["Count"].iloc[10])
    t1_rows  = [(6, "Persistence Thresholding", t1_count)]

    rows = universal_rows + t1_rows
    df = pd.DataFrame(
        [(s, lbl, f"{int(n):,}", f"{n/initial*100:.2f}\\%")
         for s, lbl, n in rows],
        columns=["Stage", "Filter", r"\# Functions", r"\% Initial"],
    )
    tex = (
        df.style
        .hide(axis="index")
        .to_latex(
            hrules=True,
            caption=(
                r"Candidate pool attrition pipeline. "
                r"Stages 0--5 apply to both Tier~1 and Tier~2; "
                r"Stage~6 (persistence thresholding) applies to Tier~1 only."
            ),
            label="tab:attrition",
        )
    )
    out = TABLES / "tab_dataset_attrition.tex"
    out.write_text(generated_by(__file__) + tex)
    print(f"  Saved -> {out}")


def build_hash_coverage_table() -> None:
    """Per-algorithm hash coverage (Table 6) → tab_hash_coverage.tex"""
    TABLES.mkdir(parents=True, exist_ok=True)
    t2_csv = INTERMEDIATE / "tier2_attrition.csv"
    if not t2_csv.exists():
        print(f"  WARNING: {t2_csv} not found. Run stage 00 first.")
        return

    df_t2    = pd.read_csv(t2_csv)
    baseline = int(df_t2["Count"].iloc[4])

    algo_rows = [
        ("Baseline (Stage 4)",       df_t2["Count"].iloc[4]),
        ("Catalog1",                 df_t2["Count"].iloc[5]),
        ("Machoke",                  df_t2["Count"].iloc[6]),
        ("FunctionSimSearch",        df_t2["Count"].iloc[7]),
        ("CCBHash",                  df_t2["Count"].iloc[8]),
        ("Universal Pool (Stage 5)", df_t2["Count"].iloc[9]),
    ]
    df = pd.DataFrame(
        [(alg, f"{int(n):,}", f"{n/baseline*100:.2f}\\%")
         for alg, n in algo_rows],
        columns=["Algorithm", r"Functions (\#)", r"Retention (\%)"],
    )
    tex = (
        df.style
        .hide(axis="index")
        .to_latex(
            hrules=True,
            caption=(
                r"Fuzzy hash coverage and retention relative to Stage~4 baseline "
                r"($" + f"{baseline:,}" + r"$ functions)."
            ),
            label="tab:hash-coverage",
        )
    )
    out = TABLES / "tab_hash_coverage.tex"
    out.write_text(generated_by(__file__) + tex)
    print(f"  Saved -> {out}")


def main() -> None:
    print("\n=== Project Distribution Plot (requires DB) ===")
    build_project_distribution()
    print("\n=== Project Distribution Plot (requires DB) ===")
    build_complexity_distribution()
    
    print("\n=== Attrition Table ===")
    build_attrition_table()
    print("\n=== Hash Coverage Table ===")
    build_hash_coverage_table()


if __name__ == "__main__":
    main()
