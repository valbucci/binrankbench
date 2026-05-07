"""
Extract optimisation sensitivity fixtures.

For each (name_id, project_id) group: anchors at GCC O0, pairs with GCC O1/O2/O3/Os
variants of the same source function. Filters to Tier 1 functions only (full strategy
coverage across all 7 strategies, name_id IS NOT NULL). Stratifies by nbbs bucket
(10 uniform deciles, boundaries computed on the full Dataset-1 pool). Samples N=1000 per
(opt_level_pair x nbbs_bucket) cell, balancing across gcc-4.8/5/7/9 versions.

DB-only -- no data lake access, no bytes or CFG records.

Writes:
    evaluation/fixtures/optimisation_sensitivity_fixtures.jsonl
    evaluation/logs/optimisation_sensitivity_fixture_extraction.log

Usage (from project root):
    python evaluation/steps/_fixtures/extract_optimisation_fixtures.py

Optional flags:
    --n N        Pairs per (opt_level_pair, bucket) cell (default: 1000)
    --seed S     Random seed (default: 42)
    --dry-run    Print boundaries and cell counts without writing fixture
"""
import argparse
import datetime
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select, text

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from binrankbench.storage.models.core import (
    Binary, Function, FunctionScalars, Project,
)
from binrankbench.storage.session import get_engine, make_session_factory
from evaluation.utils.fixtures_common import (
    NBBS_MIN, BUCKET_LABELS,
    fetch_dataset1_binary_ids, compute_boundaries_from_ids,
    _tier1_subquery, _assign_bucket,
)

OUTPUT_JSONL = project_root / "evaluation" / "fixtures" / "optimisation_sensitivity_fixtures.jsonl"
LOG_FILE     = project_root / "evaluation" / "logs" / "optimisation_sensitivity_fixture_extraction.log"

OPT_LEVELS   = ["O1", "O2", "O3", "Os"]
GCC_VERSIONS = ["gcc-4.8", "gcc-5", "gcc-7", "gcc-9"]


def _fetch_candidate_functions(session) -> list[dict]:
    """Fetch all GCC Tier-1 named functions with their opt_level and compiler."""
    col = FunctionScalars.nbbs
    tier1 = _tier1_subquery()
    stmt = (
        select(
            Function.id.label("function_id"),
            Function.name_id,
            Binary.project_id,
            Binary.compiler,
            Binary.opt_level,
            col.label("nbbs"),
            Project.name.label("project_name"),
        )
        .select_from(Function)
        .join(Function.scalars)
        .join(Function.binary)
        .join(Binary.project)
        .join(tier1, Function.id == tier1.c.function_id)
        .where(Function.name_id.isnot(None))
        .where(Binary.compiler.like("gcc%"))
        .where(Binary.opt_level.in_(["O0"] + OPT_LEVELS))
        .where(col.isnot(None))
        .where(col >= NBBS_MIN)
    )
    return [row._asdict() for row in session.execute(stmt).all()]


# ---------------------------------------------------------------------------
# Pair building and sampling
# ---------------------------------------------------------------------------

def _build_pairs(rows: list[dict], boundaries: list[float]) -> list[dict]:
    """
    Group by (name_id, project_id). Anchor on O0; pair with each OPT_LEVEL variant.
    Returns all candidate pairs with bucket assigned from the O0 function's nbbs.
    """
    groups: dict[tuple, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        key = (r["name_id"], r["project_id"])
        groups[key][r["opt_level"]].append(r)

    pairs = []
    for (name_id, project_id), by_opt in groups.items():
        anchors = by_opt.get("O0", [])
        if not anchors:
            continue
        for opt_b in OPT_LEVELS:
            targets = by_opt.get(opt_b, [])
            if not targets:
                continue
            for anchor in anchors:
                bucket = _assign_bucket(int(anchor["nbbs"]), boundaries)
                if bucket is None:
                    continue
                bucket_idx = BUCKET_LABELS.index(bucket)
                lo = boundaries[bucket_idx]
                nbbs_lo = int(lo) if bucket_idx == 0 else int(lo) + 1
                for target in targets:
                    pairs.append({
                        "function_id_A": int(anchor["function_id"]),
                        "function_id_B": int(target["function_id"]),
                        "opt_level_A":   "O0",
                        "opt_level_B":   opt_b,
                        "compiler_A":    anchor["compiler"],
                        "compiler_B":    target["compiler"],
                        "project_name":  anchor["project_name"],
                        "nbbs_bucket":   bucket,
                        "nbbs_lo":       nbbs_lo,
                        "nbbs_A":        int(anchor["nbbs"]),
                    })
    return pairs


def _sample_cell(candidates: list[dict], n: int, rng: random.Random) -> list[dict]:
    """
    Sample up to n pairs from a cell, balancing across GCC compiler_A versions.
    Draws equally from each available gcc-X.Y compiler, then fills remaining quota
    from the full pool if any versions come up short.
    """
    if len(candidates) <= n:
        return list(candidates)

    by_compiler: dict[str, list[dict]] = defaultdict(list)
    for p in candidates:
        by_compiler[p["compiler_A"]].append(p)

    available_compilers = [c for c in GCC_VERSIONS if c in by_compiler]
    if not available_compilers:
        return rng.sample(candidates, n)

    quota = n // len(available_compilers)
    selected: list[dict] = []
    leftover: list[dict] = []

    for compiler in available_compilers:
        pool = by_compiler[compiler]
        take = min(quota, len(pool))
        selected.extend(rng.sample(pool, take))
        leftover.extend(pool[take:] if take < len(pool) else [])

    remaining = n - len(selected)
    if remaining > 0 and leftover:
        selected.extend(rng.sample(leftover, min(remaining, len(leftover))))

    return selected


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(n_per_cell: int = 1000, seed: int = 42, dry_run: bool = False) -> None:
    rng = random.Random(seed)
    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    with SessionLocal() as session:
        session.execute(text("SELECT setseed(:s)"), {"s": min(0.9999, seed / 10000.0)})

        print("Fetching Dataset-1 binary IDs...")
        binary_ids = fetch_dataset1_binary_ids(session)
        print(f"  {len(binary_ids)} binaries in Dataset-1.")

        print("Computing nbbs bucket boundaries on full Dataset-1 pool...")
        boundaries = compute_boundaries_from_ids(session, binary_ids)

        log_lines = [
            f"=== {datetime.datetime.now().isoformat()} ===",
            f"args: --n {n_per_cell} --seed {seed}{' --dry-run' if dry_run else ''}",
            "nbbs bucket boundaries:",
        ]
        print("Bucket boundaries:")
        for i, label in enumerate(BUCKET_LABELS):
            lo, hi = boundaries[i], boundaries[i + 1]
            line = f"  {label}: nbbs [{lo:.0f}, {hi:.0f}]"
            print(line)
            log_lines.append(line)

        print("\nFetching candidate GCC functions from DB...")
        rows = _fetch_candidate_functions(session)
        print(f"  {len(rows):,} qualifying function rows fetched.")

    print("Building cross-optimisation pairs...")
    pairs = _build_pairs(rows, boundaries)
    print(f"  {len(pairs):,} candidate pairs before sampling.")

    # Group by (opt_level_pair, nbbs_bucket) for sampling
    cells: dict[tuple, list[dict]] = defaultdict(list)
    for p in pairs:
        cells[(p["opt_level_B"], p["nbbs_bucket"])].append(p)

    print("\nCell counts before sampling:")
    log_lines.append("cell counts (opt_level_B, bucket): available -> sampled")
    sampled: list[dict] = []
    for opt_b in OPT_LEVELS:
        for bucket in BUCKET_LABELS:
            key = (opt_b, bucket)
            candidates = cells.get(key, [])
            cell_sample = _sample_cell(candidates, n_per_cell, rng)
            sampled.extend(cell_sample)
            line = f"  ({opt_b}, {bucket}): {len(candidates)} -> {len(cell_sample)}"
            print(line)
            log_lines.append(line)

    log_lines.append(f"total pairs written: {len(sampled)}")

    if dry_run:
        log_lines.append("dry-run: fixture not written")
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as lf:
            lf.write("\n".join(log_lines) + "\n\n")
        print(f"\nDry run. Log -> {LOG_FILE}")
        return

    OUTPUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSONL, "w") as fh:
        for rec in sampled:
            fh.write(json.dumps(rec) + "\n")

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as lf:
        lf.write("\n".join(log_lines) + "\n\n")

    print(f"\nTotal written: {len(sampled):,} pairs")
    print(f"Output: {OUTPUT_JSONL}")
    print(f"Log -> {LOG_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--n", type=int, default=1000, metavar="N",
                        help="Pairs per (opt_level_pair, bucket) cell (default: 1000)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print boundaries and counts without writing fixture")
    args = parser.parse_args()
    main(n_per_cell=args.n, seed=args.seed, dry_run=args.dry_run)
