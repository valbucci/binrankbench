"""
Extract compilation sensitivity fixtures.

8 scenarios, both functions at the same opt level (O0 or Os):
  comp             -- diff compiler family, same arch family, same bitness, both O0
  bit              -- same compiler family, diff bitness, same arch family, both O0
  arch             -- same compiler family, diff arch family, same bitness, both O0
  comp+bit         -- diff compiler family, diff bitness, same arch family, both O0
  arch+bit         -- same compiler family, diff arch family, diff bitness, both O0
  comp+arch        -- diff compiler family, diff arch family, same bitness, both O0
  comp+arch+bit    -- diff compiler family, diff arch family, diff bitness, both O0
  comp+arch+bit-Os -- same as above, both Os

Tier 1 functions only (all 7 strategies, name_id IS NOT NULL, nbbs >= 5).
N=1000 per (scenario, bucket) cell, free random sampling.
Bucket boundaries loaded from evaluation/fixtures/bucket_boundaries.json.

Usage (from project root):
    python evaluation/steps/_fixtures/extract_compilation_fixtures.py [--dry-run] [--n N] [--seed S]
"""
import argparse
import datetime
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from binrankbench.storage.models.core import (
    Binary, Function, FunctionScalars,
)
from binrankbench.storage.session import get_engine, make_session_factory
from evaluation.utils.fixtures_common import (
    NBBS_MIN, BUCKET_LABELS, _tier1_subquery, _assign_bucket,
)
from evaluation.utils.constants import ARCH_FAMILY_MAP, BITNESS_MAP



OUTPUT_JSONL    = project_root / "evaluation" / "fixtures" / "compilation_sensitivity_fixtures.jsonl"
LOG_FILE        = project_root / "evaluation" / "logs" / "compilation_sensitivity_fixture_extraction.log"
BOUNDARIES_JSON = project_root / "evaluation" / "fixtures" / "bucket_boundaries.json"

SCENARIOS = [
    {"name": "comp",             "diff_cc": True,  "diff_arch": False, "diff_bit": False, "opt": "O0"},
    {"name": "bit",              "diff_cc": False, "diff_arch": False, "diff_bit": True,  "opt": "O0"},
    {"name": "arch",             "diff_cc": False, "diff_arch": True,  "diff_bit": False, "opt": "O0"},
    {"name": "comp+bit",         "diff_cc": True,  "diff_arch": False, "diff_bit": True,  "opt": "O0"},
    {"name": "arch+bit",         "diff_cc": False, "diff_arch": True,  "diff_bit": True,  "opt": "O0"},
    {"name": "comp+arch",        "diff_cc": True,  "diff_arch": True,  "diff_bit": False, "opt": "O0"},
    {"name": "comp+arch+bit",    "diff_cc": True,  "diff_arch": True,  "diff_bit": True,  "opt": "O0"},
    {"name": "comp+arch+bit-Os", "diff_cc": True,  "diff_arch": True,  "diff_bit": True,  "opt": "Os"},
]

# Group scenarios by their required opt level to avoid re-enumerating the same
# pair set once per scenario. 7 of 8 scenarios share O0; Os has its own pool.
_SCENARIOS_BY_OPT: dict[str, list[dict]] = {}
for _sc in SCENARIOS:
    _SCENARIOS_BY_OPT.setdefault(_sc["opt"], []).append(_sc)


def _pair_matches(a: dict, b: dict, sc: dict) -> bool:
    if (a["cc_family"] != b["cc_family"]) != sc["diff_cc"]:
        return False
    if (a["arch_family"] != b["arch_family"]) != sc["diff_arch"]:
        return False
    if (a["bitness"] != b["bitness"]) != sc["diff_bit"]:
        return False
    return True


def _fetch_candidates(session) -> list[dict]:
    tier1 = _tier1_subquery()
    stmt = (
        select(
            Function.id.label("function_id"),
            Function.name_id,
            Binary.project_id,
            Binary.compiler,
            Binary.opt_level,
            Binary.arch,
            FunctionScalars.nbbs,
        )
        .select_from(Function)
        .join(Function.scalars)
        .join(Function.binary)
        .join(tier1, Function.id == tier1.c.function_id)
        .where(Function.name_id.isnot(None))
        .where(FunctionScalars.nbbs.isnot(None))
        .where(FunctionScalars.nbbs >= NBBS_MIN)
        .where(Binary.arch.in_(list(ARCH_FAMILY_MAP)))
        .where(Binary.opt_level.in_(["O0", "Os"]))
    )
    rows = []
    for r in session.execute(stmt).all():
        d = r._asdict()
        d["cc_family"]   = d["compiler"].split("-")[0]
        d["arch_family"] = ARCH_FAMILY_MAP[d["arch"]]
        d["bitness"]     = BITNESS_MAP[d["arch"]]
        rows.append(d)
    return rows


def _build_pairs(rows: list[dict], boundaries: list[float]) -> dict[str, list[dict]]:
    # 11 possible (bucket, nbbs_lo) values - precompute to avoid index lookup per pair
    bucket_to_nbbs_lo = {
        lbl: (int(boundaries[i]) if i == 0 else int(boundaries[i]) + 1)
        for i, lbl in enumerate(BUCKET_LABELS)
    }

    # Group by (name_id, project_id) -> then by opt_level
    by_fn: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        by_fn[(r["name_id"], r["project_id"])][r["opt_level"]].append(r)

    all_pairs: dict[str, list[dict]] = defaultdict(list)

    for by_opt in by_fn.values():
        for opt, opt_scenarios in _SCENARIOS_BY_OPT.items():
            opt_fns = by_opt.get(opt, [])
            if len(opt_fns) < 2:
                continue
            for i, fn_a in enumerate(opt_fns):
                # bucket check for fn_a done once per fn_a, not once per (fn_a, fn_b, scenario)
                bucket = _assign_bucket(int(fn_a["nbbs"]), boundaries)
                if bucket is None:
                    continue
                for fn_b in opt_fns[i + 1:]:
                    if _assign_bucket(int(fn_b["nbbs"]), boundaries) is None:
                        continue
                    for sc in opt_scenarios:
                        if _pair_matches(fn_a, fn_b, sc):
                            all_pairs[sc["name"]].append({
                                "function_id_A": int(fn_a["function_id"]),
                                "function_id_B": int(fn_b["function_id"]),
                                "scenario":      sc["name"],
                                "nbbs_bucket":   bucket,
                                "nbbs_lo":       bucket_to_nbbs_lo[bucket],
                                "nbbs_A":        int(fn_a["nbbs"]),
                            })

    return dict(all_pairs)


def main(n_per_cell: int = 1000, seed: int = 42, dry_run: bool = False) -> None:
    rng = random.Random(seed)

    boundaries = json.loads(BOUNDARIES_JSON.read_text())["boundaries"]

    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    with SessionLocal() as session:
        print("Fetching Tier-1 candidate functions...")
        rows = _fetch_candidates(session)
    print(f"  {len(rows):,} qualifying function rows fetched.")

    print("Building cross-compilation pairs...")
    pairs_by_scenario = _build_pairs(rows, boundaries)

    log_lines = [
        f"=== {datetime.datetime.now().isoformat()} ===",
        f"args: --n {n_per_cell} --seed {seed}{' --dry-run' if dry_run else ''}",
        "cell counts (scenario, bucket): available -> sampled",
    ]

    sampled: list[dict] = []
    for sc in SCENARIOS:
        sc_name = sc["name"]
        by_bucket: dict[str, list[dict]] = defaultdict(list)
        for p in pairs_by_scenario.get(sc_name, []):
            by_bucket[p["nbbs_bucket"]].append(p)
        for bucket in BUCKET_LABELS:
            candidates = by_bucket.get(bucket, [])
            cell_sample = rng.sample(candidates, min(n_per_cell, len(candidates)))
            sampled.extend(cell_sample)
            line = f"  ({sc_name}, {bucket}): {len(candidates)} -> {len(cell_sample)}"
            print(line)
            log_lines.append(line)

    log_lines.append(f"total pairs written: {len(sampled)}")

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as lf:
        lf.write("\n".join(log_lines) + "\n\n")

    if dry_run:
        print(f"\nDry run complete. Log -> {LOG_FILE}")
        return

    OUTPUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSONL, "w") as fh:
        for rec in sampled:
            fh.write(json.dumps(rec) + "\n")

    print(f"\nTotal written: {len(sampled):,} pairs")
    print(f"Output: {OUTPUT_JSONL}")
    print(f"Log -> {LOG_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--n",       type=int, default=1000, metavar="N")
    parser.add_argument("--seed",    type=int, default=42)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(n_per_cell=args.n, seed=args.seed, dry_run=args.dry_run)
