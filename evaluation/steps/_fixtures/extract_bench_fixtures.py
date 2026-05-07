"""
Extract FRASHER benchmark fixtures from the BinRankBench corpus.

Writes evaluation/fixtures/bench_functions.jsonl and
evaluation/fixtures/bucket_boundaries.json.
Log appended to evaluation/logs/fixture_extraction.log.

Bucket boundaries are computed in the DB via percentile_cont; per-bucket
sampling uses ORDER BY random() LIMIT n. Data lake resolution processes one
binary at a time so cfg indexes are loaded and freed sequentially.

Usage (from project root):
    python evaluation/steps/_fixtures/extract_bench_fixtures.py

Optional flags:
    --n N        Functions per bucket (default: 100)
    --seed S     Random seed 0-999 (default: 42)
    --dry-run    Print bucket boundaries without writing fixture
"""
import argparse
import datetime
import csv
import io
import json
import sys
import tarfile
from itertools import groupby
from pathlib import Path

from sqlalchemy import func, select, text

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from binrankbench.common.bin2ml import BinaryDataTracker
from binrankbench.storage.models.core import Binary, Function, FunctionScalars, Project, StrategyMembership
from binrankbench.storage.session import get_engine, make_session_factory
from evaluation.utils.fixtures_common import (
    NBBS_MIN, N_STRATEGIES, BUCKET_LABELS,
    fetch_dataset1_binary_ids, compute_boundaries_from_ids,
)

DATA_LAKE       = project_root / "data" / "marcelliDataGrouped"
OUTPUT_JSONL    = project_root / "evaluation" / "fixtures" / "bench_functions.jsonl"
BOUNDARIES_JSON = project_root / "evaluation" / "fixtures" / "bucket_boundaries.json"
LOG_FILE        = project_root / "evaluation" / "logs" / "fixture_extraction.log"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _sample_bucket(
    session, binary_ids: list[int], lo: float, hi: float, n: int, first: bool
) -> list[dict]:
    """n rows sampled at random from Dataset-1 functions with full strategy coverage.
    Full coverage (all N_STRATEGIES strategies computed) guarantees bytes exist in the data lake."""
    col = FunctionScalars.nbbs
    full_cov = (
        select(StrategyMembership.function_id)
        .group_by(StrategyMembership.function_id)
        .having(func.count() == N_STRATEGIES)
        .subquery()
    )
    stmt = (
        select(
            Function.id.label("function_id"),
            Function.func_addr,
            Binary.bin_name,
            Project.name.label("project_name"),
            col.label("nbbs"),
        )
        .select_from(Function)
        .join(Function.scalars)
        .join(Function.binary)
        .join(Binary.project)
        .join(full_cov, Function.id == full_cov.c.function_id)
        .where(Function.binary_id.in_(binary_ids))
        .where(col.isnot(None))
        .where(col >= lo if first else col > lo)
        .where(col <= hi)
        .order_by(func.random())
        .limit(n)
    )
    return [row._asdict() for row in session.execute(stmt).all()]


# ---------------------------------------------------------------------------
# Data lake extraction
# ---------------------------------------------------------------------------

def _load_cfg_index(cfg_jsonl_path: Path) -> dict[int, dict]:
    index: dict[int, dict] = {}
    with open(cfg_jsonl_path) as fh:
        for line in fh:
            rec = json.loads(line)
            offset = rec.get("offset")
            if offset is not None:
                index[int(offset)] = rec
    return index


def _resolve_binary(
    project_dir: Path,
    bin_name: str,
    rows: list[dict],
) -> list[dict]:
    """
    Extract artefacts for all rows from a single binary.

    Address-based resolution: the func-index CSV inside the tar maps integer
    addresses to func_names and is used as the primary lookup (no name-based
    matching).  The cfg JSONL is still loaded for cfg_record.
    """
    cfg_path  = project_dir / f"{bin_name}_func-cfg.jsonl"
    tar_masked = project_dir / f"{bin_name}_bytes-masked.tar"
    tar_plain  = project_dir / f"{bin_name}_bytes.tar"
    tar_path   = tar_masked if tar_masked.exists() else tar_plain

    if not cfg_path.exists() or not tar_path.exists():
        return []

    # bytes-masked.tar: flat member names; bytes.tar (z3): full path prefix
    if tar_path == tar_masked:
        member_prefix  = ""
        fidx_member    = "00-func-index_bytes.csv"
    else:
        member_prefix  = f"data/marcelliDataGrouped/{project_dir.name}/{bin_name}_bytes/"
        fidx_member    = f"{member_prefix}00-func-index_bytes.csv"

    cfg_index = _load_cfg_index(cfg_path)
    results: list[dict] = []

    try:
        with tarfile.open(tar_path) as tf:
            tar_names = tf.getnames()

            # Build address→func_name from the func-index inside the tar when
            # available (address-based; reliable for z3 and newer extractions).
            # For older tars without the index, fall back to cfg-based name lookup.
            fidx: dict[int, str] | None = None
            if fidx_member in tar_names:
                handle = tf.extractfile(fidx_member)
                if handle is not None:
                    fidx = {}
                    for csv_row in csv.DictReader(io.StringIO(handle.read().decode())):
                        nblocks = int(csv_row.get("nblocks", 0) or 0)
                        if nblocks < NBBS_MIN:
                            continue
                        fidx[int(csv_row["address"])] = csv_row["name"]

            for row in rows:
                func_addr_int = int(row["func_addr"], 16)

                func_name = fidx.get(func_addr_int) if fidx is not None else None
                if not func_name:
                    cfg_rec_tmp = cfg_index.get(func_addr_int)
                    func_name = cfg_rec_tmp.get("name") if cfg_rec_tmp else None

                if not func_name:
                    continue

                # The func-index stores raw names (e.g. full demangled C++);
                # bin2ml sanitizes them (replace non-[\w.-] → '_', truncate to 100)
                # before writing to disk. Apply the same transform to match the tar.
                tar_member_name = BinaryDataTracker.sanitize_filename(func_name)

                try:
                    fobj = tf.extractfile(
                        tf.getmember(f"{member_prefix}{tar_member_name}.raw.bin")
                    )
                except KeyError:
                    continue
                if fobj is None:
                    continue

                raw_bytes = fobj.read()
                if not raw_bytes:
                    continue

                cfg_rec = cfg_index.get(func_addr_int, {})

                results.append({
                    "function_id":  int(row["function_id"]),
                    "nbbs":         int(row["nbbs"]),
                    "nbbs_bucket":  row["nbbs_bucket"],
                    "nbbs_lo":      row["nbbs_lo"],
                    "nbbs_hi":      row["nbbs_hi"],
                    "project_name": row["project_name"],
                    "bin_name":     bin_name,
                    "func_addr":    row["func_addr"],
                    "func_name":    tar_member_name,
                    "bytes_hex":    raw_bytes.hex(),
                    "cfg_record":   cfg_rec,
                })
    finally:
        del cfg_index

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(n_per_bucket: int = 100, seed: int = 42, dry_run: bool = False) -> None:
    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    with SessionLocal() as session:
        session.execute(text("SELECT setseed(:s)"), {"s": min(0.9999, seed / 10000.0)})

        print("Fetching Dataset-1 binary IDs...")
        binary_ids = fetch_dataset1_binary_ids(session)
        print(f"  {len(binary_ids)} binaries in Dataset-1.")

        print("Computing bucket boundaries in DB...")
        boundaries = compute_boundaries_from_ids(session, binary_ids)

        log_lines = [
            f"=== {datetime.datetime.now().isoformat()} ===",
            f"args: --n {n_per_bucket} --seed {seed}{' --dry-run' if dry_run else ''}",
            "bucket boundaries:",
        ]
        print("Bucket boundaries:")
        for i, label in enumerate(BUCKET_LABELS):
            lo, hi = boundaries[i], boundaries[i + 1]
            print(f"  {label}: nbbs [{lo:.0f}, {hi:.0f}]")
            log_lines.append(f"  {label}: nbbs [{lo:.0f}, {hi:.0f}]")

        if dry_run:
            log_lines.append("dry-run: fixture not written")
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a") as lf:
                lf.write("\n".join(log_lines) + "\n\n")
            print(f"\nDry run. Log → {LOG_FILE}")
            return

        BOUNDARIES_JSON.parent.mkdir(parents=True, exist_ok=True)
        BOUNDARIES_JSON.write_text(json.dumps({"bucket_labels": BUCKET_LABELS, "boundaries": boundaries}, indent=2))
        print(f"Boundaries → {BOUNDARIES_JSON}")

        print(f"\nSampling from DB ({n_per_bucket} per bucket, full-coverage functions only)...")
        all_rows: list[dict] = []
        for i, label in enumerate(BUCKET_LABELS):
            lo, hi = boundaries[i], boundaries[i + 1]
            bucket_rows = _sample_bucket(session, binary_ids, lo, hi, n_per_bucket, first=(i == 0))
            for row in bucket_rows:
                row["nbbs_bucket"] = label
                row["nbbs_lo"] = int(lo) if i == 0 else int(lo) + 1
                row["nbbs_hi"] = int(hi)
            all_rows.extend(bucket_rows)
            print(f"  {label}: {len(bucket_rows)} sampled")

    print(f"\nResolving data lake for {len(all_rows)} functions (one binary at a time)...")

    all_rows.sort(key=lambda r: (r["project_name"], r["bin_name"]))

    OUTPUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0

    with open(OUTPUT_JSONL, "w") as out_fh:
        for (project_name, bin_name), group_iter in groupby(
            all_rows, key=lambda r: (r["project_name"], r["bin_name"])
        ):
            group = list(group_iter)
            project_dir = DATA_LAKE / project_name
            records = _resolve_binary(project_dir, bin_name, group)
            for rec in records:
                out_fh.write(json.dumps(rec) + "\n")
            written += len(records)
            skipped += len(group) - len(records)
            if records:
                print(f"  {bin_name}: {len(records)}/{len(group)} written")

    print(f"\nTotal written: {written}  Skipped: {skipped}")
    print(f"Output: {OUTPUT_JSONL}")
    log_lines += [
        f"total written: {written}  skipped: {skipped}",
        f"output: {OUTPUT_JSONL}",
    ]
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as lf:
        lf.write("\n".join(log_lines) + "\n\n")
    print(f"Log → {LOG_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--n", type=int, default=100, metavar="N",
                        help="Functions per bucket (default: 100)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed 0-999 (default: 42)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print boundaries without writing fixture")
    args = parser.parse_args()
    main(n_per_bucket=args.n, seed=args.seed, dry_run=args.dry_run)
