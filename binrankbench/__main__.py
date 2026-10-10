"""
BinRankBench command-line interface.

    python -m binrankbench extract  [staging_dir] [out_dir] [options]
    python -m binrankbench ingest   <dataset_path> [options]
    python -m binrankbench ingest   --clear-logs <dataset_path>
    python -m binrankbench evaluate

Run ``python -m binrankbench <command> --help`` for per-command options.
No installation required — works from the repo root after ``pip install -r requirements.txt``.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_ALL_STRATEGIES = ["ccbhash", "machoke", "fss", "catalog1", "bytes", "function_details"]
_DEFAULT_MODES = ["bytes", "finfo", "zigs", "func-cfg", "cg", "bininfo"]


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------

def _cmd_extract(args: argparse.Namespace) -> None:
    from binrankbench.common.bin2ml import Bin2MLPipe

    staging_dir = Path(args.staging_dir)
    out_dir = Path(args.out_dir)

    if not staging_dir.is_dir():
        sys.exit(f"Error: staging_dir does not exist or is not a directory: {staging_dir}")

    bin2ml_exe = shutil.which("bin2ml")
    if bin2ml_exe is None:
        sys.exit(
            "Error: bin2ml not found on PATH.\n"
            "Use the ingestion Docker image or build bin2ml from source: "
            "https://github.com/valbucci/bin2ml"
        )

    pipe = Bin2MLPipe(bin2ml_exe, num_threads=args.num_threads, capture_output=False)

    print(f"STAGING_DIR : {staging_dir}")
    print(f"OUT_DIR     : {out_dir}")
    print("===")

    projects = sorted(p for p in staging_dir.iterdir() if p.is_dir())
    if not projects:
        sys.exit("No project sub-directories found in staging_dir.")

    for project_dir in projects:
        files = list(project_dir.iterdir())
        if not files:
            print(f"Skipping {project_dir.name} (empty directory)")
            continue

        out = out_dir / project_dir.name
        out.mkdir(parents=True, exist_ok=True)
        print(f"Processing: {project_dir.name} ({len(files)} files)")

        # Options mirror batch_ingestion.sh; *options are injected before -f by extract().
        pipe.extract(
            project_dir,
            out,
            args.modes,
            "-l", "info",
            "--extended-analysis",
            "--data-grouped",
            "--min-basic-blocks", str(args.min_basic_blocks),
        )
        print(f"Finished: {project_dir.name}\n---")

    print(f"All projects processed. Output written to: {out_dir}")


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

def _cmd_ingest(args: argparse.Namespace) -> None:
    dataset_path = Path(args.dataset_path).resolve()
    if not dataset_path.is_dir():
        sys.exit(f"Error: dataset_path does not exist or is not a directory: {dataset_path}")

    unknown = set(args.strategies) - set(_ALL_STRATEGIES)
    if unknown:
        sys.exit(
            f"Unknown strategies: {', '.join(sorted(unknown))}\n"
            f"Valid choices: {', '.join(_ALL_STRATEGIES)}"
        )

    projects = sorted(p for p in dataset_path.iterdir() if p.is_dir())
    for project_dir in projects:
        print(f"\n--- {project_dir.name}: {project_dir} ---")

        if not args.single_process:
            from binrankbench.storage.mp_ingest import ingest_directory_mp

            ingest_directory_mp(
                raw_data_dir=project_dir,
                project=project_dir.name,
                datasets=args.datasets,
                strategies=args.strategies,
                n_runners=args.n_runners,
                n_posters=args.n_posters,
                overwrite=args.overwrite,
            )
        else:
            from binrankbench.common.config import load_config
            from binrankbench.storage.ingest import ingest_directory
            from binrankbench.storage.session import get_engine, get_session, init_db

            config = load_config()
            engine = get_engine(config.storage["db_url"])
            init_db(engine)
            with get_session(engine) as session:
                binaries = ingest_directory(
                    session=session,
                    project=project_dir.name,
                    raw_data_dir=project_dir,
                    datasets=args.datasets,
                    strategies=args.strategies,
                    overwrite=args.overwrite,
                )
            print(f"Ingested {len(binaries)} binaries for '{project_dir.name}'.")

        time.sleep(3)


def _cmd_clear_logs(args: argparse.Namespace) -> None:
    dataset_path = Path(args.dataset_path).resolve()
    runtime_log = _ROOT / "runtime.log"
    skipped_log = _ROOT / "skipped_tasks.csv"

    print(f"Runtime log : {runtime_log}")
    print(f"Skipped log : {skipped_log}")
    print(f"Dataset path: {dataset_path}")
    print("===")

    if runtime_log.exists():
        runtime_log.unlink()
        print("Wiped runtime.log")
    else:
        print("No runtime.log found.")
    runtime_log.touch()

    if skipped_log.exists():
        skipped_log.unlink()
        print("Removed skipped_tasks.csv")

    markers = list(dataset_path.rglob("*.ingest_done"))
    if markers:
        print(f"Deleting {len(markers)} .ingest_done markers ...")
        for m in markers:
            m.unlink()
    print("Cleanup done!")


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------

def _cmd_evaluate(_args: argparse.Namespace) -> None:
    stages = [
        ("Pool selection",       "evaluation/stages/00_select_pools.py"),
        ("Pair generation",      "evaluation/stages/01_generate_pairs.py"),
        ("Evaluating positives", "evaluation/stages/02_evaluate_positives.py"),
        ("Evaluating negatives", "evaluation/stages/03_evaluate_negatives.py"),
    ]
    print(f"Run logs will be written to: {_ROOT / 'evaluation' / 'logs'}/")
    for i, (label, script) in enumerate(stages):
        print(f"\n[{i}/{len(stages) - 1}] {label}...")
        # Inherit stdout/stderr so the stage's StreamTee writes output once to
        # the terminal and once to its log file — no duplication, no buffering.
        subprocess.run(
            [sys.executable, _ROOT / script],
            check=True,
            cwd=_ROOT,
        )
    print("\nDone. Results in evaluation/results/, logs in evaluation/logs/.")


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m binrankbench",
        description="BinRankBench — binary function similarity evaluation framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- extract ---
    p_ext = sub.add_parser(
        "extract",
        help="Run bin2ml feature extraction on a directory of raw binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Iterate over project sub-directories inside staging_dir and run\n"
            "bin2ml on each, writing extracted features to out_dir/<project>/.\n\n"
            "Requires bin2ml to be installed and available on PATH."
        ),
    )
    p_ext.add_argument(
        "staging_dir",
        nargs="?",
        default="data/binaries",
        help="Directory of raw binaries organised as <project>/<binary-files> "
             "(default: data/binaries)",
    )
    p_ext.add_argument(
        "out_dir",
        nargs="?",
        default="data/extracted",
        help="Destination directory for bin2ml output (default: data/extracted)",
    )
    p_ext.add_argument(
        "-m", "--modes",
        nargs="+",
        default=_DEFAULT_MODES,
        metavar="MODE",
        help=f"bin2ml extraction modes (default: {' '.join(_DEFAULT_MODES)})",
    )
    p_ext.add_argument(
        "-n", "--num-threads",
        type=int,
        default=8,
        metavar="N",
        help="Number of bin2ml worker threads per project (default: 8)",
    )
    p_ext.add_argument(
        "--min-basic-blocks",
        type=int,
        default=5,
        metavar="N",
        help="Skip functions with fewer than N basic blocks (default: 5)",
    )

    # --- ingest ---
    p_ing = sub.add_parser(
        "ingest",
        help="Ingest bin2ml-extracted data into the PostgreSQL database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Iterate over project sub-directories inside dataset_path and\n"
            "compute fuzzy-hash signatures for each binary, storing results\n"
            "in the configured PostgreSQL database.\n\n"
            "Pass --clear-logs to delete runtime.log, skipped_tasks.csv and\n"
            ".ingest_done markers instead of running ingestion."
        ),
    )
    p_ing.add_argument(
        "dataset_path",
        nargs="?",
        help="Root directory whose sub-directories are project-named folders "
             "of bin2ml-extracted data.",
    )
    p_ing.add_argument(
        "--clear-logs",
        action="store_true",
        help="Delete runtime.log, skipped_tasks.csv and all .ingest_done markers "
             "in dataset_path, then exit.",
    )
    p_ing.add_argument(
        "--single-process",
        action="store_true",
        help="Use single-process pipeline (default: multiprocess). "
             "Useful for small datasets or debugging.",
    )
    p_ing.add_argument(
        "--n-runners",
        type=int,
        default=12,
        metavar="N",
        help="Number of TaskRunner workers — multiprocess only (default: 12)",
    )
    p_ing.add_argument(
        "--n-posters",
        type=int,
        default=4,
        metavar="N",
        help="Number of TaskPoster workers — multiprocess only (default: 4)",
    )
    p_ing.add_argument(
        "--strategies",
        nargs="+",
        default=_ALL_STRATEGIES,
        metavar="STRATEGY",
        help=f"Strategies to compute (default: all). "
             f"Choices: {', '.join(_ALL_STRATEGIES)}",
    )
    p_ing.add_argument(
        "--datasets",
        nargs="+",
        default=[],
        metavar="DATASET",
        help="Dataset tags to attach to every ingested binary.",
    )
    p_ing.add_argument(
        "--overwrite",
        action="store_true",
        help="Re-compute and overwrite existing signatures.",
    )

    # --- evaluate ---
    sub.add_parser(
        "evaluate",
        help="Run the full evaluation pipeline (stages 00–03) in order.",
        description=(
            "Runs stages 00_select_pools → 01_generate_pairs → "
            "02_evaluate_positives → 03_evaluate_negatives.\n"
            "Results are written to evaluation/results/; "
            "logs to evaluation/logs/.\n"
            "This takes several hours on the full dataset."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    return parser


def main() -> None:
    from binrankbench.common.logging import setup_default_logging
    setup_default_logging(
        console_level=__import__("logging").INFO,
        file_path=_ROOT / "binrankbench.log",
    )

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "extract":
        _cmd_extract(args)
    elif args.command == "ingest":
        if not args.dataset_path:
            parser.error("ingest requires dataset_path")
        if args.clear_logs:
            _cmd_clear_logs(args)
        else:
            _cmd_ingest(args)
    elif args.command == "evaluate":
        _cmd_evaluate(args)


if __name__ == "__main__":
    main()
