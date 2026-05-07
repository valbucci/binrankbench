"""CLI entry point for the BinRankBench evaluation pipeline.

Usage:
    python -m evaluation --all                   # steps 00-05 then build_output
    python -m evaluation --steps 0 1 2           # run specific steps (int or zero-padded)
    python -m evaluation --clean                 # delete intermediate/, output/, logs/
    python -m evaluation --clean --all           # clean then full rebuild

Run from the repo root (code/binrankbench/) with the project venv active.
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

EVAL = Path(__file__).parent
REPO = EVAL.parent

STEPS_SCRIPTS = {
    0: EVAL / "steps" / "00_select_pools.py",
    1: EVAL / "steps" / "01_generate_pairs.py",
    2: EVAL / "steps" / "02_evaluate_positives.py",
    3: EVAL / "steps" / "03_evaluate_negatives.py",
    4: EVAL / "steps" / "04_frashbf_benchmark.py",
}

CLEANABLE = [
    EVAL / "intermediate",
    EVAL / "output",
    EVAL / "logs",
    EVAL / "notebooks",
]


def _clean() -> None:
    for path in CLEANABLE:
        if path.exists():
            shutil.rmtree(path)
            print(f"  Removed {path.relative_to(REPO)}")
        else:
            print(f"  Already absent: {path.relative_to(REPO)}")


def _run_step(n: int) -> None:
    script = STEPS_SCRIPTS[n]
    if not script.exists():
        print(f"[!] Step {n:02d}: script not found at {script}", file=sys.stderr)
        sys.exit(1)
    print(f"\n{'='*60}")
    print(f" Step {n:02d}: {script.name}")
    print(f"{'='*60}")
    result = subprocess.run([sys.executable, str(script)], cwd=REPO)
    if result.returncode != 0:
        print(f"\n[!] Step {n:02d} failed (exit {result.returncode}). Aborting.", file=sys.stderr)
        sys.exit(result.returncode)


def _run_build_output() -> None:
    print(f"\n{'='*60}")
    print(" build_output: generating all tables and plots")
    print(f"{'='*60}")
    result = subprocess.run(
        [sys.executable, "-m", "evaluation.build_output", "all"],
        cwd=REPO,
    )
    if result.returncode != 0:
        print(f"\n[!] build_output failed (exit {result.returncode}). Aborting.", file=sys.stderr)
        sys.exit(result.returncode)


def _parse_steps(raw: list[str]) -> list[int]:
    steps = []
    for s in raw:
        try:
            n = int(s)
        except ValueError:
            print(f"[!] Invalid step: {s!r}. Must be an integer 0-5.", file=sys.stderr)
            sys.exit(1)
        if n not in STEPS_SCRIPTS:
            print(f"[!] Unknown step {n}. Valid steps: {sorted(STEPS_SCRIPTS)}", file=sys.stderr)
            sys.exit(1)
        steps.append(n)
    return sorted(set(steps))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation",
        description="BinRankBench evaluation pipeline runner.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all steps (00-05) then generate all build outputs.",
    )
    parser.add_argument(
        "--steps",
        nargs="+",
        metavar="N",
        help="Run specific steps by number (e.g. --steps 0 1 2 or --steps 00 01 02).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete intermediate/, output/, logs/, and notebooks/ before running.",
    )

    args = parser.parse_args()

    if not any([args.all, args.steps, args.clean]):
        parser.print_help()
        sys.exit(0)

    if args.clean:
        print("\n=== Cleaning generated directories ===")
        _clean()

    if args.all:
        for n in sorted(STEPS_SCRIPTS):
            _run_step(n)
        _run_build_output()
    elif args.steps:
        for n in _parse_steps(args.steps):
            _run_step(n)


if __name__ == "__main__":
    main()
