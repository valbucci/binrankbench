"""CLI smoke tests for ``python -m binrankbench ingest``.

These tests exercise the argument-parsing layer without touching a real
database.  The module is invoked as a subprocess so that import-time
side-effects are isolated from the pytest process.
"""

import subprocess
import sys

import pytest

_BASE = [sys.executable, "-m", "binrankbench", "ingest"]


@pytest.mark.unit
def test_help():
    """--help exits 0 and mentions 'usage' (case-insensitive)."""
    result = subprocess.run(
        _BASE + ["--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    combined = (result.stdout + result.stderr).lower()
    assert "usage" in combined


@pytest.mark.unit
def test_missing_required_args():
    """Running with no dataset_path must exit non-zero."""
    result = subprocess.run(
        _BASE,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


@pytest.mark.unit
def test_invalid_strategy(tmp_path):
    """Passing an unknown strategy name must exit non-zero and mention it."""
    result = subprocess.run(
        _BASE + ["--strategies", "bad_strategy", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    combined = (result.stdout + result.stderr).lower()
    assert "bad_strategy" in combined or "unknown" in combined or "error" in combined


@pytest.mark.unit
def test_single_process_flag_present():
    """--single-process must be documented in the --help output."""
    result = subprocess.run(
        _BASE + ["--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--single-process" in result.stdout + result.stderr
