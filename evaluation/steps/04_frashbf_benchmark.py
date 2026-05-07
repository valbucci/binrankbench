"""
FRASH-BF performance benchmark for BFSA algorithms inspired by FRASHER.

Produces outputs in evaluation/intermediate/throughput/:

  comparison_throughput.csv: pairs/sec per algorithm; times pure digest comparison.
  generation_throughput.csv: full-pipeline generation throughput (fn/s) per 
                             algorithm from cached radare2 artefacts.

Run from the project root:
    python -m evaluation --steps 4
"""
import json
import sys
import time
from itertools import groupby
from pathlib import Path
from typing import Any, cast

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from binrankbench.common.types import R2CallGraph
from binrankbench.storage.session import get_engine, make_session_factory
from binrankbench.modules.byte_signature import ByteSignature
from binrankbench.modules.catalog1 import numba_sign, slow_sign
from binrankbench.modules.ccbhash import CCBHash, CCBHashBuilder
from binrankbench.modules.fss import fcode_to_hash
from binrankbench.modules.machoke import fcode_to_machoke_hash
from evaluation.utils.constants import CAT1_NUM_PERMS, CCB_NO_NAME_WEIGHTS_NP, CCB_NO_NAME_EQUAL_NP, CCB_K
from evaluation.utils.logging_utils import setup_logging
from evaluation.utils.helpers import _missing, fetch_fingerprints_in_chunks
from evaluation.utils.context import (
    INTERMEDIATE_DIR, SIMILARITY_DIR, FIXTURES_DIR, DATA_LAKE_DIR
)
from evaluation.utils.constants import ALGORITHMS

log = setup_logging(__file__)

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
RESULTS_DIR = INTERMEDIATE_DIR
SCORED_DIR = SIMILARITY_DIR / "1vN"
THROUGHPUT_DIR = RESULTS_DIR / "throughput"
BENCH_JSONL = FIXTURES_DIR / "bench_functions.jsonl"
DATA_LAKE = DATA_LAKE_DIR / "marcelliDataGrouped"

THROUGHPUT_DIR.mkdir(parents=True, exist_ok=True)

N_TIMING_SAMPLE = 5_000
TIMING_ROUNDS = 50
CHUNK_SIZE = 1_000

CAT1_EQUAL_NP = np.ones(CAT1_NUM_PERMS, dtype=np.float32)


# Lookup table for popcount of 8-bit values (0-255).
# Used in _bytesig_compare to avoid repeated bin() calls.
_POPCOUNT_LUT = np.array([bin(i).count("1") for i in range(256)], dtype=np.int32)
_BYTESIG_CAP = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _attach_sig_columns(df: pd.DataFrame, fingerprints: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for alg in ALGORITHMS:
        d = fingerprints[alg]
        df.loc[:, f"{alg}_A"] = df["function_id_A"].map(d)
        df.loc[:, f"{alg}_B"] = df["function_id_B"].map(d)
    df.loc[:, "nbbs_A"] = df["function_id_A"].map(fingerprints["nbbs"])
    df.loc[:, "nbbs_B"] = df["function_id_B"].map(fingerprints["nbbs"])
    return df


# ---------------------------------------------------------------------------
# Numpy precompute helpers -- format conversion only, NOT timed.
# Each converts the stored digest format (bytes/tuples from fetch)
# into contiguous numpy arrays. The actual comparison operations (XOR, popcount,
# mask arithmetic, equality checks) run inside the timed closures below.
# ---------------------------------------------------------------------------

def _precompute_machoke(df_sigs: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, int]:
    valid = df_sigs["machoke_A"].notna() & df_sigs["machoke_B"].notna()
    rows = df_sigs[valid]
    if rows.empty:
        empty = np.empty(0, dtype=np.int32)
        return empty, empty, 0
    arr_A = np.frombuffer(b"".join(v.rjust(4, b"\x00") for v in rows["machoke_A"]), dtype=np.int32)
    arr_B = np.frombuffer(b"".join(v.rjust(4, b"\x00") for v in rows["machoke_B"]), dtype=np.int32)
    return arr_A, arr_B, int(valid.sum())


def _precompute_ccbhash(df_sigs: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, int]:
    def _to_np(d: Any) -> np.ndarray | None:
        return None if _missing(d) else CCBHash(d).to_numpy()
    np_A = df_sigs["ccb_A"].map(_to_np)
    np_B = df_sigs["ccb_B"].map(_to_np)
    valid = np_A.notna() & np_B.notna()
    if valid.any():
        mat_A = np.vstack([arr for arr in np_A[valid] if arr is not None])
        mat_B = np.vstack([arr for arr in np_B[valid] if arr is not None])
    else:
        mat_A = mat_B = np.empty((0, CCB_K), dtype=np.int64)
    return mat_A, mat_B, int(valid.sum())


def _precompute_fss_arrays(df_sigs: pd.DataFrame, key: str) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int]:
    col_A, col_B = f"{key}_A", f"{key}_B"
    valid = df_sigs[col_A].notna() & df_sigs[col_B].notna()
    rows = df_sigs[valid]
    N = int(valid.sum())
    if N == 0:
        empty = np.empty(0, dtype=np.uint64)
        return empty, empty, empty, empty, 0
    # Each tuple is (first_bytes, second_bytes), 8 bytes each (uint64 as LargeBinary).
    first_A  = np.array([int.from_bytes(t[0], "big") for t in rows[col_A]], dtype=np.uint64)
    second_A = np.array([int.from_bytes(t[1], "big") for t in rows[col_A]], dtype=np.uint64)
    first_B  = np.array([int.from_bytes(t[0], "big") for t in rows[col_B]], dtype=np.uint64)
    second_B = np.array([int.from_bytes(t[1], "big") for t in rows[col_B]], dtype=np.uint64)
    return first_A, second_A, first_B, second_B, N


def _precompute_catalog1(df_sigs: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, int]:
    valid = df_sigs["cat1_A"].notna() & df_sigs["cat1_B"].notna()
    rows = df_sigs[valid]
    if rows.empty:
        empty = np.empty((0, 16), dtype=np.int64)
        return empty, empty, 0
    mat_A = np.array([list(t) for t in rows["cat1_A"]], dtype=np.int64)
    mat_B = np.array([list(t) for t in rows["cat1_B"]], dtype=np.int64)
    return mat_A, mat_B, int(valid.sum())


def _precompute_bytesig_mats(df_sigs: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, int]:
    valid = df_sigs["bysig_A"].notna() & df_sigs["bysig_B"].notna()
    rows = df_sigs[valid]
    N = int(valid.sum())
    if N == 0:
        z = np.empty(0, dtype=np.int32)
        empty_mat = np.empty((0, _BYTESIG_CAP), dtype=np.uint8)
        return empty_mat, empty_mat, empty_mat, empty_mat, z, z, z, z, 0

    mat_bytes_A = np.zeros((N, _BYTESIG_CAP), dtype=np.uint8)
    mat_mask_A  = np.zeros((N, _BYTESIG_CAP), dtype=np.uint8)
    mat_bytes_B = np.zeros((N, _BYTESIG_CAP), dtype=np.uint8)
    mat_mask_B  = np.zeros((N, _BYTESIG_CAP), dtype=np.uint8)
    len_A = np.zeros(N, dtype=np.int32)
    len_B = np.zeros(N, dtype=np.int32)
    cc_A  = np.zeros(N, dtype=np.int32)
    cc_B  = np.zeros(N, dtype=np.int32)

    a_list = rows["bysig_A"].tolist()
    b_list = rows["bysig_B"].tolist()
    for i, (a_tup, b_tup) in enumerate(zip(a_list, b_list)):
        raw_a, mask_a, ca = a_tup
        raw_b, mask_b, cb = b_tup
        la = min(len(raw_a), _BYTESIG_CAP)
        lb = min(len(raw_b), _BYTESIG_CAP)
        mat_bytes_A[i, :la] = np.frombuffer(raw_a[:la], dtype=np.uint8)
        mat_mask_A[i,  :la] = np.frombuffer(mask_a[:la], dtype=np.uint8)
        mat_bytes_B[i, :lb] = np.frombuffer(raw_b[:lb], dtype=np.uint8)
        mat_mask_B[i,  :lb] = np.frombuffer(mask_b[:lb], dtype=np.uint8)
        len_A[i] = la
        len_B[i] = lb
        cc_A[i]  = int(ca) if ca else 0
        cc_B[i]  = int(cb) if cb else 0

    return mat_bytes_A, mat_mask_A, mat_bytes_B, mat_mask_B, len_A, len_B, cc_A, cc_B, N


# ---------------------------------------------------------------------------
# Timed comparison kernels.
# XOR/popcount/mask arithmetic included; only format conversion is excluded.
# ---------------------------------------------------------------------------

def _fss_popcount(
    first_A: np.ndarray, second_A: np.ndarray,
    first_B: np.ndarray, second_B: np.ndarray,
) -> np.ndarray:
    return (np.bitwise_count(first_A ^ first_B)
            + np.bitwise_count(second_A ^ second_B)).astype(np.int64)


def _fss_hsim(
    first_A: np.ndarray, second_A: np.ndarray,
    first_B: np.ndarray, second_B: np.ndarray,
) -> np.ndarray:
    return 1.0 - _fss_popcount(first_A, second_A, first_B, second_B) / 128.0


def _fss_hdist(
    first_A: np.ndarray, second_A: np.ndarray,
    first_B: np.ndarray, second_B: np.ndarray,
) -> np.ndarray:
    return _fss_popcount(first_A, second_A, first_B, second_B).astype(np.float64)


def _fss_kappa(
    first_A: np.ndarray, second_A: np.ndarray,
    first_B: np.ndarray, second_B: np.ndarray,
) -> np.ndarray:
    # Cohen's Kappa: clips to 0 if hsim <= 50%, maps to [0,1] if hsim > 50%
    return np.maximum(0.0, 64.0 - _fss_popcount(first_A, second_A, first_B, second_B)) / 64.0


def _bytesig_compare(
    mat_bytes_A: np.ndarray, mat_mask_A: np.ndarray,
    mat_bytes_B: np.ndarray, mat_mask_B: np.ndarray,
    len_A: np.ndarray, len_B: np.ndarray,
    cc_A: np.ndarray, cc_B: np.ndarray,
    withcheck: bool,
) -> np.ndarray:
    common_mask    = mat_mask_A & mat_mask_B
    byte_match     = (mat_bytes_A & common_mask) == (mat_bytes_B & common_mask)
    mask_bitcounts = _POPCOUNT_LUT[common_mask]
    matching_bits  = (byte_match * mask_bitcounts).sum(axis=1).astype(np.int32)
    max_len        = np.maximum(len_A, len_B)
    scores         = matching_bits / 8.0 / np.maximum(max_len, 1)
    if withcheck:
        scores[(cc_A < 10) | (cc_B < 10) | (matching_bits < 128)] = 0.0
    return scores


# ---------------------------------------------------------------------------
# Comparison Throughput
# ---------------------------------------------------------------------------

def build_comparison_throughput(session: Session, scored_xa: pd.DataFrame) -> pd.DataFrame:
    sample = scored_xa.sample(min(N_TIMING_SAMPLE, len(scored_xa)), random_state=42)
    unique_ids = pd.unique(sample[["function_id_A", "function_id_B"]].values.ravel()).tolist()

    log.info(f"  Fetching signatures for {len(unique_ids)} functions...")
    fingerprints_list = fetch_fingerprints_in_chunks(session, unique_ids)
    df_fingerprints = pd.DataFrame(fingerprints_list)
    del fingerprints_list
    
    log.info("Mapping fingerprints to DataFrame...")
    df = sample.merge(df_fingerprints.add_suffix("_A"), on="function_id_A", how="left")
    df = df.merge(df_fingerprints.add_suffix("_B"), on="function_id_B", how="left")
    # df_sigs = _attach_sig_columns(sample, df_fingerprints)
    print(df.columns)

    # Format conversion -- not timed. Builds contiguous numpy arrays from stored
    # digest representations. The actual comparison kernels run inside the loop.
    arr_mach_A, arr_mach_B, n_mach = _precompute_machoke(df)
    mat_ccb_A,  mat_ccb_B,  n_ccb  = _precompute_ccbhash(df)
    fA_o,  sA_o,  fB_o,  sB_o,  n_fsso  = _precompute_fss_arrays(df, "fsso")
    fA_m,  sA_m,  fB_m,  sB_m,  n_fssm  = _precompute_fss_arrays(df, "fssm")
    fA_mw, sA_mw, fB_mw, sB_mw, n_fssmw = _precompute_fss_arrays(df, "fssmw")
    mat_cat_A, mat_cat_B, n_cat = _precompute_catalog1(df)
    bA, mA, bB, mB, lA, lB, cA, cB, n_bys = _precompute_bytesig_mats(df)

    # specs: (display_label, n_valid_pairs, zero-arg timed closure)
    # Each closure performs the full comparison kernel including XOR/popcount/mask ops.
    specs = [
        ("Machoke",
            n_mach,  lambda: (arr_mach_A == arr_mach_B).astype(np.float64)),
        ("CCBHash (dist.)",
            n_ccb,   lambda: (mat_ccb_A != mat_ccb_B).mean(axis=1)),
        ("CCBHash (sim.)",
            n_ccb,   lambda: ((mat_ccb_A == mat_ccb_B) @ CCB_NO_NAME_EQUAL_NP) / 12),
        ("CCBHash (weights)",
            n_ccb,   lambda: (mat_ccb_A == mat_ccb_B) @ CCB_NO_NAME_WEIGHTS_NP),
        ("FSS (h-sim)",
            n_fsso,  lambda: _fss_hsim(fA_o,  sA_o,  fB_o,  sB_o)),
        ("FSS (h-dist)",
            n_fsso,  lambda: _fss_hdist(fA_o, sA_o,  fB_o,  sB_o)),
        ("FSS (kappa)",
            n_fsso,  lambda: _fss_kappa(fA_o, sA_o,  fB_o,  sB_o)),
        ("FSS-M (h-sim)",
            n_fssm,  lambda: _fss_hsim(fA_m,  sA_m,  fB_m,  sB_m)),
        ("FSS-M (h-dist)",
            n_fssm,  lambda: _fss_hdist(fA_m, sA_m,  fB_m,  sB_m)),
        ("FSS-M (kappa)",
            n_fssm,  lambda: _fss_kappa(fA_m, sA_m,  fB_m,  sB_m)),
        ("FSS-MW (h-sim)",
            n_fssmw, lambda: _fss_hsim(fA_mw,  sA_mw, fB_mw, sB_mw)),
        ("FSS-MW (h-dist)",
            n_fssmw, lambda: _fss_hdist(fA_mw, sA_mw, fB_mw, sB_mw)),
        ("FSS-MW (kappa)",
            n_fssmw, lambda: _fss_kappa(fA_mw, sA_mw, fB_mw, sB_mw)),
        ("ByteSig (no-check)",
            n_bys,   lambda: _bytesig_compare(bA, mA, bB, mB, lA, lB, cA, cB, False)),
        ("ByteSig (with-check)",
            n_bys,   lambda: _bytesig_compare(bA, mA, bB, mB, lA, lB, cA, cB, True)),
        ("Catalog1",
            n_cat,   lambda: ((mat_cat_A == mat_cat_B) @ CAT1_EQUAL_NP) / CAT1_NUM_PERMS),
    ]

    records = []
    for label, n_valid, time_fn in specs:
        round_times = []
        for _ in range(TIMING_ROUNDS):
            t0 = time.perf_counter()
            time_fn()
            round_times.append(time.perf_counter() - t0)
        mean_t = float(np.mean(round_times))
        records.append({
            "algorithm":     label,
            "n_pairs":       n_valid,
            "mean_time_s":   round(mean_t, 6),
            "pairs_per_sec": round(n_valid / mean_t) if mean_t > 0 else 0,
        })

    return pd.DataFrame(records)

# ---------------------------------------------------------------------------
# Generation Throughput -- full-pipeline from cached radare2 artefacts
# ---------------------------------------------------------------------------

def build_generation_throughput(bench_jsonl_path: Path) -> pd.DataFrame:
    if not bench_jsonl_path.exists():
        log.warning(f"  {bench_jsonl_path} not found. Run scripts/extract_bench_fixtures.py first.")
        return pd.DataFrame()

    records_raw: list[dict] = []
    with open(bench_jsonl_path) as fh:
        for line in fh:
            records_raw.append(json.loads(line))

    if not records_raw:
        log.warning("  bench_functions.jsonl is empty.")
        return pd.DataFrame()

    # Pre-compute which function addresses are needed per binary so we only keep
    # those entries in memory (zigs/finfo files can have 80k+ entries each).
    from collections import defaultdict
    needed_addrs: dict[tuple, set[int]] = defaultdict(set)
    for rec in records_raw:
        key = (rec["project_name"], rec["bin_name"])
        needed_addrs[key].add(int(rec["func_addr"], 16))

    # Pre-load binary-level artefacts (not timed)
    bin_cache: dict[tuple, dict] = {}
    for rec in records_raw:
        key = (rec["project_name"], rec["bin_name"])
        if key in bin_cache:
            continue
        proj_dir = DATA_LAKE / rec["project_name"]
        bin_name = rec["bin_name"]
        cg_path    = proj_dir / f"{bin_name}_cg.json"
        zigs_path  = proj_dir / f"{bin_name}_zigs.json"
        finfo_path = proj_dir / f"{bin_name}_finfo.json"
        zigs_raw = json.loads(zigs_path.read_text())  if zigs_path.exists()  else []
        finfo_raw= json.loads(finfo_path.read_text()) if finfo_path.exists() else []
        needed = needed_addrs[key]
        bin_cache[key] = {
            # Store the path, not the parsed CG: z3's CGs are 40-47 MB each and
            # expand to ~200 MB as Python objects.  Loading all 200+ z3 CGs at once
            # exceeds available RAM.  _gen_ccbhash loads on demand (OS page-cache
            # keeps it warm for subsequent timing rounds).
            "cg_path": cg_path if cg_path.exists() else None,
            "zigs":    {int(r["addr"]): r for r in zigs_raw  if "addr" in r and int(r["addr"]) in needed},
            "finfo":   {int(r["addr"]): r for r in finfo_raw if "addr" in r and int(r["addr"]) in needed},
        }
        log.info(f"  Loaded artefacts: {bin_name}  (kept {len(bin_cache[key]['zigs'])} zigs, {len(bin_cache[key]['finfo'])} finfo)")

    # Generation functions -- each returns the computed object (or None if artefacts missing)
    def _gen_catalog1_slow(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        return slow_sign(bytes.fromhex(rec["bytes_hex"]), CAT1_NUM_PERMS)

    def _gen_catalog1_numba(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        return numba_sign(bytes.fromhex(rec["bytes_hex"]), CAT1_NUM_PERMS)

    def _gen_bytesig(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        addr = int(rec["func_addr"], 16)
        zig = cache.get("zigs", {}).get(addr)
        fi  = cache.get("finfo", {}).get(addr)
        if zig is None or fi is None:
            return None
        return ByteSignature(
            raw_bytes=bytes.fromhex(zig["bytes"]),
            mask=bytes.fromhex(zig["mask"]),
            cc=fi.get("cc", 0),
        )

    def _gen_fsso(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        return fcode_to_hash(rec["cfg_record"], mode="original")

    def _gen_fssm(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        return fcode_to_hash(rec["cfg_record"], mode="marcelli")

    def _gen_fssmw(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        return fcode_to_hash(rec["cfg_record"], mode="marcelli",
                             marcelli_weights={"mnem_weight": .05, "graphlet_weight": 1., "immediate_weight": 4.})

    def _gen_machoke(rec: dict[str, Any], cache: dict[str, Any]) -> Any:
        return fcode_to_machoke_hash(rec["cfg_record"])

    # Accepts explicit cg so the timing loop can pre-load each binary's CG outside
    # the timed window.  When called without cg (pre-run eligibility check only),
    # a 1-entry closure cache avoids re-parsing the same binary for every function.
    _pre_cg_state: list = [None, []]

    def _gen_ccbhash(rec: dict[str, Any], cache: dict[str, Any],
                     cg: R2CallGraph | None = None) -> Any:
        addr = int(rec["func_addr"], 16)
        zig = cache.get("zigs", {}).get(addr)
        fi  = cache.get("finfo", {}).get(addr)
        if zig is None or fi is None:
            return None
        if cg is not None:
            resolved: R2CallGraph = cg
        else:
            p: Path | None = cache.get("cg_path")
            if p != _pre_cg_state[0]:
                _pre_cg_state[0] = p
                _pre_cg_state[1] = json.loads(p.read_text()) if p else []
            resolved = cast(R2CallGraph, _pre_cg_state[1])
        return CCBHashBuilder.build(fi, zig, rec["cfg_record"], resolved)

    # preload_key_fn: if set, the timing loop groups eligible functions by its
    # return value, pre-loads the artefact outside the timer, and passes it
    # explicitly to fn.  Use for algorithms whose per-binary artefact is too
    # large to hold all at once in memory.
    _ccb_key = lambda _r, c: c.get("cg_path")

    GEN_FNS = [
        ("Catalog1 (slow)",  _gen_catalog1_slow,  None),
        ("Catalog1 (numba)", _gen_catalog1_numba, None),
        ("ByteSig",          _gen_bytesig,        None),
        ("FSS",              _gen_fsso,           None),
        ("FSS-M",            _gen_fssm,           None),
        ("FSS-MW",           _gen_fssmw,          None),
        ("Machoke",          _gen_machoke,        None),
        ("CCBHash",          _gen_ccbhash,        _ccb_key),
    ]

    output_rows = []
    for label, fn, preload_key_fn in GEN_FNS:
        # Pre-run: identify eligible records (not timed).  Sort by preload key
        # when set so the 1-entry fallback cache in the gen function gets a hit
        # for every consecutive function from the same binary.
        if preload_key_fn is not None:
            pre_recs = sorted(
                records_raw,
                key=lambda r: str(preload_key_fn(r, bin_cache.get((r["project_name"], r["bin_name"]), {})) or ""),
            )
        else:
            pre_recs = records_raw
        eligible: list[tuple[dict, dict]] = []
        for rec in pre_recs:
            cache = bin_cache.get((rec["project_name"], rec["bin_name"]), {})
            try:
                if fn(rec, cache) is not None:
                    eligible.append((rec, cache))
            except Exception:
                pass

        if not eligible:
            log.warning(f"  {label}: no eligible functions, skipping.")
            continue

        if preload_key_fn is not None:
            # Group by binary so we load one artefact at a time.  Binary-outer
            # loop loads each artefact once across all TIMING_ROUNDS; only pure
            # computation is timed.
            _sort  = lambda t: str(preload_key_fn(t[0], t[1]) or "")
            _group = lambda t: preload_key_fn(t[0], t[1])
            eligible = sorted(eligible, key=_sort)
            cg_groups = [(k, list(g)) for k, g in groupby(eligible, key=_group)]
            group_times: list[list[float]] = [[] for _ in range(TIMING_ROUNDS)]
            for cg_path, group in cg_groups:
                cg = json.loads(cg_path.read_text()) if cg_path else []
                for round_idx in range(TIMING_ROUNDS):
                    t0 = time.perf_counter()
                    for rec, cache in group:
                        fn(rec, cache, cg)
                    group_times[round_idx].append(time.perf_counter() - t0)
            round_times: list[float] = [sum(ts) for ts in group_times]
        else:
            round_times = []
            for _ in range(TIMING_ROUNDS):
                t0 = time.perf_counter()
                for rec, cache in eligible:
                    fn(rec, cache)
                round_times.append(time.perf_counter() - t0)

        mean_time = float(np.mean(round_times))
        fps = round(len(eligible) / mean_time) if mean_time > 0 else 0
        output_rows.append({
            "algorithm":         label,
            "n_functions":       len(eligible),
            "mean_time_s":       round(mean_time, 4),
            "functions_per_sec": fps,
        })
        log.info(f"  {label}: {fps:,} fn/s  (n={len(eligible)}, mean_time={mean_time:.3f}s)")

    return pd.DataFrame(output_rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _ensure_fixtures() -> None:
    """Auto-generate any missing fixture files before the main benchmark runs."""
    if not BENCH_JSONL.exists():
        log.info(f"[auto] {BENCH_JSONL.name} missing -- running extract_bench_fixtures...")
        from evaluation.steps._fixtures.extract_bench_fixtures import main as _ext_bench
        _ext_bench()


if __name__ == "__main__":
    _ensure_fixtures()

    engine = get_engine()
    SessionLocal = make_session_factory(engine)

    # Using XA to calculate fingerprints comparison throughput anything would
    # have worked for this test; the fingerprints themselves don't matter
    xa_path = SCORED_DIR / "scored_positive_XA.csv"
    if not xa_path.exists():
        log.error("XA scored file missing. Run step 02 first.")
        sys.exit(1)

    out_ctp  = THROUGHPUT_DIR / "comparison_throughput.csv"
    out_gen  = THROUGHPUT_DIR / "generation_throughput.csv"
    out_opt   = THROUGHPUT_DIR / "optimisation_sensitivity.csv"
    out_comp   = THROUGHPUT_DIR / "compilation_sensitivity.csv"

    need_ctp = not out_ctp.exists()
    if need_ctp:
        xa_ids = pd.read_csv(xa_path, usecols=["function_id_A", "function_id_B"])
        log.info(f"Loaded XA (ID columns): {len(xa_ids):,} pairs")
        with SessionLocal() as session:
            if need_ctp:
                log.info("=== Comparison Throughput ===")
                df_tp = build_comparison_throughput(session, xa_ids)
                df_tp.to_csv(out_ctp, index=False)
                log.info(f"Saved -> {out_ctp}")
                log.info(df_tp.to_string(index=False))
            else:
                log.info(f"[SKIP] {out_ctp.name} already exists.")
        del xa_ids
    else:
        log.info(f"[SKIP] {out_ctp.name} already exist.")

    if not out_gen.exists():
        log.info("=== Generation Throughput ===")
        df_gen = build_generation_throughput(BENCH_JSONL)
        if not df_gen.empty:
            df_gen.to_csv(out_gen, index=False)
            log.info(f"Saved -> {out_gen}")
            log.info(df_gen.to_string(index=False))
    else:
        log.info(f"[SKIP] {out_gen.name} already exists.")

    log.info("Done. Run evaluation/reporting/gen_frash_outputs.py to regenerate plots and tables.")
