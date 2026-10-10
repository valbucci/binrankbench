"""
ingest.py — single-binary ingest pipeline for the storage layer.

Ties together the existing generate-pipeline data-loading infrastructure
(``BinaryDataPaths``, ``BinaryFunctionsDataManager``, Task classes) with the
new ``DBWriter`` so that one call per binary can drive the full flow:
1. JSON/tar data
2. Task.run()
3. DBWriter
4. PostgreSQL / SQLite

Usage
-----

    from pathlib import Path
    from binrankbench.storage.session import get_engine, get_session, init_db
    from binrankbench.storage.ingest import ingest_binary

    engine = get_engine("sqlite:///test.db")
    init_db(engine)

    with get_session(engine) as sess:
        binary = ingest_binary(
            session=sess,
            project="git",
            bin_name="git_2-47-1.exe",
            raw_data_dir=Path("tests/test_data/bin2ml"),
            datasets=["sample_dataset"],
        )

Design notes
------------
* Runs entirely **in-process** (no multiprocessing) — suitable for small/test
  datasets.  The existing ``__main__.py`` multiprocess pipeline is unchanged.
* Missing data types are silently skipped by ``BinaryDataPaths.__post_init__``
  (sets the field to ``None`` when files are absent).
* The ``bytes`` warning from ``BinaryDataPaths`` fires when *neither* the
  ``bytes`` nor ``bytes_masked`` tar files can be found.  Always pass the
  paths -- the dataclass validates existence itself.
* FSS is also skipped gracefully when ``functionsimsearch`` is not installed.
* Each call commits exactly once at the end of the binary (not per function).
"""
from __future__ import annotations

import json
import logging
import multiprocessing
import queue
import re
import signal
import time
from collections.abc import Collection
from pathlib import Path
from typing import Any, Optional
from queue import Empty

from sqlalchemy import select
from sqlalchemy.orm import Session

try:
    from tqdm import tqdm as _tqdm
except ImportError:
    _tqdm = None  # type: ignore


class _TqdmLoggingHandler(logging.StreamHandler):
    """Route log records through tqdm.write() so they don't corrupt progress bars."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            if _tqdm is not None:
                _tqdm.write(msg)
            else:
                print(msg)
            self.flush()
        except Exception:
            self.handleError(record)

from binrankbench.common.hex import hexvalue_to_bytes
from binrankbench.storage.models import (
    Binary,
    BinaryDatasetTag,
    Dataset,
    Function,
)
from binrankbench.storage.models.core import StrategyMembership, FunctionScalars
from binrankbench.storage.models.signatures.strategy_type import StrategyID
from .writer import DBWriter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Strategy → StrategyID mapping (ingest strategy name strings → DB enum)
# ---------------------------------------------------------------------------
# "fss" covers both fss_original and fss_marcelli (same data file).
_STRATEGY_IDS: dict[str, list[StrategyID]] = {
    "catalog1":  [StrategyID.catalog1],
    "ccbhash":   [StrategyID.ccbhash],
    "machoke":   [StrategyID.machoke],
    "fss":       [StrategyID.fss_original, StrategyID.fss_marcelli, StrategyID.fss_marcelli_weighted],
    "bytes":     [StrategyID.bytes_signature],
}


def _get_done_strategies(
    session: Session,
    binary_id: int,
    strategies: Collection[str],
    *,
    overwrite: bool = False,
) -> dict[str, set[str]]:
    """Return a mapping of strategy_name → set of func_addr hex strings already
    written for *binary_id*.

    Executes at most ``len(strategies)`` SELECT queries total — one per
    strategy group — regardless of how many functions the binary has.
    Returns empty sets for all strategies when *overwrite* is True.
    """
    if overwrite:
        return {s: set() for s in strategies}

    done: dict[str, set[str]] = {}
    for strat in strategies:
        if strat == "function_details":
            # An execution is "done" if the FunctionScalars row exists. 
            # We don't require all fields to be non-null, as fields like bbsum/nargs can legitimately be NULL.
            rows = session.execute(
                select(Function.func_addr)
                .join(FunctionScalars, FunctionScalars.function_id == Function.id)
                .where(
                    Function.binary_id == binary_id
                )
            ).scalars().all()
            done[strat] = set(rows)
            continue
            
        sids = _STRATEGY_IDS.get(strat, [])
        if not sids:
            done[strat] = set()
            continue
        # Collect func_addrs that have ALL sub-strategy_ids written.
        # For most strategies len(sids)==1; for fss it's 3 (original+marcelli+marcelli_weighted).
        # We take the intersection: an address is "done" only if every
        # sub-strategy is present.
        addr_sets: list[set[str]] = []
        for sid in sids:
            rows = session.execute(
                select(Function.func_addr)
                .join(StrategyMembership,
                      StrategyMembership.function_id == Function.id)
                .where(
                    Function.binary_id == binary_id,
                    StrategyMembership.strategy_id == int(sid),
                )
            ).scalars().all()
            addr_sets.append(set(rows))
            done[sid.name] = set(rows)
        done[strat] = addr_sets[0].intersection(*addr_sets[1:]) if addr_sets else set()
    return done


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def clean_function_name(name: str | None) -> str | None:
    if not name:
        return None
    # Radare2 auto-generates names like 'fcn.00000000' or 'sym.func.00000000'
    # Ghidra / IDA typically use 'sub_00000000'
    if re.match(r"^(fcn\.|sub_|sym\.func\.)[0-9a-fA-F]+$", name):
        return None
    return name

def ingest_binary(
    *,
    session: Session,
    project: str,
    bin_name: str,
    raw_data_dir: Path,
    datasets: Collection[str] = (),
    strategies: Collection[str] = ("ccbhash", "machoke"),
    overwrite: bool = False,
) -> Binary:
    """Ingest one binary's hash data into the DB.

    Parameters
    ----------
    session:
        An active SQLAlchemy session (should be inside a ``get_session``
        context manager so the caller controls the transaction boundary).
    project:
        Human-readable project / benchmark name, e.g. ``"git"``.
    bin_name:
        Canonical binary name, e.g. ``"git_2-47-1.exe"``.  Must match the
        stem prefix used by the data files (e.g. ``git_2-47-1.exe_cfg.json``).
    raw_data_dir:
        Directory that contains the data files for this binary.  Files are
        discovered by the standard ``BinaryDataPaths`` conventions.
    datasets:
        Optional sequence of dataset / experiment tag names.  Each name will
        be created if it does not exist, and then linked to the binary via
        ``BinaryDatasetTag``.  Pass an empty iterable for no tagging.
    strategies:
        Hash strategies to run.  Defaults to the strategies that work without
        byte-level data (``ccbhash``, ``machoke``).  Add ``"catalog1"`` /
        ``"bytes"`` only when the corresponding ``.tar`` files are present.
    overwrite:
        Not yet implemented; reserved for future idempotent re-processing.

    Returns
    -------
    Binary
        The (created or retrieved) ORM ``Binary`` row.
    """
    # ------------------------------------------------------------------
    # Lazy imports — avoid hard-failing if optional deps are missing
    # ------------------------------------------------------------------
    try:
        from binrankbench.modules.generate.data import (
            BinaryDataPaths,
            BinaryFunctionsDataManager,
            BytesDataPaths,
        )
        from binrankbench.modules.generate.tasks import (
            BytesTask,
            Catalog1Task,
            CCBHashTask,
            MachokeTask,
            FunctionSimSearchTask,
            FunctionDetailsTask,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Could not import generate-pipeline modules. "
            "Make sure the full binrankbench package is installed."
        ) from exc

    raw_data_dir = Path(raw_data_dir)

    # ------------------------------------------------------------------
    # 1. Parse bininfo.json for binary-level metadata (optional)
    # ------------------------------------------------------------------
    bininfo = _load_bininfo(raw_data_dir, bin_name)
    arch    = bininfo.get("arch")
    bits    = bininfo.get("bits")
    cc      = bininfo.get("cc")
    sha256  = bininfo.get("sha256")

    # ------------------------------------------------------------------
    # 2. Build data paths (BinaryDataPaths detects what files exist)
    # ------------------------------------------------------------------
    stem = bin_name          # e.g. "git_2-47-1.exe"
    cfg_path       = raw_data_dir / f"{stem}_cfg.json"
    func_cfg_dir   = raw_data_dir / f"{stem}_func-cfg"
    func_cfg_jsonl = raw_data_dir / f"{stem}_func-cfg.jsonl"
    zigs_path      = raw_data_dir / f"{stem}_zigs.json"
    finfo_path     = raw_data_dir / f"{stem}_finfo.json"
    cg_path        = raw_data_dir / f"{stem}_cg.json"

    # bytes: tar archive + index CSV.
    # The index may live in several places depending on how the data was generated.
    # Probe in priority order and fall back to the subdirectory convention so
    # TarDataStreamer can search inside the tar as a last resort.
    def _find_index(tar_path: Path, stem_name: str, kind: str) -> Path:
        """Return the first existing index path, or the subdir-convention path."""
        candidates = [
            # Flat alongside the tar: {stem}_{kind}_func-index.csv
            tar_path.parent / f"{stem_name}_{kind}_func-index.csv",
            # Flat alongside the tar: 00-func-index_{kind}.csv
            tar_path.parent / f"00-func-index_{kind}.csv",
            # Inside extracted subdirectory
            tar_path.parent / f"{stem_name}_{kind}" / f"00-func-index_{kind}.csv",
        ]
        for p in candidates:
            if p.is_file():
                return p
        # Return the subdir convention so TarDataStreamer can try inside the tar
        return candidates[-1]

    bytes_tar         = raw_data_dir / f"{stem}_bytes.tar"
    bytes_masked_tar  = raw_data_dir / f"{stem}_bytes-masked.tar"
    bytes_index        = _find_index(bytes_tar,        stem, "bytes")
    bytes_masked_index = _find_index(bytes_masked_tar, stem, "bytes-masked")

    # func_cfg may be a directory (one JSON per function) or a single .jsonl
    func_cfg_path: Path | None = None
    if func_cfg_dir.is_dir():
        func_cfg_path = func_cfg_dir
    elif func_cfg_jsonl.is_file():
        func_cfg_path = func_cfg_jsonl

    data_paths = BinaryDataPaths(
        cfg      = cfg_path   if cfg_path.is_file()   else None,
        func_cfg = func_cfg_path,
        zigs     = zigs_path  if zigs_path.is_file()  else None,
        finfo    = finfo_path if finfo_path.is_file() else None,
        cg       = cg_path    if cg_path.is_file()    else None,
        # Always pass bytes paths; BinaryDataPaths checks existence itself
        bytes         = BytesDataPaths(
            data_path  = bytes_tar,
            index_path = bytes_index,
        ),
        bytes_masked  = BytesDataPaths(
            data_path  = bytes_masked_tar,
            index_path = bytes_masked_index,
        ),
    )

    # ------------------------------------------------------------------
    # 3. Load all function data in memory
    # ------------------------------------------------------------------
    # Use a synthetic Path for binary_path (file need not exist on disk)
    binary_path = raw_data_dir / bin_name
    manager = BinaryFunctionsDataManager(
        binary_path=binary_path,
        data_paths=data_paths,
        callgraph_path=cg_path,
    )
    manager.setup()

    callgraph = manager.get_callgraph()

    # ------------------------------------------------------------------
    # 3b. Warn upfront about missing data required by requested strategies
    # ------------------------------------------------------------------
    _STRATEGY_NEEDS = {
        "ccbhash":  ["cfg/func-cfg", "finfo", "zigs", "cg"],
        "machoke":  ["cfg/func-cfg"],
        "fss":      ["cfg/func-cfg"],
        "catalog1": ["bytes or bytes-masked"],
        "bytes":    ["zigs"],  # This is the byte signature which we only get from the zigs file
        "function_details": ["finfo", "zigs"],
    }
    _have_cfg  = data_paths.cfg is not None or data_paths.func_cfg is not None
    _have_finfo = data_paths.finfo is not None
    _have_zigs  = data_paths.zigs  is not None
    _have_cg    = data_paths.cg    is not None
    _have_bytes = data_paths.bytes is not None or data_paths.bytes_masked is not None

    _data_ok = {
        "cfg/func-cfg":       _have_cfg,
        "finfo":              _have_finfo,
        "zigs":               _have_zigs,
        "cg":                 _have_cg,
        "bytes or bytes-masked": _have_bytes,
    }

    for strat in strategies:
        missing = [
            need for need in _STRATEGY_NEEDS.get(strat, [])
            if not _data_ok.get(need, True)
        ]
        if missing:
            logger.warning(
                "[%s/%s] Strategy '%s' will be SKIPPED — missing data: %s",
                project, bin_name, strat, ", ".join(missing),
            )

    # ------------------------------------------------------------------
    # 4. Create / retrieve DB entity and apply dataset tags
    # ------------------------------------------------------------------
    writer = DBWriter(session)

    binary = writer.get_or_create_binary(
        project, bin_name,
        arch=arch, bits=bits, cc=cc, sha256=sha256,
    )

    for ds_name in datasets:
        ds = writer.get_or_create_dataset(ds_name)
        writer.tag_binary(binary, ds)

    # ------------------------------------------------------------------
    # 4b. Check which strategies are already complete for this binary
    # ------------------------------------------------------------------
    # One SELECT per strategy — result is a set of func_addr strings already
    # written. Used both to skip entire strategies (binary level) and to skip
    # individual functions (per-function level) when a run was partial.
    done_by_strat = _get_done_strategies(
        session, binary.id, strategies, overwrite=overwrite
    )

    # Strategies where every DB function already has the entry; skip loading
    # the data file at all. We consider a strategy "complete" at binary level
    # when the done set is non-empty AND equals the full set of functions in DB.
    # (New binary = 0 functions in DB -> done set is empty -> load everything.)
    #
    # We get the full function count lazily: only if at least one strat has a
    # non-empty done set, to avoid an extra COUNT(*) when everything is fresh.
    _total_funcs_in_db: int | None = None

    def _total_funcs() -> int:
        nonlocal _total_funcs_in_db
        if _total_funcs_in_db is None:
            from sqlalchemy import func as safunc
            _total_funcs_in_db = session.execute(
                select(safunc.count()).select_from(Function)
                .where(Function.binary_id == binary.id)
            ).scalar_one()
        return _total_funcs_in_db

    def clean_function_name(name: str | None) -> str | None:
        if not name:
            return None
        if re.match(r"^(fcn\.|sub_|sym\.func\.)[0-9a-fA-F]+$", name):
            return None
        return name

    fully_done: set[str] = set()
    for strat, done_addrs in done_by_strat.items():
        if done_addrs and len(done_addrs) >= _total_funcs():
            fully_done.add(strat)
            logger.info(
                "[%s/%s] Strategy '%s' already complete (%d functions) — skipping",
                project, bin_name, strat, len(done_addrs),
            )

    effective_strategies = [s for s in strategies if s not in fully_done]
    if not effective_strategies:
        logger.info(
            "[%s/%s] All strategies already complete — nothing to do.",
            project, bin_name,
        )
        return binary

    if fully_done:
        logger.info(
            "[%s/%s] Skipping complete strategies: %s",
            project, bin_name, ", ".join(sorted(fully_done)),
        )

    # ------------------------------------------------------------------
    # 5. Iterate functions and run requested tasks
    # ------------------------------------------------------------------
    n_ok = n_skip = n_err = 0
    all_func_data = list(manager.iterate_functions_data(
        sort_by_address=True, include_callgraph=("ccbhash" in effective_strategies)
    ))
    n_funcs = len(all_func_data)

    if _tqdm is not None:
        _iter = _tqdm(
            all_func_data,
            desc=bin_name,
            unit="fn",
            dynamic_ncols=True,
            leave=False,
            position=1,
        )
    else:
        _iter = all_func_data

    results_batch: list[tuple[Function, Any]] = []
    for (func_addr, func_name, func_cfg, func_zignature,
         func_finfo, cfg_raw_str, zignature_raw_str, finfo_raw_str,
         callgraph, _fbytes_raw, _fbytes_bitmask) in _iter:

        func_addr_hex = hex(func_addr)

        func_row = writer.get_or_create_function(
            project, bin_name, func_addr_hex,
            func_name=clean_function_name(func_name)
        )

        # ------  CCBHash  ------
        if ("ccbhash" in effective_strategies
                and func_addr_hex not in done_by_strat.get("ccbhash", set())):
            task = CCBHashTask(
                func_addr=func_addr,
                preloaded_func_info=func_finfo,
                preloaded_func_zignature=func_zignature,
                preloaded_func_code=func_cfg,
                func_callgraph=callgraph,
            )
            result = task.run()
            if result.success and result.ccbhash_features is not None:
                results_batch.append((func_row, result))
                n_ok += 1
            else:
                n_skip += 1

        # ------  Machoke  ------
        if ("machoke" in effective_strategies
                and func_addr_hex not in done_by_strat.get("machoke", set())):
            mtask = MachokeTask(func_addr=func_addr, preloaded_func_code=func_cfg)
            mresult = mtask.run()
            if mresult.success and mresult.machoke_digest is not None:
                results_batch.append((func_row, mresult))
                n_ok += 1
            else:
                n_skip += 1

        # ------  FSS Variants ------
        if ("fss" in effective_strategies
                and func_addr_hex not in done_by_strat.get("fss", set())):
            compute_original = func_addr_hex not in done_by_strat.get(StrategyID.fss_original.name, set())
            compute_marcelli = func_addr_hex not in done_by_strat.get(StrategyID.fss_marcelli.name, set())
            compute_marcelli_weighted = func_addr_hex not in done_by_strat.get(StrategyID.fss_marcelli_weighted.name, set())
            
            ftask = FunctionSimSearchTask(
                func_addr=func_addr, 
                preloaded_func_code=func_cfg,
                compute_original=compute_original,
                compute_marcelli=compute_marcelli,
                compute_marcelli_weighted=compute_marcelli_weighted
            )
            fresult = ftask.run()
            if fresult.success:
                results_batch.append((func_row, fresult))
                n_ok += 1
            else:
                n_skip += 1

        # ------  Catalog1  ------
        if ("catalog1" in effective_strategies
                and func_addr_hex not in done_by_strat.get("catalog1", set())):
            ctask = Catalog1Task(
                func_addr=func_addr,
                func_bytes=_fbytes_raw,
                preloaded_func_zignature=func_zignature,
                bit_masked_func_bytes=_fbytes_bitmask,
                preloaded_func_info=func_finfo
            )
            cresult = ctask.run()
            if cresult.success and cresult.catalog1 is not None:
                results_batch.append((func_row, cresult))
                n_ok += 1
            else:
                n_skip += 1

        # ------  Byte Signatures  ------
        if ("bytes" in effective_strategies
                and func_addr_hex not in done_by_strat.get("bytes", set())):
            btask = BytesTask(
                func_addr=func_addr,
                func_bytes=_fbytes_raw,
                preloaded_func_zignature=func_zignature,
                bit_masked_func_bytes=_fbytes_bitmask,
                preloaded_func_info=func_finfo
            )
            bresult = btask.run()
            if bresult.success:
                results_batch.append((func_row, bresult))
                n_ok += 1
            else:
                n_skip += 1
                    
        # ------  Function Details (Scalars) ------
        if ("function_details" in effective_strategies
                and func_addr_hex not in done_by_strat.get("function_details", set())):
            if func_finfo or func_zignature:
                dtask = FunctionDetailsTask(
                    func_addr=func_addr,
                    preloaded_func_zignature=func_zignature,
                    preloaded_func_info=func_finfo,
                )
                dresult = dtask.run()
                if dresult.success:
                    results_batch.append((func_row, dresult))
                    n_ok += 1
                else:
                    n_skip += 1
            else:
                n_skip += 1

        # Flush in reasonably sized chunks to avoid excessive memory usage in ingest_binary
        if len(results_batch) >= 100:
            writer.write_batch(results_batch)
            results_batch = []

    # Final flush
    if results_batch:
        writer.write_batch(results_batch)

    logger.info(
        "ingest_binary(%s/%s): %d functions, %d signatures written, %d skipped, %d errors",
        project, bin_name, n_funcs, n_ok, n_skip, n_err,
    )

    session.commit()
    return binary


def ingest_directory(
    *,
    session: Session,
    project: str,
    raw_data_dir: Path,
    datasets: Collection[str] = (),
    strategies: Collection[str] = ("ccbhash", "machoke"),
    overwrite: bool = False,
) -> list[Binary]:
    """Ingest all binaries found in a directory.

    Discovers unique binaries by looking for *_finfo.json or other data files
    and calls `ingest_binary` for each one.
    """
    raw_data_dir = Path(raw_data_dir)
    
    bin_names = set()
    for p in raw_data_dir.iterdir():
        if not p.is_file() and not p.is_dir():
            continue
            
        name = p.name
        # Common suffixes that identify a binary's data
        for suffix in (
            "_cfg.json", "_func-cfg.jsonl", "_finfo.json", 
            "_zigs.json", "_cg.json", "_bininfo.json", 
            "_bytes.tar", "_bytes-masked.tar"
        ):
            if name.endswith(suffix):
                bin_names.add(name[:-len(suffix)])
                break
                
        # Handle func-cfg directory
        if p.is_dir() and name.endswith("_func-cfg"):
            bin_names.add(name[:-len("_func-cfg")])
            
        # Handle bytes directories
        for pfix in ("_bytes", "_bytes-masked"):
            if p.is_dir() and name.endswith(pfix):
                bin_names.add(name[:-len(pfix)])
                
    sorted_bins = sorted(bin_names)
    binaries = []

    # Install tqdm-aware logging for the duration of the directory ingest so
    # log messages don't tear the progress bars apart.
    _root_logger = logging.getLogger("binrankbench")
    _original_handlers = [
        h for h in _root_logger.handlers
        if not isinstance(h, logging.NullHandler)
    ]
    if _tqdm is not None and _original_handlers:
        _tqdm_handler = _TqdmLoggingHandler()
        _tqdm_handler.setFormatter(_original_handlers[0].formatter)
        _root_logger.handlers = [_tqdm_handler]

    try:
        if _tqdm is not None:
            _bin_iter = _tqdm(
                sorted_bins,
                desc="binaries",
                unit="bin",
                dynamic_ncols=True,
                leave=True,
                position=0,
            )
        else:
            _bin_iter = sorted_bins

        for bin_name in _bin_iter:
            if _tqdm is not None:
                _bin_iter.set_postfix_str(bin_name, refresh=True)  # type: ignore[union-attr]
            logger.info("Discovering %s for ingestion in %s", bin_name, raw_data_dir)
            binary = ingest_binary(
                session=session,
                project=project,
                bin_name=bin_name,
                raw_data_dir=raw_data_dir,
                datasets=datasets,
                strategies=strategies,
                overwrite=overwrite,
            )
            binaries.append(binary)
    finally:
        # Restore original logging handlers
        if _tqdm is not None and _original_handlers:
            _root_logger.handlers = _original_handlers

    logger.info("ingest_directory(%s): successfully processed %d binaries.", project, len(binaries))
    return binaries



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_bininfo(raw_data_dir: Path, bin_name: str) -> dict[str, Any]:
    """Parse ``<bin_name>_bininfo.json`` and extract useful fields.

    Returns an empty dict if the file is missing or malformed.
    The recognised keys are: arch, bits, cc, sha256.
    """
    bininfo_path = raw_data_dir / f"{bin_name}_bininfo.json"
    if not bininfo_path.is_file():
        logger.debug("bininfo.json not found at %s", bininfo_path)
        return {}

    try:
        raw = json.loads(bininfo_path.read_text())
    except Exception as exc:
        logger.warning("Could not parse %s: %s", bininfo_path, exc)
        return {}

    result: dict[str, Any] = {}
    bin_section = raw.get("bin", {})

    for key in ("arch", "bits", "cc"):
        val = bin_section.get(key)
        if val is not None:
            result[key] = val

    checksums = raw.get("checksums", {})
    sha256 = checksums.get("sha256")
    if sha256:
        result["sha256"] = sha256

    return result
