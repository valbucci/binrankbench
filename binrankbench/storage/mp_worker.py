"""IngestTaskPoster and DBResultCollector worker processes for the multiprocess ingestion pipeline."""

import logging
import time
import collections
from pathlib import Path
from multiprocessing import Queue
from queue import Empty, Full
import re
import json
from typing import Optional

from binrankbench.modules.generate.worker import QueueManager
from binrankbench.modules.generate.logging import setup_worker_logging, binary_log_context, get_logger
from binrankbench.modules.generate.data import BinaryFunctionsDataManager, BinaryDataPaths, BytesDataPaths
from binrankbench.modules.generate.tasks import TaskWrapper, CCBHashTask, MachokeTask, FunctionSimSearchTask, Catalog1Task, BytesTask, FunctionDetailsTask, get_task_priority
from binrankbench.modules.generate.result import SkipInfo
from binrankbench.modules.generate.stats import (
    SharedStats,
    WORKER_STATE_STOPPED,
    WORKER_STATE_IDLE,
    WORKER_STATE_WORKING
)

from binrankbench.common.hex import hexvalue_to_bytes
from binrankbench.storage.session import get_engine, get_session
from binrankbench.storage.writer import DBWriter
from binrankbench.storage.ingest import _load_bininfo, _get_done_strategies, clean_function_name
from binrankbench.storage.models import Function, SkipLog
from sqlalchemy import select as _sa_select

logger = get_logger("mp_worker")

def count_lines_regex(path: Path) -> int:
    """Rapidly count valid function entries in a jsonl file."""
    count = 0
    if not path.is_file():
        return 0
    # Look for "offset" or "addr" and "type":"fcn" without closing brackets in between
    # This specifically targets the line-by-line function entries in the jsonl
    addr_pattern = re.compile(r'"(offset|addr)"\s*:\s*\d+')
    type_pattern = re.compile(r'"type"\s*:\s*("(fcn|sym)"|null)')
    try:
        with open(path, 'r') as f:
            for line in f:
                if addr_pattern.search(line) and ("\"type\"" not in line or type_pattern.search(line)):
                    count += 1
    except Exception:
        return 0
    return count

def clean_function_name(name: str | None) -> str | None:
    if not name:
        return None
    
    # Radare2 auto-generates names like 'fcn.00000000' or 'sym.func.00000000'
    # Ghidra / IDA typically use 'sub_00000000'
    if re.match(r"^(fcn\.|sub_|sym\.func\.)[0-9a-fA-F]+$", name):
        return None
        
    return name

class DBResultCollector:
    def __init__(self, queue_manager: QueueManager, project: str, shared_stats: Optional[SharedStats] = None):
        self.queue_manager = queue_manager
        self.project = project
        self.shared_stats = shared_stats
        self.batch_size = 10_000  # Size of batch before committing
    
    @property
    def logger(self) -> logging.Logger:
        return get_logger("DBResultCollector")

    def run(self) -> dict:
        self.logger.info("DBResultCollector started")
        
        engine = get_engine()
        
        running = True
        batch_count = 0
        total_written = 0
        total_errors = 0
        
        _result_buffer = []  # List of ResultWrappers
        _skip_buffer: list[SkipInfo] = []  # List of SkipInfo objects
        _stats_counter = collections.Counter()
        _flushes_count = 0

        def flush_buffers():
            nonlocal _result_buffer, _skip_buffer, _flushes_count, _stats_counter
            if _skip_buffer:
                try:
                    writer.bulk_write_skips(_skip_buffer, self.project)
                    self.logger.debug(f"Flushed skip buffer ({len(_skip_buffer)} skips)")
                except Exception as e:
                    self.logger.exception(f"Failed to flush skip buffer: {e}")
                finally:
                    _skip_buffer = []
            if _result_buffer:
                try:
                    # 1. Extract definitions
                    defs = []
                    for wrapper in _result_buffer:
                        res = wrapper.result
                        bin_name = getattr(wrapper, "binary_name", "unknown")
                        raw_name = getattr(wrapper, "func_name", None) or getattr(res, "func_name", None) or getattr(res, "name", None)
                        defs.append({
                            "bin_name": bin_name,
                            "func_addr": hex(res.func_addr),
                            "func_name": clean_function_name(raw_name)
                        })
                    
                    # 2. Bulk resolve Functions
                    func_map = writer.bulk_get_or_create_functions(self.project, defs)
                    
                    # 3. Zip actual Functions and Results
                    batch = []
                    for wrapper, d in zip(_result_buffer, defs):
                        f = func_map.get((d["bin_name"], d["func_addr"]))
                        if f:
                            batch.append((f, wrapper.result))
                            
                    # 4. Write
                    if batch:
                        writer.write_batch(batch)
                        
                        # Track stats for the breakdown log
                        from binrankbench.modules.generate.result import (
                            CCBHashResult, MachokeResult,
                            FunctionSimSearchResult, Catalog1Result,
                            BytesResult, FunctionDetailsResult
                        )
                        for _, res in batch:
                            if isinstance(res, CCBHashResult): _stats_counter["ccbhash"] += 1
                            elif isinstance(res, Catalog1Result): _stats_counter["catalog1"] += 1
                            elif isinstance(res, FunctionSimSearchResult):
                                if getattr(res, "fss_plain", None): _stats_counter["fss_original"] += 1
                                if getattr(res, "mss_plain", None): _stats_counter["fss_marcelli"] += 1
                                if getattr(res, "mss_weighted", None): _stats_counter["fss_marcelli_weighted"] += 1
                            elif isinstance(res, MachokeResult): _stats_counter["machoke"] += 1
                            elif isinstance(res, BytesResult): _stats_counter["bytes"] += 1
                            elif isinstance(res, FunctionDetailsResult): _stats_counter["scalars"] += 1

                    _flushes_count += 1
                    if _flushes_count % 5 == 0:
                        stats_str = ", ".join([f"{k}: {v}" for k, v in _stats_counter.items()])
                        self.logger.info(f"Cumulative Ingestion Breakdown: {stats_str}")

                    self.logger.debug(f"Flushed generic result buffer ({len(batch)} results)")
                    _result_buffer = []
                except Exception as e:
                    self.logger.exception(f"Failed to flush result buffer: {e}")
                    _result_buffer = []

        try:
            if self.shared_stats:
                self.shared_stats.set_collector_state(WORKER_STATE_IDLE)
            
            with get_session(engine) as session:
                writer = DBWriter(session)
                while running:
                    if self.queue_manager.collector_shutdown.is_set() and self.queue_manager.result_queue.empty():
                        running = False
                        flush_buffers()
                        continue
                    
                    try:
                        result_payload = self.queue_manager.result_queue.get(timeout=1.0)
                    except Empty:
                        if self.shared_stats:
                            self.shared_stats.set_collector_state(WORKER_STATE_IDLE)
                        if batch_count > 0:
                            flush_buffers()
                            session.commit()
                            self.logger.debug(f"Committed batch of {batch_count} records (timeout)")
                            batch_count = 0
                        continue
                    
                    if self.shared_stats:
                        self.shared_stats.set_collector_state(WORKER_STATE_WORKING)
                    
                    if not isinstance(result_payload, list):
                        result_batch = [result_payload]
                    else:
                        result_batch = result_payload
                        
                    for result_wrapper in result_batch:
                        if self.queue_manager.all_runners_shutdown.is_set():
                            self.logger.debug("Hard shutdown requested; breaking batch early.")
                            running = False
                            break

                        if isinstance(result_wrapper, SkipInfo):
                            bin_name = getattr(result_wrapper, "binary_name", "unknown")
                            if self.shared_stats:
                                self.shared_stats.increment_binary_done(bin_name)
                            _skip_buffer.append(result_wrapper)
                            
                            # Also check for flush here since skips can dominate
                            if len(_skip_buffer) >= self.batch_size:
                                flush_buffers()
                                session.commit()
                                # NOTE: batch_count refers to results, so it stays at its current value
                            continue

                        bin_name = getattr(result_wrapper, "binary_name", "unknown")

                        if not result_wrapper.result.success:
                            error_str = str(getattr(result_wrapper.result, 'error', ''))
                            task_type = result_wrapper.result.__class__.__name__.replace("Result", "").lower()

                            # Log failure as a skip in the DB
                            clean_err = error_str.replace('\n', ' ')
                            _skip_buffer.append(SkipInfo(
                                func_addr=result_wrapper.result.func_addr,
                                task_type=task_type,
                                reason=clean_err[:500],  # cap length
                                binary_name=bin_name,
                            ))
                            if self.shared_stats:
                                self.shared_stats.increment_binary_done(bin_name)

                            total_errors += 1
                            if total_errors <= 100:
                                self.logger.error(f"Task failed ({bin_name} @ {hex(result_wrapper.result.func_addr)}): {error_str}")
                                if self.shared_stats:
                                    self.shared_stats.increment_result_errors()

                            continue

                        _result_buffer.append(result_wrapper)
                        batch_count += 1
                        total_written += 1
                        if self.shared_stats:
                            self.shared_stats.increment_results_written()
                            self.shared_stats.increment_binary_done(bin_name)
                        
                        # Flush if either buffer gets too large, or if total processed items (results + skips)
                        # exceeds a reasonable batch size.
                        if batch_count >= self.batch_size or len(_result_buffer) + len(_skip_buffer) >= self.batch_size:
                            self.logger.debug(f"Committing batch (results={len(_result_buffer)}, skips={len(_skip_buffer)})")
                            flush_buffers()
                            session.commit()
                            batch_count = 0
                
                # Final flush for any remaining data in the buffers
                if len(_result_buffer) > 0 or len(_skip_buffer) > 0:
                    self.logger.debug(f"Committing final batch (results={len(_result_buffer)}, skips={len(_skip_buffer)})")
                    flush_buffers()
                    session.commit()

        except Exception as e:
            self.logger.exception("Fatal error in DBResultCollector")
        finally:
            engine.dispose()
            if self.shared_stats:
                self.shared_stats.set_collector_state(WORKER_STATE_STOPPED)
            self.logger.info(f"DBResultCollector finished: written={total_written}, errors={total_errors}")

        return {"written": total_written, "errors": total_errors}

def run_db_result_collector(queue_manager: QueueManager, log_queue: Queue, project: str, shared_stats: Optional[SharedStats] = None) -> dict:
    setup_worker_logging(log_queue)
    collector = DBResultCollector(queue_manager, project, shared_stats)
    return collector.run()

class IngestTaskPoster:
    def __init__(self, binary_path: Path, raw_data_dir: Path, output_dir: Path, queue_manager: QueueManager, poster_id: int, project: str, strategies: list[str], datasets: list[str], overwrite: bool, shared_stats: Optional[SharedStats] = None):
        self.binary_path = binary_path
        self.raw_data_dir = raw_data_dir
        self.output_dir = output_dir
        self.queue_manager = queue_manager
        self.poster_id = poster_id
        self.project = project
        self.strategies = strategies
        self.datasets = datasets
        self.overwrite = overwrite
        self.shared_stats = shared_stats
        self._logger = logging.LoggerAdapter(get_logger("IngestTaskPoster"), extra={'binary_name': self.binary_path.name})
        self.skipped_tasks_cache: dict[str, set[int]] = {}  # Populated during setup() via a DB query

    @property
    def logger(self):
        return self._logger

    @property
    def binary_name(self):
        return self.binary_path.name

    def _is_bytes_strategy_complete(self, strat: str) -> bool:
        if strat not in self.done_by_strat:
            return False
            
        index_path = None
        if self.data_paths.bytes_masked and self.data_paths.bytes_masked.ok:
            index_path = self.data_paths.bytes_masked.index_path
        elif self.data_paths.bytes and self.data_paths.bytes.ok:
            index_path = self.data_paths.bytes.index_path
            
        if not index_path or not index_path.is_file():
            return False
            
        try:
            with open(index_path, 'rb') as f:
                # Approximate line count (subtract 1 for header)
                total_bytes_funcs = sum(1 for _ in f) - 1
                
            strat_done_set = self.done_by_strat.get(strat, set())
            if len(strat_done_set) >= total_bytes_funcs:
                return True
        except Exception as e:
            self.logger.debug(f"Failed to mathematically check {strat}: {e}")
            
        return False

    def setup(self):
        self.engine = get_engine()

        stem = self.binary_name
        cfg_path = self.raw_data_dir / f"{stem}_cfg.json"
        func_cfg_dir = self.raw_data_dir / f"{stem}_func-cfg"
        func_cfg_jsonl = self.raw_data_dir / f"{stem}_func-cfg.jsonl"
        zigs_path = self.raw_data_dir / f"{stem}_zigs.json"
        finfo_path = self.raw_data_dir / f"{stem}_finfo.json"
        cg_path = self.raw_data_dir / f"{stem}_cg.json"
        
        bytes_tar = self.raw_data_dir / f"{stem}_bytes.tar"
        bytes_masked_tar = self.raw_data_dir / f"{stem}_bytes-masked.tar"
        
        def _find_index(tar_path, stem_name, kind):
            candidates = [
                tar_path.parent / f"{stem_name}_{kind}_func-index.csv",
                tar_path.parent / f"00-func-index_{kind}.csv",
                tar_path.parent / f"{stem_name}_{kind}" / f"00-func-index_{kind}.csv",
            ]
            for p in candidates:
                if p.is_file():
                    return p
            return candidates[-1]

        bytes_index = _find_index(bytes_tar, stem, "bytes")
        bytes_masked_index = _find_index(bytes_masked_tar, stem, "bytes-masked")

        func_cfg_path = None
        if func_cfg_dir.is_dir():
            func_cfg_path = func_cfg_dir
        elif func_cfg_jsonl.is_file():
            func_cfg_path = func_cfg_jsonl

        self.data_paths = BinaryDataPaths(
            cfg=cfg_path if cfg_path.is_file() else None,
            func_cfg=func_cfg_path,
            zigs=zigs_path if zigs_path.is_file() else None,
            finfo=finfo_path if finfo_path.is_file() else None,
            cg=cg_path if cg_path.is_file() else None,
            bytes=BytesDataPaths(data_path=bytes_tar, index_path=bytes_index),
            bytes_masked=BytesDataPaths(data_path=bytes_masked_tar, index_path=bytes_masked_index),
            binary_name=self.binary_name,
        )

        bininfo = _load_bininfo(self.raw_data_dir, self.binary_name)
        arch = bininfo.get("arch")
        bits = bininfo.get("bits")
        cc = bininfo.get("cc")
        sha256 = bininfo.get("sha256")

        self.done_marker_path = self.raw_data_dir / f"{self.binary_name}.ingest_done"
        if self.done_marker_path.exists() and not self.overwrite:
            self.logger.info(f"Binary marked as natively completed by .ingest_done marker. Fast-skipping.")
            self._is_completed = True
            return

        with get_session(self.engine) as session:
            writer = DBWriter(session)
            binary_row = writer.get_or_create_binary(self.project, self.binary_name, arch=arch, bits=bits, cc=cc, sha256=sha256)
            for ds_name in self.datasets:
                ds = writer.get_or_create_dataset(ds_name)
                writer.tag_binary(binary_row, ds)
                
            self.done_by_strat = _get_done_strategies(session, binary_row.id, self.strategies, overwrite=self.overwrite)
            
            if self.done_by_strat is None:
                self.done_by_strat = {s: set() for s in self.strategies}
            else:
                for s in self.strategies:
                    if s not in self.done_by_strat or self.done_by_strat[s] is None:
                        self.done_by_strat[s] = set()

            # Build skipped_tasks_cache from skip_log in the DB (one query).
            # This produces the shape: {task_type: set(hex_addr_str)}
            if not self.overwrite:
                try:
                    from binrankbench.storage.ingest import _STRATEGY_IDS
                    from sqlalchemy import select
                    
                    rows = session.execute(
                        select(Function.func_addr, SkipLog.strategy_id)
                        .join(SkipLog.function)
                        .where(Function.binary_id == binary_row.id)
                    ).all()
                    
                    # Reverse map: strategy ID (int) -> task type (str)
                    strat_to_task = {
                        strat.value: task
                        for task, strats in _STRATEGY_IDS.items()
                        for strat in strats
                    }

                    for hex_addr, strat_id in rows:
                        task = strat_to_task.get(strat_id)
                        if task:
                            self.skipped_tasks_cache.setdefault(task, set()).add(hex_addr)
                    self._logger.info(f"Loaded {len(rows)} skips from database.")
                except Exception as e:
                    self._logger.warning(f"Failed to load skip_log cache from DB: {e}")

            for strat, skipped_addrs in self.skipped_tasks_cache.items():
                if strat not in self.done_by_strat:
                    self.done_by_strat[strat] = set()
                self.done_by_strat[strat].update(skipped_addrs)

            session.commit()

        # O(1) Metadata Bypass: Check if all strategies are ALREADY 100% complete in DB
        # before reading 1GB+ JSONL files.
        try:
            expected_count = count_lines_regex(func_cfg_path)
            if expected_count > 0:
                is_actually_done = True
                for strat in self.strategies:
                    if len(self.done_by_strat.get(strat, set())) < expected_count:
                        is_actually_done = False
                        break
                
                if is_actually_done:
                    self.logger.info(f"Binary confirmed 100% complete via metadata count ({expected_count} functions). Instant skip.")
                    self._is_completed = True
                    try:
                        self.done_marker_path.touch(exist_ok=True)
                    except Exception:
                        pass
                    return
        except Exception as e:
            self.logger.debug(f"Metadata bypass check failed: {e}")

        # Phase 4 Optimization: O(1) mathematical skip for TAR archives
        # Iterating `tarfile` sequentially in memory takes 5-10s per binary.
        # If catalog1 and bytes are completely present in Postgres (verified by func-index.csv sizes),
        # we can completely unplug the TAR paths to skip the agonizing disk iteration.
        
        # Clone strategies to avoid modifying the list shared by all posters
        self.strategies = list(self.strategies)
        
        bytes_complete = ("bytes" not in self.strategies) or self._is_bytes_strategy_complete("bytes")
        catalog1_complete = ("catalog1" not in self.strategies) or self._is_bytes_strategy_complete("catalog1")
        
        if bytes_complete and catalog1_complete:
            self.logger.debug("Strategies requiring bytes.tar are mathematically 100% complete (or disabled). Bypassing bytes extraction.")
            self.data_paths.bytes = None
            self.data_paths.bytes_masked = None

    def run(self):
        start_time = time.time()
        with binary_log_context(self.binary_name):
            try:
                setup_start = time.time()
                self.setup()
                setup_end = time.time()
                if (setup_end - setup_start) > 2.0:
                    self.logger.info(f"Setup took {setup_end - setup_start:.2f}s")
                
                if getattr(self, '_is_completed', False):
                    self.logger.info("IngestTaskPoster fast-skipping already completed binary")
                    if self.shared_stats:
                        self.shared_stats.set_binary_expected(self.binary_name, 0)
                    return
                
                self.data_manager = BinaryFunctionsDataManager(
                    binary_path=self.binary_path,
                    data_paths=self.data_paths,
                    callgraph_path=self.data_paths.cg,
                )
                self.data_manager.setup(lazy=True)
                
                # Check the callgraph at the binary level
                # (it's the same for all the functions in the binary)
                have_cg = self.data_paths.cg is not None
                
                # Iterate functions
                current_batch: list[TaskWrapper] = []
                batch_size = 100
                tasks_posted = 0
                loop_start = time.time()

                for func_data in self.data_manager.iterate_functions_data(sort_by_address=True, include_callgraph=False):
                    (func_addr, func_name, func_cfg, func_zignature, func_finfo, 
                     cfg_raw_str, zignature_raw_str, finfo_raw_str, 
                     _func_cg, _fbytes_raw, _fbytes_bitmask) = func_data
                    func_addr_hex = hex(func_addr)
                    
                    # Phase 3 Optimization: Serialize to JSON strings once per function
                    # if they weren't already serialized (lazy serialization).
                    if zignature_raw_str is None and func_zignature is not None:
                        zignature_raw_str = json.dumps(func_zignature)
                    if finfo_raw_str is None and func_finfo is not None:
                        finfo_raw_str = json.dumps(func_finfo)
                                        
                    # Determine function size for prioritization
                    func_size = 0
                    if func_finfo:
                        func_size = func_finfo.get("size", 0)
                    elif func_cfg:
                        func_size = func_cfg.get("size", 0)

                    # Lookup function bytes
                    func_bytes = None
                    if _fbytes_raw is not None and len(_fbytes_raw) > 0:
                        # Try from bytes data source
                        func_bytes = _fbytes_raw
                    elif func_zignature is not None and func_size <= 500:
                        # Try from zignature if function is not too big to be stored there
                        func_bytes_hex = func_zignature.get("bytes")
                        if func_bytes_hex:
                            func_bytes = bytes.fromhex(func_bytes_hex)

                    # Helper conditions
                    has_cfg = func_cfg is not None
                    has_finfo = func_finfo is not None
                    has_zignature = func_zignature is not None
                    has_bytes = func_bytes is not None

                    tasks_for_this_func = []

                    if "ccbhash" in self.strategies and func_addr_hex not in self.done_by_strat.get("ccbhash", set()):
                        m = []
                        if not has_cfg: m.append("func_cfg")
                        if not has_finfo: m.append("func_info")
                        if not has_zignature: m.append("func_zignature")
                        if not have_cg: m.append("callgraph")

                        if not m:
                            tasks_for_this_func.append(TaskWrapper(
                                func_addr=func_addr, 
                                task=CCBHashTask(func_addr=func_addr, finfo_raw_str=finfo_raw_str, zignature_raw_str=zignature_raw_str, cfg_raw_str=cfg_raw_str, binary_name=self.binary_name), 
                                output_path=self.output_dir, 
                                binary_name=self.binary_name,
                                func_name=func_name,
                                size=func_size
                            ))
                        else:
                            tasks_for_this_func.append(SkipInfo(func_addr=func_addr, task_type="ccbhash", reason=f"missing {', '.join(m)}", output_path=self.output_dir / f"{self.binary_name}_ccbhash.csv", binary_name=self.binary_name))
                        
                    if "machoke" in self.strategies and func_addr_hex not in self.done_by_strat.get("machoke", set()):
                        if has_cfg:
                            tasks_for_this_func.append(TaskWrapper(
                                func_addr=func_addr, 
                                task=MachokeTask(func_addr=func_addr, cfg_raw_str=cfg_raw_str), 
                                output_path=self.output_dir, 
                                binary_name=self.binary_name,
                                func_name=func_name,
                                size=func_size
                            ))
                        else:
                            tasks_for_this_func.append(SkipInfo(func_addr=func_addr, task_type="machoke", reason="missing func_cfg", output_path=self.output_dir / f"{self.binary_name}_machoke.csv", binary_name=self.binary_name))
                            
                    if "fss" in self.strategies and func_addr_hex not in self.done_by_strat.get("fss", set()):
                        if has_cfg:
                            from binrankbench.storage.models.signatures.strategy_type import StrategyID
                            
                            compute_original = func_addr_hex not in self.done_by_strat.get(StrategyID.fss_original.name, set())
                            compute_marcelli = func_addr_hex not in self.done_by_strat.get(StrategyID.fss_marcelli.name, set())
                            compute_marcelli_weighted = func_addr_hex not in self.done_by_strat.get(StrategyID.fss_marcelli_weighted.name, set())
                            
                            tasks_for_this_func.append(TaskWrapper(
                                func_addr=func_addr, 
                                task=FunctionSimSearchTask(
                                    func_addr=func_addr, 
                                    cfg_raw_str=cfg_raw_str,
                                    compute_original=compute_original,
                                    compute_marcelli=compute_marcelli,
                                    compute_marcelli_weighted=compute_marcelli_weighted
                                ), 
                                output_path=self.output_dir, 
                                binary_name=self.binary_name,
                                func_name=func_name,
                                size=func_size
                            ))
                        else:
                            tasks_for_this_func.append(SkipInfo(func_addr=func_addr, task_type="fss", reason="missing func_cfg", output_path=self.output_dir / f"{self.binary_name}_fss.csv", binary_name=self.binary_name))
                            
                    if "catalog1" in self.strategies and func_addr_hex not in self.done_by_strat.get("catalog1", set()):
                        if has_bytes:
                            tasks_for_this_func.append(TaskWrapper(
                                func_addr=func_addr, 
                                task=Catalog1Task(
                                    func_addr=func_addr, 
                                    func_bytes=func_bytes, 
                                    zignature_raw_str=zignature_raw_str,
                                    bit_masked_func_bytes=_fbytes_bitmask,
                                    finfo_raw_str=finfo_raw_str
                                ), 
                                output_path=self.output_dir, 
                                binary_name=self.binary_name,
                                func_name=func_name,
                                size=func_size
                            ))
                        else:
                            tasks_for_this_func.append(SkipInfo(func_addr=func_addr, task_type="catalog1", reason="missing func_bytes", output_path=self.output_dir / f"{self.binary_name}_catalog1.csv", binary_name=self.binary_name))
                            
                    if "bytes" in self.strategies and func_addr_hex not in self.done_by_strat.get("bytes", set()):
                        if has_bytes and has_zignature:
                            tasks_for_this_func.append(TaskWrapper(
                                func_addr=func_addr, 
                                task=BytesTask(
                                    func_addr=func_addr, 
                                    func_bytes=func_bytes, 
                                    zignature_raw_str=zignature_raw_str, 
                                    bit_masked_func_bytes=_fbytes_bitmask,
                                    finfo_raw_str=finfo_raw_str
                                ), 
                                output_path=self.output_dir, 
                                binary_name=self.binary_name,
                                func_name=func_name,
                                size=func_size
                            ))
                        else:
                            m = []
                            if not has_bytes: m.append("func_bytes")
                            if not has_zignature: m.append("func_zignature")
                            tasks_for_this_func.append(SkipInfo(func_addr=func_addr, task_type="bytes", reason=f"missing {', '.join(m)}", output_path=self.output_dir / f"{self.binary_name}_bytes.csv", binary_name=self.binary_name))
                            
                    if "function_details" in self.strategies and func_addr_hex not in self.done_by_strat.get("function_details", set()):
                        if func_finfo is not None or func_zignature is not None:
                            from binrankbench.modules.generate.tasks import FunctionDetailsTask
                            tasks_for_this_func.append(TaskWrapper(
                                func_addr=func_addr, 
                                task=FunctionDetailsTask(func_addr=func_addr, zignature_raw_str=zignature_raw_str, finfo_raw_str=finfo_raw_str), 
                                output_path=self.output_dir, 
                                binary_name=self.binary_name,
                                func_name=func_name,
                                size=func_size
                            ))
                        else:
                            tasks_for_this_func.append(SkipInfo(func_addr=func_addr, task_type="function_details", reason="missing func_info, func_zignature", output_path=self.output_dir / f"{self.binary_name}_function_details.csv", binary_name=self.binary_name))

                    # Sort tasks for this function by task type priority
                    tasks_for_this_func.sort(key=lambda w: get_task_priority(w) if not isinstance(w, SkipInfo) else 0)
                    
                    # Add to current batch
                    for wrapper in tasks_for_this_func:
                        if isinstance(wrapper, SkipInfo):
                            # SkipInfo belongs on the result queue, NOT the task queue
                            self.queue_manager.result_queue.put(wrapper)
                            continue
                        current_batch.append(wrapper)
                        tasks_posted += 1
                        if len(current_batch) >= batch_size:
                            while True:
                                try:
                                    self.queue_manager.task_queue.put(current_batch, timeout=0.1)
                                    if self.shared_stats:
                                        self.shared_stats.increment_task_groups_expected(len(current_batch))
                                        self.shared_stats.increment_binary_expected(self.binary_name, len(current_batch))
                                        self.shared_stats.increment_task_groups_posted(len(current_batch), self.poster_id, self.binary_name)
                                    current_batch = []
                                    break
                                except Full:
                                    if self.queue_manager.all_runners_shutdown.is_set():
                                        return
                
                # Post remaining tasks in the final batch
                if current_batch:
                    while True:
                        try:
                            self.queue_manager.task_queue.put(current_batch, timeout=0.1)
                            if self.shared_stats:
                                self.shared_stats.increment_task_groups_expected(len(current_batch))
                                self.shared_stats.increment_binary_expected(self.binary_name, len(current_batch))
                                self.shared_stats.increment_task_groups_posted(len(current_batch), self.poster_id, self.binary_name)
                            break
                        except Full:
                            if self.queue_manager.all_runners_shutdown.is_set():
                                return
                    tasks_posted += 1
                    
                if tasks_posted == 0 and not getattr(self, '_is_completed', False):
                    # We iterated the entire binary and not a single task was posted!
                    # This means it's mathematically completely done. Safe to mark.
                    self.logger.info("0 tasks mapped! Dropping .ingest_done flag for instant skips next boot.")
                    try:
                        self.done_marker_path.touch()
                    except Exception as e:
                        self.logger.debug(f"Failed to touch {self.done_marker_path}: {e}")
                        
                if getattr(self, '_is_completed', False) == False and self.shared_stats:
                    self.shared_stats.set_binary_expected(self.binary_name, tasks_posted)
                        
                duration = time.time() - start_time
                if tasks_posted > 0 or duration > 1.0:
                    self.logger.info(f"Posted {tasks_posted} tasks in {duration:.2f}s (iter: {time.time() - loop_start:.2f}s)")
            except Exception as e:
                self.logger.exception(f"Error posting tasks for {self.binary_name}: {e}")
            finally:
                if hasattr(self, 'engine'):
                    self.engine.dispose()


def run_ingest_poster(worker_id: int, project: str, raw_data_dir: Path, output_dir: Path, queue_manager: QueueManager, log_queue: Queue, shared_stats: Optional[SharedStats], strategies: list[str], datasets: list[str], overwrite: bool):
    setup_worker_logging(log_queue)
    logger = get_logger(f"IngestPoster-{worker_id}")
    logger.info(f"Ingest Poster {worker_id} started")
    
    if shared_stats:
        shared_stats.set_poster_state(worker_id, WORKER_STATE_IDLE)
        
    while True:
        try:
            binary_path = queue_manager.binary_queue.get(timeout=3.0)
            if binary_path is None:
                break
            
            if shared_stats:
                shared_stats.set_poster_state(worker_id, WORKER_STATE_WORKING)
                
            poster = IngestTaskPoster(
                binary_path=binary_path, 
                raw_data_dir=raw_data_dir, 
                output_dir=output_dir, 
                queue_manager=queue_manager, 
                poster_id=worker_id, 
                project=project, 
                strategies=strategies, 
                datasets=datasets, 
                overwrite=overwrite, 
                shared_stats=shared_stats
            )
            poster.run()
            
            if shared_stats:
                shared_stats.set_poster_state(worker_id, WORKER_STATE_IDLE)
                
        except Empty:
            if queue_manager.all_runners_shutdown.is_set():
                break
            continue
        except Exception as e:
            logger.exception(f"Error in outer poster loop: {e}")

    if shared_stats:
        shared_stats.set_poster_state(worker_id, WORKER_STATE_STOPPED)

    logger.info(f"Ingest Poster {worker_id} exiting")
