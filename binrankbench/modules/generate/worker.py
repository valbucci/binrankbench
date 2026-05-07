"""Multiprocess workers: TaskPoster, TaskRunner, ResultCollector, and the LoggingManager process."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any, NamedTuple
from tqdm import tqdm
from multiprocessing import Queue, Event, Value
from queue import Empty, Full
from contextlib import suppress
import logging
import csv
import time

from binrankbench.modules.generate.logging import setup_worker_logging, get_logging_config
from binrankbench.common.types import (R2CodeInfoIn, R2ZignatureIn, R2CallGraph,
                                   R2FunctionInfoIn)
from binrankbench.modules.generate.logging import get_logger, LoggerManager, binary_log_context
from binrankbench.modules.generate.data import get_data_manager, get_processed_functions
from binrankbench.modules.generate.tasks import CCBHashTask, get_task_priority
from binrankbench.modules.generate.tasks import TaskGroup, TaskWrapper, TASK_KEYS
from binrankbench.modules.generate.result import ResultWrapper, SkipInfo
from binrankbench.modules.generate.dashboard import DashboardLogMessage
from binrankbench.modules.generate.stats import (
    SharedStats, 
    WORKER_STATE_STOPPED, 
    WORKER_STATE_IDLE, 
    WORKER_STATE_WORKING
)
from binrankbench.common.config import load_config


logger = get_logger("worker")


# Utility functions for shutdown checking
def _check_shutdown_requested(shared_stats: Optional[SharedStats]) -> bool:
    """
    Check if force shutdown has been requested.
    
    Args:
        shared_stats: Optional SharedStats instance
        
    Returns:
        True if shutdown requested, False otherwise
    """
    if shared_stats is None:
        return False
    return shared_stats.forced_shutdown_requested


@dataclass
class PosterMetrics:
    """Track posting progress for TaskPoster for clearer reporting."""

    functions_seen: int = 0
    functions_with_tasks: int = 0
    tasks_posted: int = 0
    skips_posted: int = 0
    checkpoint_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))


class ReceivedShutdownSignal(Exception):
    """Signal that the LoggingManager has received a shutdown signal."""
    pass


class LoggingManager:
    """
    Process that receives logs and control messages, writes to files.
    
    This runs in a separate process and is the single point of file I/O
    for all log files, avoiding contention and handler duplication.
    """
    
    def __init__(self, log_queue: Queue, 
                 dashboard_queue: Optional[Queue] = None,
                 tui_enabled: Optional[bool] = None,
                 console_level: Optional[int] = None,
                 file_level: Optional[int] = None,
                 log_file_path: Optional[Path] = None):
        self.log_queue = log_queue
        self.dashboard_queue = dashboard_queue
        
        # Get logging configuration
        logging_config = get_logging_config()
        if tui_enabled is None:
            tui_enabled = logging_config.tui_enabled
        if console_level is None:
            console_level = logging_config.console_level
        if file_level is None:
            file_level = logging_config.file_level
        if log_file_path is None:
            log_file_path = logging_config.log_file_path
        
        # Create LoggerManager with file logging enabled (this process writes to files)
        # When TUI is enabled, don't attach console handler (all output goes to files and dashboard)
        # When TUI is disabled, attach console handler with ConsoleFormatter (nice looking console output)
        self.logger_manager = LoggerManager(
            enable_file_logging=True,
            attach_console=not tui_enabled,  # Attach console only when TUI disabled
            console_level=console_level,
            file_level=file_level,
            log_file_path=log_file_path,
            use_file_formatter_for_console=False,  # Always use ConsoleFormatter for console (nice looking)
        )
        
        try:
            cfg = load_config()
            logging_cfg = cfg.logging
            self.logger_manager.configure_levels(
                logging_cfg.get("default_level"),
                logging_cfg.get("components", {}),
            )
        except Exception as e:
            pass
        
        self.running = True
        self.flush_counter = 0
        self.logger = self.logger_manager.get_logger("LoggingManager")
        
        # Log file path info when TUI disabled
        if not tui_enabled and log_file_path is not None:
            self.logger.info(f"Log file: {log_file_path.resolve()}")
        elif not tui_enabled:
            self.logger.info(f"Log file: {self.logger_manager.global_log_path.resolve()}")
    
    def run(self) -> None:
        """Main loop: receive and process log records and control messages."""
        self.logger.info("LoggingManager started")
        
        try:
            while self.running:
                try:
                    item = self.log_queue.get(timeout=1.0)
                except Empty:
                    # Periodic flush during idle
                    try:
                        self.logger_manager.flush_handlers(force=False)
                    except Exception as e:
                        pass  # Don't crash on flush errors
                    continue
                
                # Handle different item types
                if isinstance(item, logging.LogRecord):
                    self.handle_log_record(item)
                
                elif item is None:
                    raise ReceivedShutdownSignal()

                else:
                    self.logger.warning(f"Unknown item type in log queue: {type(item)}")
                
                # Periodic flush every 100 records
                self.flush_counter += 1
                if self.flush_counter >= 100:
                    try:
                        self.logger_manager.flush_handlers(force=False)
                    except Exception as e:
                        pass  # Don't crash on flush errors
                    self.flush_counter = 0
        
        except ReceivedShutdownSignal:
            self.logger.info("Received shutdown signal, shutting down")
            self.running = False
        
        except Exception as e:
            self.logger.exception(f"Fatal error in LoggingManager: {e}")
        
        finally:
            # Final cleanup
            self.logger.info("LoggingManager shutting down, cleaning up...")
            self.logger_manager.cleanup()
    
    def _broadcast_to_dashboard(self, record: logging.LogRecord) -> None:
        if self.dashboard_queue is None:
            return

        try:
            message = record.getMessage()
            if len(message) > 1000:
                message = message[:997] + "..."
            name = record.name.replace("binrankbench.modules.generate.", "")
            binary_name = getattr(record, "binary_name", None)
            if binary_name:
                name = f"{name}({binary_name})"

            payload = DashboardLogMessage(
                created=record.created,
                levelno=record.levelno,
                levelname=record.levelname,
                name=name,
                message=message,
            )
            self.dashboard_queue.put_nowait(payload)
        except Full:
            pass
        except Exception as e:
            pass

    def handle_log_record(self, record: logging.LogRecord) -> None:
        """Process and emit log record through appropriate handlers."""
        try:
            self._broadcast_to_dashboard(record)
            # Get the logger and let it propagate through handlers
            logger = logging.getLogger(record.name)
            logger.handle(record)
        except Exception as e:
            # Fallback to stderr if logging fails
            import sys
            print(f"ERROR LOGGING: {record.getMessage()} (Exception: {e})", file=sys.stderr)


def run_logging_manager(log_queue: Queue, dashboard_queue: Optional[Queue] = None,
                        tui_enabled: bool = True,
                        console_level: Optional[int] = None,
                        file_level: Optional[int] = None,
                        log_file_path: Optional[str] = None) -> None:
    """Process function wrapper for LoggingManager."""
    # Convert log_file_path string back to Path if provided
    log_path: Optional[Path] = None
    if log_file_path is not None:
        log_path = Path(log_file_path)
    
    manager = LoggingManager(
        log_queue, 
        dashboard_queue,
        tui_enabled=tui_enabled,
        console_level=console_level,
        file_level=file_level,
        log_file_path=log_path,
    )
    manager.run()


class QueueManager:
    """Manages queues and coordination events for multiprocess generation."""
    
    def __init__(self, maxsize_tasks: int = 10_000, 
                 maxsize_results: int = 100_000) -> None:
        self.task_queue = Queue(maxsize=maxsize_tasks)
        self.result_queue = Queue(maxsize=maxsize_results)
        self.binary_queue = Queue()  # Queue of binary paths to process
        
        # Coordination events
        self.all_posters_done = Event()
        self.all_runners_shutdown = Event()
        self.collector_shutdown = Event()
    
    def get_safe_size(self, queue_name: str) -> int:
        """
        Safely get queue size, handling NotImplementedError and OSError.
        
        Args:
            queue_name: Name of queue ('task', 'result', or 'binary')
            
        Returns:
            Queue size, or 0 if unable to determine
        """
        queue_map = {
            'task': self.task_queue,
            'result': self.result_queue,
            'binary': self.binary_queue,
        }
        
        queue = queue_map.get(queue_name.lower())
        if queue is None:
            return 0
        
        try:
            return queue.qsize()
        except (NotImplementedError, OSError, AttributeError):
            return 0
        except Exception as e:
            return 0
    
    def close(self) -> None:
        """Close multiprocessing queues to avoid hanging join threads at exit."""
        for q in (self.task_queue, self.result_queue, self.binary_queue):
            with suppress(Exception):
                q.close()
            with suppress(Exception):
                q.cancel_join_thread()


class TaskPoster:
    """Posts individual tasks from binary function data to the task queue."""
    
    def __init__(self, binary_path: Path, raw_data_dir: Path,
                 output_dir: Path, queue_manager: QueueManager,
                 poster_id: int,
                 shared_stats: Optional[SharedStats] = None) -> None:
        self.binary_path = binary_path
        self.raw_data_dir = raw_data_dir
        self.output_dir = output_dir
        self.queue_manager = queue_manager
        self.stopped_event = Event()
        self.data_manager = get_data_manager(binary_path, raw_data_dir)
        self.checkpoint_data: Optional[dict[str, set[int]]] = None
        self.poster_id = poster_id
        self.shared_stats = shared_stats
        self._shutdown_triggered = False
        self._last_metrics: Optional[PosterMetrics] = None
        self._is_completed = False
        
        # Use LoggerAdapter to add binary context to all log records
        self._logger = logging.LoggerAdapter(
            get_logger("TaskPoster"),
            extra={'binary_name': self.binary_path.name}
        )

    @property
    def logger(self) -> logging.LoggerAdapter:
        return self._logger
    
    @property
    def binary_name(self) -> str:
        return self.binary_path.name

    @property
    def shutdown_triggered(self) -> bool:
        return self._shutdown_triggered

    @property
    def last_metrics(self) -> Optional[PosterMetrics]:
        return self._last_metrics

    def _shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return _check_shutdown_requested(self.shared_stats)
        
    def _exit_condition_reached(self) -> bool:
        return (self._shutdown_requested() or self.stopped_event.is_set() or 
                self.queue_manager.all_posters_done.is_set())

    def _get_total_functions_fast(self) -> Optional[int]:
        """Rapidly count the total number of ingestable functions using dataset sizes to avoid parsing."""
        finfo_path = self.data_manager.data_paths.finfo
        if finfo_path and finfo_path.is_file():
            try:
                with open(finfo_path, 'rb') as f:
                    content = f.read()
                    return content.count(b'"address":')
            except Exception as e:
                self.logger.debug(f"Fast finfo count failed: {e}")
        return None

    def setup(self) -> None:
        """Setup data manager and register call graph."""
        binary_name = self.binary_name
        
        # Check if this is a resumed run (has .log.part file)
        part_file = self.output_dir / f"{binary_name}.log.part"
        
        if part_file.exists():
            self.logger.info(f"Resuming from checkpoint: {part_file.name}")
            self.checkpoint_data = self._load_checkpoint()
            
            # EARLY EXIT FAST-PATH:
            total_funcs = self._get_total_functions_fast()
            if total_funcs is not None and total_funcs > 0 and self.checkpoint_data:
                strategies = ["machoke", "ccbhash", "catalog1", "bytes", "function_details", "fss"]
                is_complete = all(
                    len(self.checkpoint_data.get(task_type, set())) >= total_funcs 
                    for task_type in strategies
                )
                if is_complete:
                    self.logger.info(f"Binary 100% complete in checkpoints ({total_funcs} functions). Fast-skipping.")
                    self._is_completed = True
                    return
        else:
            self.checkpoint_data = None
            
        self.data_manager.setup()

    def _load_checkpoint(self) -> dict[str, set[int]]:
        """Load checkpoint data from existing CSV files."""
        checkpoint = {}
        binary_name = self.binary_path.name
        
        for task_type in ["machoke", "ccbhash", "catalog1", 
                         "bytes", "function_details", "fss"]:
            processed = get_processed_functions(
                binary_name, 
                self.output_dir, 
                task_type
            )
            checkpoint[task_type] = processed
            if processed:
                self.logger.info(
                    f"Checkpoint: {len(processed)} functions already processed for {task_type}"
                )
        
        total_checkpointed = sum(len(s) for s in checkpoint.values())
        if total_checkpointed > 0:
            self.logger.info(f"Total checkpointed function-tasks: {total_checkpointed}")
        
        return checkpoint
    
    def _record_task_group_stats(
        self,
        task_wrappers: list[TaskWrapper],
        skip_infos: list[SkipInfo],
        checkpointed_tasks: list[str],
        is_task_group: bool = True
    ) -> None:
        """Record statistics for task groups (functions).
        
        Args:
            task_wrappers: List of task wrappers (individual tasks)
            skip_infos: List of skip infos
            checkpointed_tasks: List of checkpointed task types
            is_task_group: If True, treat this as one task group (function).
                          If False, count individual tasks (for backward compatibility).
        """
        if self.shared_stats is None:
            return

        if is_task_group:
            # One function = one task group, regardless of how many tasks it has
            # A function is "posted" if it has any tasks to execute
            # A function is "skipped" only if ALL its tasks were skipped (no task_wrappers, no checkpointed_tasks)
            # A function is "recovered" if it has checkpointed tasks but no new tasks to post
            posted = 1 if task_wrappers else 0
            skipped = 1 if skip_infos and not task_wrappers and not checkpointed_tasks else 0
            recovered = 1 if checkpointed_tasks and not task_wrappers else 0
        else:
            # Legacy mode: count individual tasks
            posted = len(task_wrappers)
            skipped = len(skip_infos)
            recovered = len(checkpointed_tasks)
        
        expected = posted + skipped + recovered

        if expected:
            self.shared_stats.increment_task_groups_expected(expected)
            # Track per-binary expected (task groups = functions)
            self.shared_stats.increment_binary_expected(self.binary_name, expected)
        if posted:
            self.shared_stats.increment_task_groups_posted(
                posted, 
                poster_id=self.poster_id,
                binary_name=self.binary_name
            )
        if skipped:
            self.shared_stats.increment_task_groups_skipped(skipped)
         
    def _enqueue_batch(
        self,
        items: list[Any],
        queue: Queue,
        timeout: float = 0.1,
    ) -> tuple[int, int]:
        """
        Attempt to enqueue a batch of items while respecting shutdown signals.
        
        Returns a tuple (posted, remaining) indicating how many items were
        enqueued and how many are left in the list after processing.
        """
        original_len = len(items)
        posted = 0
        pending = deque(items)

        while pending:
            if self._exit_condition_reached():
                break

            try:
                queue.put(pending[0], timeout=timeout)
            except Full:
                continue
            else:
                pending.popleft()
                posted += 1

        # Remove the items we successfully enqueued from the original list
        if posted:
            del items[:posted]

        remaining = original_len - posted
        return posted, remaining

    def _post_skip_infos(self, skip_list: list[SkipInfo]) -> tuple[int, int]:
        return self._enqueue_batch(skip_list, self.queue_manager.result_queue)

    def _post_tasks(self, task_list: list[TaskWrapper]) -> tuple[int, int]:
        return self._enqueue_batch(task_list, self.queue_manager.task_queue)

    def _build_task_group(
        self,
        func_data: tuple[Any, ...]
    ) -> TaskGroup:
        # Updated tuple unpacking: call graph is still in tuple but will be None
        # when include_callgraph=False, so we unpack it but ignore it
        (address, name, cfg, zignature, finfo, fbytes_raw, fbytes_bitmask, _) = func_data

        return TaskGroup(
            output_dir=self.output_dir,
            binary_name=self.binary_name,
            func_addr=address,
            func_name=name,
            func_info=finfo,
            func_zignature=zignature,
            func_code=cfg,
            func_callgraph=None,  # No longer included - will be looked up via manager
            func_bytes=fbytes_raw,
            bit_masked_func_bytes=fbytes_bitmask,
        )

    def _process_function(
        self,
        func_data: tuple[Any, ...],
        metrics: PosterMetrics,
        task_buffer: Optional[dict[int, list[TaskWrapper]]] = None,
        skip_buffer: Optional[list[SkipInfo]] = None,
    ) -> bool:
        """Prepare tasks for a single function, optionally buffering them.

        If task_buffer is provided, tasks are added to the buffer instead of being posted immediately.
        This allows posting tasks in priority order across multiple functions.

        Returns False if a shutdown condition interrupted processing.
        """
        if self._shutdown_requested():
            self.logger.warning(
                "Shutdown requested; stopping task posting immediately"
            )
            self.logger.info(
                "Partial progress: processed %d functions so far",
                metrics.functions_seen,
            )
            return False

        task_group = self._build_task_group(func_data)

        task_wrappers, skip_infos, checkpointed_tasks = task_group.prepare_tasks(
            checkpoint_data=self.checkpoint_data
        )

        metrics.functions_seen += 1

        if task_buffer is not None:
            # Buffer mode: collect tasks by priority for later posting
            # But record stats immediately so progress tracking works correctly
            self._record_task_group_stats(
                task_wrappers,
                skip_infos,
                checkpointed_tasks,
            )
            
            for task_wrapper in task_wrappers:
                priority = get_task_priority(task_wrapper)
                if priority not in task_buffer:
                    task_buffer[priority] = []
                task_buffer[priority].append(task_wrapper)
            
            if skip_buffer is not None:
                skip_buffer.extend(skip_infos)
            
            # Update metrics
            if task_wrappers:
                metrics.functions_with_tasks += 1
                metrics.tasks_posted += len(task_wrappers)  # Will be posted later
            if skip_infos:
                metrics.skips_posted += len(skip_infos)  # Will be posted later
            
            for task_type in checkpointed_tasks:
                metrics.checkpoint_counts[task_type] += 1
            
            return True
        else:
            # Immediate posting mode: post tasks for this function right away
            # Sort tasks by priority: fast tasks first, slow tasks last
            task_wrappers.sort(key=get_task_priority)

            self._record_task_group_stats(
                task_wrappers,
                skip_infos,
                checkpointed_tasks,
            )

            if task_wrappers:
                metrics.functions_with_tasks += 1
                posted, remaining = self._post_tasks(task_wrappers)
                metrics.tasks_posted += posted
                if remaining:
                    self.logger.debug(
                        "Shutdown while posting tasks; %d task(s) not enqueued",
                        remaining,
                    )
                    return False

            if skip_infos:
                posted_skips, remaining_skips = self._post_skip_infos(skip_infos)
                metrics.skips_posted += posted_skips
                if remaining_skips:
                    self.logger.debug(
                        "Shutdown while posting skips; %d skip(s) not enqueued",
                        remaining_skips,
                    )
                    return False

            for task_type in checkpointed_tasks:
                metrics.checkpoint_counts[task_type] += 1

            return True

    def _run(self) -> None:
        """Load function data and post individual tasks to queue.
        
        Uses a two-pass approach for better task prioritization:
        1. First pass: Collect all tasks from all functions, grouped by priority
        2. Second pass: Post tasks in priority order (fast tasks first, slow tasks last)
        
        This ensures workers process many fast tasks before hitting slow CCBHash tasks,
        rather than processing all tasks from one function before moving to the next.
        """
        metrics = PosterMetrics()
        shutdown_triggered = False
        last_progress_log = time.time()
        
        # Buffer to collect tasks by priority across all functions
        task_buffer: dict[int, list[TaskWrapper]] = {}
        skip_buffer: list[SkipInfo] = []
        
        # First pass: Collect all tasks from all functions
        for func_data in self.data_manager.iterate_functions_data(include_callgraph=False):
            if self._exit_condition_reached():
                self.logger.debug("Exit condition reached during iteration; stopping task collection")
                shutdown_triggered = True
                break

            try:
                should_continue = self._process_function(func_data, metrics, task_buffer, skip_buffer)
            except Exception as e:
                self.logger.exception(f"Error processing function: {e}")
                should_continue = True
            if not should_continue:
                shutdown_triggered = True
                break
        
        # Second pass: Post tasks in priority order (lowest priority number = highest priority)
        if not shutdown_triggered and task_buffer:
            # Sort priorities (lower number = higher priority)
            sorted_priorities = sorted(task_buffer.keys())
            
            for priority in sorted_priorities:
                if self._exit_condition_reached():
                    self.logger.debug("Shutdown requested during task posting; stopping")
                    shutdown_triggered = True
                    break
                
                tasks = task_buffer[priority]
                posted, remaining = self._post_tasks(tasks)
                if remaining:
                    self.logger.debug(
                        "Shutdown while posting priority %d tasks; %d task(s) not enqueued",
                        priority,
                        remaining,
                    )
                    shutdown_triggered = True
                    break
        
        # Post skip infos
        if not shutdown_triggered and skip_buffer:
            posted_skips, remaining_skips = self._post_skip_infos(skip_buffer)
            if remaining_skips:
                self.logger.debug(
                    "Shutdown while posting skips; %d skip(s) not enqueued",
                    remaining_skips,
                )
        
        # Stats are already recorded during the first pass (buffering phase)
        # No need to record again here

        n_skipped_functions = metrics.functions_seen - metrics.functions_with_tasks
        self._shutdown_triggered = shutdown_triggered
        self._last_metrics = metrics

        if shutdown_triggered:
            self.logger.warning("=" * 50)
            self.logger.warning("STOPPED EARLY DUE TO SHUTDOWN REQUEST")
            self.logger.warning(
                "Processed %d functions (may be incomplete)",
                metrics.functions_seen,
            )
            self.logger.warning(
                "Posted %d tasks from %d functions",
                metrics.tasks_posted,
                metrics.functions_with_tasks,
            )
            self.logger.warning("=" * 50)
        else:
            # Reduced logging - only log completion, not detailed stats
            self.logger.debug(
                "Posted %d tasks from %d functions",
                metrics.tasks_posted,
                metrics.functions_with_tasks,
            )

    def run(self) -> None:
        with binary_log_context(self.binary_name):
            if getattr(self, '_is_completed', False):
                self.logger.info("TaskPoster fast-skipping already completed binary")
                self.stopped_event.set()
                return

            try:
                self._run()
            except Exception as e:
                self.logger.exception(f"Error posting tasks: {e}")
            else:
                if self._shutdown_triggered:
                    self.logger.info("TaskPoster exiting early due to shutdown signal")
                else:
                    self.logger.info("All tasks posted")
            finally:
                self.stopped_event.set()


class TaskRunner:
    """Pulls TaskWrappers from queue and executes them."""
    
    def __init__(self, worker_id: int, queue_manager: QueueManager,
                 shared_stats: Optional[SharedStats] = None,
                 raw_data_dir: Optional[Path] = None):
        self.worker_id = worker_id
        self.queue_manager = queue_manager
        self.n_completed = 0
        self.n_failed = 0
        self.stopped_event = Event()
        self.shared_stats = shared_stats
        self.raw_data_dir = raw_data_dir
        self._local_callgraph_cache: dict[str, R2CallGraph] = {}  # Process-local cache
        self._cache_access_times: dict[str, float] = {}  # Track last access
    
    @property
    def logger(self) -> logging.Logger:
        return get_logger(f"TaskRunner-{self.worker_id}")

    def _shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        if self.queue_manager.all_runners_shutdown.is_set():
            return True
        return _check_shutdown_requested(self.shared_stats)
        
    def _exit_condition_reached(self) -> bool:
        # if self.queue_manager.all_runners_shutdown.is_set():
        #     return self.queue_manager.task_queue.empty()
        # return self._shutdown_requested() or (
        #     self.queue_manager.all_posters_done.is_set()
        #     and self.queue_manager.task_queue.empty()
        # )
        return self._shutdown_requested()
    
    def _get_callgraph(self, binary_name: str) -> Optional[R2CallGraph]:
        """Get call graph for binary, using local cache or disk loading."""
        # Check local cache first
        if binary_name in self._local_callgraph_cache:
            self._cache_access_times[binary_name] = time.time()
            return self._local_callgraph_cache[binary_name]
        
        # 1. Try disk loading if raw_data_dir is available
        if self.raw_data_dir is not None:
            cg_path = self.raw_data_dir / f"{binary_name}_cg.json"
            if cg_path.is_file():
                try:
                    import json
                    with open(cg_path, 'r') as f:
                        callgraph = json.load(f)
                    self._local_callgraph_cache[binary_name] = callgraph
                    self._cache_access_times[binary_name] = time.time()
                    self.logger.info(f"Loaded callgraph for {binary_name} from disk ({cg_path.name})")
                    return callgraph
                except Exception as e:
                    self.logger.warning(f"Failed to load callgraph from {cg_path}: {e}")
        
        return None
    
    def _cleanup_local_cache(self, max_age_seconds: float = 1800.0) -> None:
        """Remove stale entries from local cache."""
        current_time = time.time()
        stale = [
            binary_name for binary_name, access_time in self._cache_access_times.items()
            if current_time - access_time > max_age_seconds
        ]
        for binary_name in stale:
            self._local_callgraph_cache.pop(binary_name, None)
            self._cache_access_times.pop(binary_name, None)
    
    def _run(self) -> None:
        """Main execution loop."""
        # Track consecutive empty-queue timeouts after all_posters_done is set.
        # Multiprocessing queues have internal buffering latency, so a single
        # Empty timeout is not reliable evidence that the queue is truly drained.
        _empty_retries_after_done = 0
        _MAX_EMPTY_RETRIES = 10
        
        if self.shared_stats:
            self.shared_stats.set_runner_state(self.worker_id, WORKER_STATE_IDLE)
            
        while not self._exit_condition_reached():
            try:
                task_payload = self.queue_manager.task_queue.get(timeout=1.0)
                # Successfully got a task; reset the retry counter
                _empty_retries_after_done = 0
            except Empty:
                if self._shutdown_requested():
                    self.logger.debug("Shutdown requested while waiting for task; exiting loop")
                    break
                if self.queue_manager.all_posters_done.is_set():
                    # Multiprocessing queues can have small delays between qsize() and get()
                    # We check and also use a retry counter to be 100% sure items are gone.
                    actual_qsize = 0
                    try:
                        actual_qsize = self.queue_manager.task_queue.qsize()
                    except Exception:
                        pass

                    if actual_qsize == 0:
                        _empty_retries_after_done += 1
                        if _empty_retries_after_done >= _MAX_EMPTY_RETRIES:
                            self.logger.debug(
                                "All posters done and queue empty after %d retries; exiting loop",
                                _empty_retries_after_done,
                            )
                            break
                    else:
                        # Queue not actually empty; reset retries and continue trying to get()
                        _empty_retries_after_done = 0
                        continue
                    # Queue may still have items in transit or OS buffer; retry
                    continue
                continue
            
            if not isinstance(task_payload, list):
                task_batch = [task_payload]
            else:
                task_batch = task_payload
                
            if self.shared_stats:
                self.shared_stats.set_runner_state(self.worker_id, WORKER_STATE_WORKING)
                
            result_batch: list[ResultWrapper] = []
            
            for task_wrapper in task_batch:
                # Check for interrupt during large batches
                if self._shutdown_requested():
                    self.logger.debug("Shutdown requested inside batch; breaking early.")
                    break
                    
                # Inject call graph getter into CCBHashTask if needed
                if isinstance(task_wrapper.task, CCBHashTask):
                    if task_wrapper.task.callgraph_getter is None:
                        task_wrapper.task.callgraph_getter = self._get_callgraph
                    if getattr(task_wrapper.task, "binary_name", None) is None:
                        task_wrapper.task.binary_name = getattr(task_wrapper, "binary_name", None)
                
                # Periodic cache cleanup (every N tasks or time-based)
                if self.n_completed > 0 and self.n_completed % 100 == 0:
                    self._cleanup_local_cache()
                
                # Execute the task
                with binary_log_context(getattr(task_wrapper, "binary_name", None)):
                    try:
                        start_time = time.perf_counter()
                        success = task_wrapper.execute_task()
                        duration = time.perf_counter() - start_time
                        if success:
                            self.n_completed += 1
                            # If it was skipped because of a checkpoint or missing data, don't count the duration
                            if task_wrapper.result.success and self.shared_stats is not None:
                                # Get task type from task class
                                task_type = TASK_KEYS.get(type(task_wrapper.task))
                                if duration > 5.0:
                                    self.logger.warning(f"Slow task: {task_type} for 0x{task_wrapper.func_addr:x} took {duration:.2f}s")
                                self.shared_stats.record_task_success(duration, task_type=task_type)
                                self.shared_stats.increment_runner_tasks(self.worker_id)
                                task_bin_name = getattr(task_wrapper, "binary_name", None)
                                if task_bin_name:
                                    self.shared_stats.increment_binary_done(task_bin_name)
                        else:
                            self.n_failed += 1
                            if self.shared_stats is not None:
                                self.shared_stats.record_task_failure()
                        
                        # Accumulate result for the collector
                        result_wrapper = task_wrapper.get_result_wrapper()
                        result_batch.append(result_wrapper)
                        
                    except Exception as e:
                        self.logger.exception(
                            f"Unexpected error executing task for function "
                            f"{hex(task_wrapper.func_addr)}: {e}"
                        )
                        self.n_failed += 1
                        if self.shared_stats is not None:
                            self.shared_stats.record_task_failure()
            
            # Submit batch to result queue
            if result_batch:
                max_put_attempts = 120
                attempts = 0
                put_timeout = 0.5
                while True:
                    try:
                        self.queue_manager.result_queue.put(result_batch, timeout=put_timeout)
                        break
                    except Full:
                        attempts += 1
                        if self.queue_manager.collector_shutdown.is_set():
                            self.logger.warning(
                                "Collector shutdown detected while result queue full; dropping result batch"
                            )
                            break
                        if self._shutdown_requested():
                            self.logger.debug(
                                "Shutdown requested while waiting to enqueue result batch; aborting put"
                            )
                            break
                            self.logger.warning(
                                f"Result queue still full after {attempts * put_timeout:.1f}s; dropping batch"
                            )
                            break
            
            if self.shared_stats:
                self.shared_stats.set_runner_state(self.worker_id, WORKER_STATE_IDLE)
                
        self.logger.info(f"Reached exit condition")

    def run(self) -> dict:
        """Run the task runner and return statistics."""
        self.logger.info(f"Started")
        
        try:
            self._run()
        except Exception as e:
            self.logger.exception(f"Unexpected error in runner loop: {e}")
        finally:
            if self.shared_stats:
                self.shared_stats.set_runner_state(self.worker_id, WORKER_STATE_STOPPED)
            self.stopped_event.set()
            self.logger.info(f"Shutting down. "
                             f"Completed: {self.n_completed}, "
                             f"Failed: {self.n_failed}")
        
        return {"completed": self.n_completed, "failed": self.n_failed}


class ResultCollector:
    """
    Collects results from queue and writes to CSV files.
    Uses LRU caching to manage file handles efficiently.
    """
    
    def __init__(self, queue_manager: QueueManager, max_open_files: int = 50,
                 shared_stats: Optional[SharedStats] = None):
        self.queue_manager = queue_manager
        self.max_open_files = max_open_files
        self.shared_stats = shared_stats
        
        # Track initialized files
        self.initialized_files: set[Path] = set()
        
        # LRU cache for file handles
        self.file_cache: dict[Path, tuple[Any, Any]] = {}
        self.file_access_order: list[Path] = []
        
        # Statistics
        self.n_results_written = 0
        self.n_errors_logged = 0
        self.n_skips_logged = 0

        # Track skip entries to avoid duplicates (per skip file)
        self._skip_records: dict[Path, set[int]] = {}
    
    @property
    def logger(self) -> logging.Logger:
        return get_logger("ResultCollector")
    
    def get_writer(self, output_path: Path):
        """Get CSV writer with LRU caching."""
        if output_path in self.file_cache:
            # Move to end (most recently used)
            self.file_access_order.remove(output_path)
            self.file_access_order.append(output_path)
            return self.file_cache[output_path][1]
        
        # Need to open new file
        if len(self.file_cache) >= self.max_open_files:
            # Close least recently used
            lru_path = self.file_access_order.pop(0)
            handle, _ = self.file_cache.pop(lru_path)
            handle.flush()
            handle.close()
            self.logger.debug(f"Closed LRU file: {lru_path.name}")
        
        # Open file in append mode
        mode = 'a' if output_path.exists() else 'w'
        handle = open(output_path, mode, newline='', buffering=8192)
        writer = csv.writer(handle)
        
        self.file_cache[output_path] = (handle, writer)
        self.file_access_order.append(output_path)
        self.logger.debug(f"Opened file: {output_path.name} (mode: {mode})")
        
        return writer
    
    def write_result(self, result_wrapper: ResultWrapper) -> None:
        """Write single result to CSV."""
        result = result_wrapper.result
        output_path = result_wrapper.output_path
        binary_name = getattr(result_wrapper, "binary_name", None)
        
        with binary_log_context(binary_name):
            # Initialize file with headers if needed
            if output_path not in self.initialized_files:
                if not output_path.exists() or output_path.stat().st_size == 0:
                    writer = self.get_writer(output_path)
                    writer.writerow(result.csv_headers())
                    self.logger.info(f"Initialized CSV: {output_path.name}")
                self.initialized_files.add(output_path)
            
            # Write result or error
            if result.success:
                writer = self.get_writer(output_path)
                writer.writerow(result.to_csv_row())
                self.n_results_written += 1
                if self.shared_stats is not None:
                    self.shared_stats.increment_results_written()
            else:
                # Write to error log
                error_path = output_path.with_name(
                    output_path.stem + "_errors.csv"
                )
                
                if error_path not in self.initialized_files:
                    if not error_path.exists() or error_path.stat().st_size == 0:
                        writer = self.get_writer(error_path)
                        writer.writerow(["func_addr", "error_type", "error_message"])
                        self.logger.info(f"Initialized error log: {error_path.name}")
                    self.initialized_files.add(error_path)
                
                writer = self.get_writer(error_path)
                writer.writerow([
                    f"{result.func_addr:x}",
                    type(result.error).__name__ if result.error else "Unknown",
                    str(result.error) if result.error else "Task failed"
                ])
                self.n_errors_logged += 1
                if self.shared_stats is not None:
                    self.shared_stats.increment_result_errors()
    
    def write_skip(self, skip_info: SkipInfo) -> None:
        """Write skip information to skipped CSV."""
        binary_name = getattr(skip_info, "binary_name", None)
        # Construct skip file path: binary-name_task-type.skipped.csv
        skip_stem = skip_info.output_path.stem  # "mips32-clang-7-Os_z3_ccbhash"
        skip_path = skip_info.output_path.with_name(f"{skip_stem}.skipped.csv")
        
        with binary_log_context(binary_name):
            recorded_addrs = self._skip_records.setdefault(skip_path, set())
            if skip_info.func_addr in recorded_addrs:
                self.logger.debug(
                    "Skip already recorded for %s @ %s; ignoring duplicate",
                    skip_info.task_type,
                    f"0x{skip_info.func_addr:x}",
                )
                return

            # Initialize file with headers if needed
            if skip_path not in self.initialized_files:
                if not skip_path.exists() or skip_path.stat().st_size == 0:
                    writer = self.get_writer(skip_path)
                    writer.writerow(SkipInfo.csv_headers())
                    self.logger.info(f"Initialized skip log: {skip_path.name}")
                self.initialized_files.add(skip_path)
            
            # Write skip record
            writer = self.get_writer(skip_path)
            writer.writerow(skip_info.to_csv_row())
            recorded_addrs.add(skip_info.func_addr)
            self.n_skips_logged += 1
            if self.shared_stats is not None:
                self.shared_stats.increment_skips_logged()
    
    def cleanup(self) -> None:
        """Close all open file handles."""
        for handle, _ in self.file_cache.values():
            handle.flush()
            handle.close()
        self.file_cache.clear()
        self.logger.info("All file handles closed")
        
    def _exit_condition_reached(self) -> bool:
        return self.queue_manager.collector_shutdown.is_set() or (
            self.queue_manager.result_queue.empty()
        )
    
    def _run(self) -> None:
        """Main collection loop."""
        if self.shared_stats:
            self.shared_stats.set_collector_state(WORKER_STATE_IDLE)
            
        # Main loop
        shutdown_signaled = False
        while True:
            # Check if we should shutdown (but finish remaining results first)
            if self.queue_manager.collector_shutdown.is_set():
                if not shutdown_signaled:
                    self.logger.info("Shutdown signal received. Draining remaining results from queue...")
                    shutdown_signaled = True
                # Try to get any remaining results with a short timeout
                try:
                    item = self.queue_manager.result_queue.get(timeout=0.5)
                    if self.shared_stats:
                        self.shared_stats.set_collector_state(WORKER_STATE_WORKING)
                except Empty:
                    # Queue is empty and shutdown signaled, we're done
                    self.logger.info("Result queue empty. Shutting down.")
                    break
            else:
                # Normal operation: wait longer for results
                try:
                    item = self.queue_manager.result_queue.get(timeout=1)
                    if self.shared_stats:
                        self.shared_stats.set_collector_state(WORKER_STATE_WORKING)
                except Empty:
                    if self.shared_stats:
                        self.shared_stats.set_collector_state(WORKER_STATE_IDLE)
                    continue
            
            try:
                # Handle lists of ResultWrappers or SkipInfos
                if not isinstance(item, list):
                    item_batch = [item]
                else:
                    item_batch = item
                    
                for single_item in item_batch:
                    if self.queue_manager.all_runners_shutdown.is_set():
                        self.logger.info("Hard shutdown requested; breaking batch early.")
                        break
                        
                    if isinstance(single_item, SkipInfo):
                        self.write_skip(single_item)
                    elif isinstance(single_item, ResultWrapper):
                        self.write_result(single_item)
                    else:
                        raise NotImplementedError(
                            f"Unknown item type: {type(single_item)}")
            except Exception as e:
                self.logger.exception(f"Error writing item: {e}")
                self.n_errors_logged += 1
                if self.shared_stats is not None:
                    self.shared_stats.increment_result_errors()
    
    def run(self) -> dict:
        """Run the result collector and return statistics."""
        self.logger.info("ResultCollector started")
        
        try:
            self._run()
        except Exception as e:
            self.logger.exception(f"Fatal error in result collector: {e}")
        finally:
            if self.shared_stats:
                self.shared_stats.set_collector_state(WORKER_STATE_STOPPED)
            self.cleanup()
            self.logger.info(f"ResultCollector shutting down. "
                           f"Results written: {self.n_results_written}, "
                           f"Errors: {self.n_errors_logged}, "
                           f"Skips: {self.n_skips_logged}")
        
        return {"results_written": self.n_results_written, 
                "errors_logged": self.n_errors_logged,
                "skips_logged": self.n_skips_logged}


# Poster worker orchestration -------------------------------------------------

# Process wrapper functions for multiprocessing

def run_task_runner(
    worker_id: int,
    queue_manager: QueueManager,
    log_queue: Queue,
    shared_stats: Optional[SharedStats] = None,
    raw_data_dir: Optional[Path] = None,
) -> dict:
    """Process function wrapper for TaskRunner."""
    setup_worker_logging(log_queue)
    runner = TaskRunner(worker_id, queue_manager, shared_stats, raw_data_dir)
    return runner.run()


