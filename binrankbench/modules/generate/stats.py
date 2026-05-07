"""Shared statistics structures for the binrankbench.modules.generate pipeline.

This module exposes an efficient, multiprocessing-friendly container that
collects counters, timers, and coordination signals used by the terminal
dashboard.  The implementation relies on ``multiprocessing.Value`` and
``multiprocessing.Array`` primitives to minimise overhead while allowing all
worker processes to update the shared state atomically.
"""

from __future__ import annotations

import ctypes
import time
from collections import deque
from dataclasses import dataclass, asdict
from multiprocessing import Array, Event, Lock, Manager, Value
from typing import Any, Dict, List


# Worker state constants
WORKER_STATE_STOPPED = 0
WORKER_STATE_IDLE = 1
WORKER_STATE_WORKING = 2

@dataclass(frozen=True)
class StatsSnapshot:
    """Immutable view of the current statistics.

    The snapshot is designed to be JSON-serialisable and easy to render in the
    dashboard layer.  All numeric values are provided as plain ``int`` or
    ``float`` instances to avoid leaking the underlying shared-memory types.
    """

    total_binaries: int
    completed_binaries: int
    skipped_binaries: int
    task_groups_expected: int
    task_groups_posted: int
    task_groups_skipped: int
    tasks_succeeded: int
    tasks_failed: int
    results_written: int
    result_errors: int
    skips_logged: int
    poster_task_groups: List[int]
    runner_tasks_completed: List[int]
    poster_states: List[int]
    runner_states: List[int]
    collector_state: int
    task_type_stats: dict[str, dict[str, float]]  # task_type -> {count, total_time, avg_time}
    task_type_sliding_averages: dict[str, dict[str, Any]]  # task_type -> {average, window_size, sample_count}
    binary_progress: dict[str, dict[str, int]]  # binary_name -> {expected, posted}
    task_queue_size: int
    result_queue_size: int
    binary_queue_size: int
    average_task_seconds: float
    total_success_task_time: float
    elapsed_seconds: float
    forced_shutdown_requested: bool

    def as_dict(self) -> Dict[str, Any]:
        """Return the snapshot as a plain dictionary."""

        return asdict(self)


class SharedStats:
    """Thread- and process-safe counters for pipeline monitoring."""

    @staticmethod
    def _get_variant_task_types() -> list[str]:
        return []

    def __init__(self, n_posters: int, n_runners: int) -> None:
        self._n_posters = n_posters
        self._n_runners = n_runners

        # Timing
        self._start_time_wall = time.time()
        self._start_time_monotonic = time.monotonic()

        # Binary progress counters
        self.total_binaries = Value(ctypes.c_longlong, 0, lock=True)
        self.completed_binaries = Value(ctypes.c_longlong, 0, lock=True)
        self.skipped_binaries = Value(ctypes.c_longlong, 0, lock=True)

        # Task group posting statistics
        self.task_groups_expected = Value(ctypes.c_longlong, 0, lock=True)
        self.task_groups_posted = Value(ctypes.c_longlong, 0, lock=True)
        self.task_groups_skipped = Value(ctypes.c_longlong, 0, lock=True)

        # Task execution statistics (TaskRunner workers)
        self.tasks_succeeded = Value(ctypes.c_longlong, 0, lock=True)
        self.tasks_failed = Value(ctypes.c_longlong, 0, lock=True)
        self.success_task_time = Value(ctypes.c_double, 0.0, lock=True)

        # Result collector statistics
        self.results_written = Value(ctypes.c_longlong, 0, lock=True)
        self.result_errors = Value(ctypes.c_longlong, 0, lock=True)
        self.skips_logged = Value(ctypes.c_longlong, 0, lock=True)

        # Queue depth tracking (updated periodically by coordinator thread)
        self.task_queue_size = Value(ctypes.c_longlong, 0, lock=True)
        self.result_queue_size = Value(ctypes.c_longlong, 0, lock=True)
        self.binary_queue_size = Value(ctypes.c_longlong, 0, lock=True)

        # Per-poster statistics (number of task groups posted)
        if n_posters > 0:
            self.poster_task_groups = Array(ctypes.c_longlong, n_posters, lock=True)
        else:
            self.poster_task_groups = None
        
        # Per-runner statistics (number of successful tasks completed)
        if n_runners > 0:
            self.runner_tasks_completed = Array(ctypes.c_longlong, n_runners, lock=True)
        else:
            self.runner_tasks_completed = None
            
        # Worker states (0=Stopped, 1=Idle, 2=Working)
        if n_posters > 0:
            self.poster_states = Array('i', n_posters, lock=True)
        else:
            self.poster_states = None
            
        if n_runners > 0:
            self.runner_states = Array('i', n_runners, lock=True)
        else:
            self.runner_states = None
            
        # Collector state
        self.collector_state = Value('i', WORKER_STATE_IDLE, lock=True)
        
        # Task type statistics: track count and total time per task type
        # Using a dict with locks for each task type
        self._task_type_data: dict[str, Any] = {}  # Dict[str, tuple[Value, Value]]
        self._task_type_lock = Lock()
        # Initialize for known task types (base + variant tasks)
        base_task_types = ["machoke", "cfehash", "ccbhash", "ccbhash_cfe", "catalog1", "bytes", "function_details", "fss"]
        variant_task_types = self._get_variant_task_types()
        all_task_types = base_task_types + variant_task_types
        for task_type in all_task_types:
            self._task_type_data[task_type] = (
                Value(ctypes.c_longlong, 0, lock=True),  # count
                Value(ctypes.c_double, 0.0, lock=True),   # total_time
            )

        # Per-binary progress tracking (functions expected and posted per binary)
        manager = Manager()
        self._binary_progress: Any = manager.dict()  # binary_name -> {expected, posted} (DictProxy)
        self._binary_progress_lock = Lock()

        # Sliding window averages for task processing times
        # Use Manager().list() for process-safe sliding windows
        # Note: Manager lists don't support maxlen, so we manually enforce window size
        self._sliding_windows: dict[str, Any] = {}  # Dict[str, ListProxy] - Manager list
        self._sliding_window_lock = Lock()
        self._sliding_window_size = 100  # Default window size (configurable in future)
        # Initialize sliding windows for all task types using Manager lists
        for task_type in all_task_types:
            self._sliding_windows[task_type] = manager.list()
        # Cache for sliding averages to avoid recalculating on every access
        self._sliding_average_cache: dict[str, float] = {}
        self._sliding_average_cache_valid: dict[str, bool] = {
            task_type: False for task_type in all_task_types
        }

        # Shutdown coordination (force shutdown only)
        self.forced_shutdown = Event()

        # Auxiliary lock used for compound updates (e.g. task timings)
        self._avg_lock = Lock()

    # ------------------------------------------------------------------
    # Binary counters

    def set_total_binaries(self, total: int) -> None:
        with self.total_binaries.get_lock():
            self.total_binaries.value = total

    def increment_completed_binaries(self, delta: int = 1) -> None:
        if delta <= 0:
            return
        with self.completed_binaries.get_lock():
            self.completed_binaries.value += delta

    def increment_skipped_binaries(self, delta: int = 1) -> None:
        if delta <= 0:
            return
        with self.skipped_binaries.get_lock():
            self.skipped_binaries.value += delta

    # ------------------------------------------------------------------
    # Task posting statistics

    def increment_task_groups_expected(self, delta: int) -> None:
        if delta <= 0:
            return
        with self.task_groups_expected.get_lock():
            self.task_groups_expected.value += delta

    def increment_task_groups_posted(self, delta: int, poster_id: int | None = None, binary_name: str | None = None) -> None:
        if delta <= 0:
            return
        with self.task_groups_posted.get_lock():
            self.task_groups_posted.value += delta

        if poster_id is not None and self.poster_task_groups is not None:
            if 0 <= poster_id < self._n_posters:
                with self.poster_task_groups.get_lock():
                    self.poster_task_groups[poster_id] += delta
        
        # Track per-binary progress
        if binary_name:
            with self._binary_progress_lock:
                binary_dict = self._binary_progress.get(binary_name, {"expected": 0, "posted": 0, "done": 0})
                binary_dict["posted"] += delta
                self._binary_progress[binary_name] = binary_dict
    
    def set_binary_expected(self, binary_name: str, expected: int) -> None:
        """Set the expected number of task groups for a binary."""
        with self._binary_progress_lock:
            binary_dict = self._binary_progress.get(binary_name, {"expected": 0, "posted": 0, "done": 0})
            binary_dict["expected"] = expected
            self._binary_progress[binary_name] = binary_dict
    
    def increment_binary_expected(self, binary_name: str, delta: int) -> None:
        """Increment the expected number of task groups for a binary."""
        if delta <= 0:
            return
        with self._binary_progress_lock:
            binary_dict = self._binary_progress.get(binary_name, {"expected": 0, "posted": 0, "done": 0})
            binary_dict["expected"] += delta
            self._binary_progress[binary_name] = binary_dict

    def increment_binary_done(self, binary_name: str, delta: int = 1) -> None:
        """Increment the number of completed task groups for a binary."""
        if delta <= 0 or not binary_name:
            return
        with self._binary_progress_lock:
            binary_dict = self._binary_progress.get(binary_name, {"expected": 0, "posted": 0, "done": 0})
            binary_dict["done"] += delta
            self._binary_progress[binary_name] = binary_dict

    def increment_task_groups_skipped(self, delta: int) -> None:
        if delta <= 0:
            return
        with self.task_groups_skipped.get_lock():
            self.task_groups_skipped.value += delta

    # ------------------------------------------------------------------
    # Task execution statistics

    def record_task_success(self, duration_seconds: float | None, task_type: str | None = None) -> None:
        with self.tasks_succeeded.get_lock():
            self.tasks_succeeded.value += 1

        if duration_seconds is None:
            return

        with self._avg_lock:
            with self.success_task_time.get_lock():
                self.success_task_time.value += float(duration_seconds)
        
        # Record task type statistics
        if task_type and task_type in self._task_type_data:
            count_val, time_val = self._task_type_data[task_type]
            with count_val.get_lock():
                count_val.value += 1
            with time_val.get_lock():
                time_val.value += float(duration_seconds)
            
            # Record in sliding window for this task type
            self.record_task_time_sliding(task_type, float(duration_seconds))

    def record_task_failure(self) -> None:
        with self.tasks_failed.get_lock():
            self.tasks_failed.value += 1
    
    def record_task_time_sliding(self, task_type: str, duration: float) -> None:
        """
        Record a task processing time in the sliding window for the given task type.
        
        Args:
            task_type: Type of task (e.g., "machoke", "ccbhash")
            duration: Task processing time in seconds
        """
        if task_type not in self._sliding_windows:
            return
        
        # Manager lists are process-safe, but we still need a lock for atomic operations
        # Note: Manager lists don't support maxlen, so we manually enforce window size
        with self._sliding_window_lock:
            window = self._sliding_windows[task_type]
            window.append(duration)
            # Enforce maxlen by removing oldest items if window exceeds size
            while len(window) > self._sliding_window_size:
                window.pop(0)  # Remove oldest item
            # Invalidate cache for this task type
            self._sliding_average_cache_valid[task_type] = False
    
    def get_sliding_average(self, task_type: str) -> float | None:
        """
        Get the sliding window average for a task type.
        
        Args:
            task_type: Type of task (e.g., "machoke", "ccbhash")
            
        Returns:
            Average processing time in seconds, or None if window is empty
        """
        if task_type not in self._sliding_windows:
            return None
        
        # Acquire lock for reading (Manager lists are process-safe but we need consistency)
        with self._sliding_window_lock:
            window = self._sliding_windows[task_type]
            window_len = len(window)
            if window_len == 0:
                return None
            
            # Check cache first
            if self._sliding_average_cache_valid.get(task_type, False):
                cached = self._sliding_average_cache.get(task_type)
                if cached is not None:
                    return cached
            
            # Calculate average
            avg = sum(window) / window_len
            # Update cache
            self._sliding_average_cache[task_type] = avg
            self._sliding_average_cache_valid[task_type] = True
            return avg
    
    def get_sliding_window_info(self, task_type: str) -> dict[str, Any] | None:
        """
        Get detailed sliding window information for a task type.
        
        Args:
            task_type: Type of task (e.g., "machoke", "ccbhash")
            
        Returns:
            Dictionary with 'average', 'window_size', 'sample_count', or None if window is empty
        """
        if task_type not in self._sliding_windows:
            return None
        
        with self._sliding_window_lock:
            window = self._sliding_windows[task_type]
            window_len = len(window)
            if window_len == 0:
                return None
            
            # Calculate average directly (don't call get_sliding_average to avoid lock issues)
            # Check cache first
            if self._sliding_average_cache_valid.get(task_type, False):
                cached_avg = self._sliding_average_cache.get(task_type)
                if cached_avg is not None:
                    avg = cached_avg
                else:
                    avg = sum(window) / window_len
                    self._sliding_average_cache[task_type] = avg
                    self._sliding_average_cache_valid[task_type] = True
            else:
                # Calculate average
                avg = sum(window) / window_len
                # Update cache
                self._sliding_average_cache[task_type] = avg
                self._sliding_average_cache_valid[task_type] = True
            
            return {
                "average": avg,
                "window_size": self._sliding_window_size,
                "sample_count": window_len,
            }
    
    def increment_runner_tasks(self, runner_id: int, delta: int = 1) -> None:
        """
        Increment the task count for a specific runner.
        
        Only successful tasks should be counted (not failures or skips).
        
        Args:
            runner_id: ID of the runner (0-indexed)
            delta: Number of tasks to add (default: 1)
        """
        if delta <= 0:
            return
        if self.runner_tasks_completed is None:
            return
        if 0 <= runner_id < self._n_runners:
            with self.runner_tasks_completed.get_lock():
                self.runner_tasks_completed[runner_id] += delta

    def set_poster_state(self, poster_id: int, state: int) -> None:
        """Set the state (Stopped/Idle/Working) for a specific poster."""
        if self.poster_states is None:
            return
        if 0 <= poster_id < self._n_posters:
            with self.poster_states.get_lock():
                self.poster_states[poster_id] = state

    def set_runner_state(self, runner_id: int, state: int) -> None:
        """Set the state (Stopped/Idle/Working) for a specific runner."""
        if self.runner_states is None:
            return
        if 0 <= runner_id < self._n_runners:
            with self.runner_states.get_lock():
                self.runner_states[runner_id] = state

    def set_collector_state(self, state: int) -> None:
        """Set the state (Stopped/Idle/Working) for the collector."""
        with self.collector_state.get_lock():
            self.collector_state.value = state

    # ------------------------------------------------------------------
    # Result collector statistics

    def increment_results_written(self, delta: int = 1) -> None:
        if delta <= 0:
            return
        with self.results_written.get_lock():
            self.results_written.value += delta

    def increment_result_errors(self, delta: int = 1) -> None:
        if delta <= 0:
            return
        with self.result_errors.get_lock():
            self.result_errors.value += delta

    def increment_skips_logged(self, delta: int = 1) -> None:
        if delta <= 0:
            return
        with self.skips_logged.get_lock():
            self.skips_logged.value += delta

    # ------------------------------------------------------------------
    # Queue depths

    def update_queue_sizes(self, *, task: int | None = None, result: int | None = None, binary: int | None = None) -> None:
        if task is not None:
            with self.task_queue_size.get_lock():
                self.task_queue_size.value = max(task, 0)
        if result is not None:
            with self.result_queue_size.get_lock():
                self.result_queue_size.value = max(result, 0)
        if binary is not None:
            with self.binary_queue_size.get_lock():
                self.binary_queue_size.value = max(binary, 0)

    # ------------------------------------------------------------------
    # Shutdown coordination

    def request_forced_shutdown(self) -> None:
        """Request immediate force shutdown of all processes."""
        self.forced_shutdown.set()

    def clear_forced_shutdown(self) -> None:
        """Clear force shutdown flag (for testing/recovery)."""
        self.forced_shutdown.clear()

    # ------------------------------------------------------------------
    # Snapshot helpers

    def _copy_poster_counts(self) -> List[int]:
        if self.poster_task_groups is None:
            return []
        with self.poster_task_groups.get_lock():
            return list(self.poster_task_groups[:])
    
    def _copy_runner_counts(self) -> List[int]:
        """Copy runner task completion counts."""
        if self.runner_tasks_completed is None:
            return []
        with self.runner_tasks_completed.get_lock():
            return list(self.runner_tasks_completed[:])

    def _copy_poster_states(self) -> List[int]:
        if self.poster_states is None:
            return []
        with self.poster_states.get_lock():
            return list(self.poster_states[:])
            
    def _copy_runner_states(self) -> List[int]:
        if self.runner_states is None:
            return []
        with self.runner_states.get_lock():
            return list(self.runner_states[:])

    def get_elapsed_seconds(self) -> float:
        return time.monotonic() - self._start_time_monotonic

    def get_snapshot(self) -> StatsSnapshot:
        with self.total_binaries.get_lock():
            total_binaries = int(self.total_binaries.value)
        with self.completed_binaries.get_lock():
            completed_binaries = int(self.completed_binaries.value)
        with self.skipped_binaries.get_lock():
            skipped_binaries = int(self.skipped_binaries.value)

        with self.task_groups_expected.get_lock():
            expected = int(self.task_groups_expected.value)
        with self.task_groups_posted.get_lock():
            posted = int(self.task_groups_posted.value)
        with self.task_groups_skipped.get_lock():
            skipped_groups = int(self.task_groups_skipped.value)

        with self.tasks_succeeded.get_lock():
            tasks_succeeded = int(self.tasks_succeeded.value)
        with self.tasks_failed.get_lock():
            tasks_failed = int(self.tasks_failed.value)
        with self.success_task_time.get_lock():
            total_success_time = float(self.success_task_time.value)

        with self.results_written.get_lock():
            results_written = int(self.results_written.value)
        with self.result_errors.get_lock():
            result_errors = int(self.result_errors.value)
        with self.skips_logged.get_lock():
            skips_logged = int(self.skips_logged.value)

        with self.task_queue_size.get_lock():
            task_queue_size = int(self.task_queue_size.value)
        with self.result_queue_size.get_lock():
            result_queue_size = int(self.result_queue_size.value)
        with self.binary_queue_size.get_lock():
            binary_queue_size = int(self.binary_queue_size.value)

        poster_counts = self._copy_poster_counts()
        runner_counts = self._copy_runner_counts()
        poster_states = self._copy_poster_states()
        runner_states = self._copy_runner_states()
        with self.collector_state.get_lock():
            collector_state = int(self.collector_state.value)
        
        # Copy task type statistics
        task_type_stats: dict[str, dict[str, float]] = {}
        with self._task_type_lock:
            for task_type, (count_val, time_val) in self._task_type_data.items():
                with count_val.get_lock():
                    count = int(count_val.value)
                with time_val.get_lock():
                    total_time = float(time_val.value)
                if count > 0:
                    task_type_stats[task_type] = {
                        "count": float(count),
                        "total_time": total_time,
                        "avg_time": total_time / count,
                    }
        
        # Copy sliding window averages with detailed information
        # If sliding window is empty but all-time stats exist, use all-time as fallback
        task_type_sliding_averages: dict[str, dict[str, Any]] = {}
        base_task_types = ["machoke", "cfehash", "ccbhash", "ccbhash_cfe", "catalog1", "bytes", "function_details", "fss"]
        all_task_types = base_task_types + self._get_variant_task_types()
        for task_type in all_task_types:
            info = self.get_sliding_window_info(task_type)
            if info is not None:
                task_type_sliding_averages[task_type] = info
        
        # Copy binary progress statistics
        binary_progress: dict[str, dict[str, int]] = {}
        with self._binary_progress_lock:
            for binary_name, progress_dict in self._binary_progress.items():
                # Convert Manager dict (DictProxy) to regular dict
                binary_progress[binary_name] = {
                    "expected": int(progress_dict.get("expected", 0)),
                    "posted": int(progress_dict.get("posted", 0)),
                    "done": int(progress_dict.get("done", 0)),
                }

        # Derive average processing time (successes only)
        avg_time = total_success_time / tasks_succeeded if tasks_succeeded else 0.0

        return StatsSnapshot(
            total_binaries=total_binaries,
            completed_binaries=completed_binaries,
            skipped_binaries=skipped_binaries,
            task_groups_expected=expected,
            task_groups_posted=posted,
            task_groups_skipped=skipped_groups,
            tasks_succeeded=tasks_succeeded,
            tasks_failed=tasks_failed,
            results_written=results_written,
            result_errors=result_errors,
            skips_logged=skips_logged,
            poster_task_groups=poster_counts,
            runner_tasks_completed=runner_counts,
            poster_states=poster_states,
            runner_states=runner_states,
            collector_state=collector_state,
            task_type_stats=task_type_stats,
            task_type_sliding_averages=task_type_sliding_averages,
            binary_progress=binary_progress,
            task_queue_size=task_queue_size,
            result_queue_size=result_queue_size,
            binary_queue_size=binary_queue_size,
            average_task_seconds=avg_time,
            total_success_task_time=total_success_time,
            elapsed_seconds=self.get_elapsed_seconds(),
            forced_shutdown_requested=self.forced_shutdown.is_set(),
        )

    # ------------------------------------------------------------------
    # Convenience helpers

    @property
    def start_time(self) -> float:
        """Return the wall-clock start time for this run (UTC timestamp)."""

        return self._start_time_wall

    @property
    def n_posters(self) -> int:
        return self._n_posters

    @property
    def n_runners(self) -> int:
        return self._n_runners

    @property
    def forced_shutdown_requested(self) -> bool:
        """Check if force shutdown has been requested."""
        return self.forced_shutdown.is_set()


