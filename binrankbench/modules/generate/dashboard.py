"""Terminal dashboard implementation for the binrankbench.modules.generate pipeline."""

from __future__ import annotations

import math
import select
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from queue import Empty
from typing import Iterable, List, Optional
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table
from rich.text import Text

from binrankbench.modules.generate.stats import SharedStats, StatsSnapshot

try:  # pragma: no cover - platform dependent
    import termios  # type: ignore
    import tty  # type: ignore
except ImportError:  # pragma: no cover - Windows fallback
    termios = None  # type: ignore
    tty = None  # type: ignore

try:  # Python 3.12+: typing module provides TypedDict etc. We only need TYPE_CHECKING.
    from typing import TYPE_CHECKING
except ImportError:  # pragma: no cover - Python <3.8 not supported
    TYPE_CHECKING = False  # type: ignore

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from multiprocessing import Queue
    from binrankbench.modules.generate.worker import QueueManager


# ---------------------------------------------------------------------------
# Log capture utilities


@dataclass(frozen=True)
class DashboardLogMessage:
    """Simple serialisable message used to feed the dashboard log panel."""

    created: float
    levelno: int
    levelname: str
    name: str
    message: str


class DashboardLogBuffer:
    """Thread-safe ring buffer storing recent log messages."""

    def __init__(self, capacity: int = 400) -> None:
        self._capacity = capacity
        self._buffer: List[DashboardLogMessage] = []
        self._lock = threading.Lock()

    def extend(self, messages: Iterable[DashboardLogMessage]) -> None:
        with self._lock:
            for message in messages:
                self._buffer.append(message)
                overflow = len(self._buffer) - self._capacity
                if overflow > 0:
                    del self._buffer[:overflow]

    def snapshot(self, limit: int) -> List[DashboardLogMessage]:
        with self._lock:
            if limit <= 0:
                return []
            return self._buffer[-limit:]


# ---------------------------------------------------------------------------
# Formatting helpers


LEVEL_COLOURS = {
    "DEBUG": "dim",
    "INFO": "cyan",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}


def format_time_hms(timestamp: float) -> str:
    """Format a UNIX timestamp as HH:MM:SS (local time)."""

    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")


def format_duration(seconds: float) -> str:
    """Return a human-readable duration string."""

    if math.isnan(seconds) or seconds < 0:
        return "--"
    if seconds < 1e-3:
        return "0 ms"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {remainder:04.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m"


def format_task_time(seconds: float) -> str:
    """
    Format task time showing rate if > 1/sec, duration if < 1/sec.
    
    Examples:
        - 0.4 seconds -> "2.5/s" (2.5 tasks per second)
        - 2.4 seconds -> "2.4s" (takes 2.4 seconds per task)
    """
    if math.isnan(seconds) or seconds < 0:
        return "--"
    if seconds <= 0:
        return "--"
    
    rate = 1.0 / seconds  # tasks per second
    if rate >= 1.0:
        # Show as rate: 2.5/s
        return f"{rate:.1f}/s"
    else:
        # Show as duration: 2.4s
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        return f"{seconds:.1f}s"


def safe_progress_total(total: int, completed: int) -> int:
    """Ensure a non-zero total for progress bars."""

    if total > 0:
        return total
    if completed > 0:
        return completed
    return 1


# ---------------------------------------------------------------------------
# Dashboard implementation


class Dashboard:
    """Rich-based live dashboard for monitoring the generation pipeline."""

    def __init__(
        self,
        *,
        shared_stats: SharedStats,
        queue_manager: Optional["QueueManager"] = None,
        log_queue: Optional["Queue"] = None,
        console: Optional[Console] = None,
        update_interval: float = 1.0,
        log_lines: int = 20,
        refresh_per_second: float = 4.0,
        log_file_path: Optional[Path] = None,
        title: str = "GENERATE",
        throughput_label: str = "CSV lines/sec",
    ) -> None:
        self.shared_stats = shared_stats
        self.queue_manager = queue_manager
        self.log_queue = log_queue
        self.console = console or Console()
        self.update_interval = max(update_interval, 0.1)
        self.refresh_per_second = refresh_per_second
        self.log_lines = log_lines
        self.log_file_path = log_file_path
        self.title = title
        self.throughput_label = throughput_label

        self.log_buffer = DashboardLogBuffer()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._keyboard_thread: Optional[threading.Thread] = None
        self._stdin_fd: Optional[int] = None
        if sys.stdin and hasattr(sys.stdin, "fileno"):
            try:
                fd = sys.stdin.fileno()
            except (ValueError, OSError):
                fd = None
            else:
                if fd is not None and sys.stdin.isatty():
                    self._stdin_fd = fd

    # ------------------------------------------------------------------
    # Public API

    def start(self) -> None:
        """Start the dashboard loop in a background daemon thread."""

        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="FuzzybinDashboard",
            daemon=True,
        )
        self._thread.start()

        if self._stdin_fd is not None:
            self._keyboard_thread = threading.Thread(
                target=self._keyboard_loop,
                name="FuzzybinDashboardKeyboard",
                daemon=True,
            )
            self._keyboard_thread.start()

    def stop(self) -> None:
        """Signal the dashboard loop to stop and wait for completion."""

        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._keyboard_thread is not None:
            self._keyboard_thread.join(timeout=2.0)

    # ------------------------------------------------------------------
    # Internal helpers

    def _run_loop(self) -> None:  # pragma: no cover - side-effect driven
        initial_snapshot = self.shared_stats.get_snapshot()
        layout = self._build_layout(initial_snapshot)

        with Live(
            layout,
            console=self.console,
            refresh_per_second=self.refresh_per_second,
            screen=False,
        ) as live:
            while not self._stop_event.is_set():
                start = time.monotonic()
                self._drain_log_queue()
                self._update_queue_sizes()
                snapshot = self.shared_stats.get_snapshot()
                live.update(self._build_layout(snapshot), refresh=True)

                elapsed = time.monotonic() - start
                remaining = max(self.update_interval - elapsed, 0.05)
                if self._stop_event.wait(remaining):
                    break

    def _drain_log_queue(self) -> None:
        if self.log_queue is None:
            return

        messages: List[DashboardLogMessage] = []
        while True:
            try:
                payload = self.log_queue.get_nowait()
            except Empty:
                break
            except Exception:  # pragma: no cover - defensive
                break
            else:
                if isinstance(payload, DashboardLogMessage):
                    messages.append(payload)
        if messages:
            self.log_buffer.extend(messages)

    def _update_queue_sizes(self) -> None:
        if self.queue_manager is None:
            return

        task_size = self._safe_qsize(getattr(self.queue_manager, "task_queue", None))
        result_size = self._safe_qsize(getattr(self.queue_manager, "result_queue", None))
        binary_size = self._safe_qsize(getattr(self.queue_manager, "binary_queue", None))
        self.shared_stats.update_queue_sizes(
            task=task_size,
            result=result_size,
            binary=binary_size,
        )

    @staticmethod
    def _safe_qsize(queue_obj: Optional[object]) -> int:
        if queue_obj is None:
            return 0
        qsize_method = getattr(queue_obj, "qsize", None)
        if qsize_method is None:
            return 0
        try:
            size = qsize_method()
        except (NotImplementedError, AttributeError, OSError):
            return 0
        except Exception:  # pragma: no cover - defensive
            return 0
        return max(int(size), 0)

    def _keyboard_loop(self) -> None:  # pragma: no cover - interactive I/O
        fd = self._stdin_fd
        if fd is None or termios is None or tty is None:
            return

        try:
            original_settings = termios.tcgetattr(fd)
        except termios.error:
            return

        awaiting_confirmation = False
        try:
            tty.setcbreak(fd)
            while not self._stop_event.is_set():
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                except (select.error, ValueError):
                    break
                if not ready:
                    continue

                try:
                    ch = sys.stdin.read(1)
                except Exception:
                    continue

                if not ch:
                    continue

                lowered = ch.lower()

                # Simplified shutdown: Press 'S' to force shutdown immediately
                if lowered == "s":
                    self.shared_stats.request_forced_shutdown()
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, original_settings)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Rendering helpers

    def _build_layout(self, snapshot: StatsSnapshot) -> Layout:
        layout = Layout()
        # Keep original log panel height
        log_panel_size = self.log_lines + 2
        layout.split(
            Layout(self._render_header(snapshot), name="header", size=3),
            Layout(name="main_content", ratio=1),
        )
        
        # Split main content into left columns (progress+workers) and right column (stats)
        layout["main_content"].split_row(
            Layout(name="left_columns", ratio=3),  # Progress + Workers (ratio 1+2=3)
            Layout(name="right_column", ratio=2),  # Statistics (full height)
        )
        
        # Left columns: split vertically into body and logs area
        layout["left_columns"].split(
            Layout(name="left_body", ratio=1),
            Layout(name="left_logs", size=log_panel_size),
        )
        
        # Left body: split horizontally into progress and workers (equal width)
        layout["left_body"].split_row(
            Layout(self._render_progress_panel(snapshot), name="progress", ratio=1),  # Equal width
            Layout(self._render_workers_panel(snapshot), name="workers", ratio=1),    # Equal width
        )
        
        # Left logs: logs panel spans both progress and workers columns
        layout["left_logs"].update(self._render_logs_panel())
        
        # Right column: Statistics spans full height (body + logs area)
        layout["right_column"].update(self._render_statistics_panel(snapshot))

        return layout

    def _render_header(self, snapshot: StatsSnapshot) -> Panel:
        elapsed = format_duration(snapshot.elapsed_seconds)
        completed = snapshot.completed_binaries + snapshot.skipped_binaries
        total = max(snapshot.total_binaries, completed)
        header_text = Text()
        header_text.append("Bin", style="bold red")
        header_text.append("Rank", style="bold green")
        header_text.append("Bench", style="bold blue")
        header_text.append(f" {self.title}", style="bold white")
        header_text.append("  |  ")
        header_text.append(f"Elapsed: {elapsed}", style="cyan")
        header_text.append("  |  ")
        header_text.append(f"Binaries: {completed}/{total}", style="magenta")

        if snapshot.forced_shutdown_requested:
            header_text.append("  |  SHUTDOWN INITIATED", style="bold red")
        else:
            header_text.append("  |  Press [S] to shutdown", style="dim")

        return Panel(header_text, box=box.ROUNDED, style="bright_blue", padding=(0, 1))

    def _render_progress_panel(self, snapshot: StatsSnapshot) -> Panel:
        progress = Progress(
            TextColumn("{task.description}", style="cyan"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TextColumn("{task.completed}/{task.total}", justify="right"),
            expand=True,
        )

        # Add per-binary progress bars (sorted by progress descending, excluding 100% complete)
        binary_progress_list = []
        if snapshot.binary_progress:
            for binary_name, progress_data in snapshot.binary_progress.items():
                expected = progress_data.get("expected", 0)
                posted = progress_data.get("posted", 0)
                if expected > 0:
                    pct = posted / expected if expected > 0 else 0.0
                    # Only show binaries that are not 100% complete
                    if pct < 1.0:
                        binary_progress_list.append((binary_name, posted, expected, pct))
        
        # Sort by progress percentage (descending - highest progress first)
        binary_progress_list.sort(key=lambda x: x[3], reverse=True)
        
        # Add individual binary progress bars
        for binary_name, posted, expected, _ in binary_progress_list:
            # Truncate binary name if too long
            display_name = binary_name[:20] + "..." if len(binary_name) > 20 else binary_name
            progress.add_task(
                display_name,
                total=expected,
                completed=posted,
            )

        # Overall binaries progress (only if no binary-specific progress yet)
        if not binary_progress_list:
            total_binaries = safe_progress_total(
                snapshot.total_binaries,
                snapshot.completed_binaries + snapshot.skipped_binaries,
            )
            progress.add_task(
                "Binaries",
                total=total_binaries,
                completed=snapshot.completed_binaries + snapshot.skipped_binaries,
            )

        # Task posting progress (posted vs expected)
        total_expected = safe_progress_total(
            snapshot.task_groups_expected,
            snapshot.task_groups_posted + snapshot.task_groups_skipped,
        )
        progress.add_task(
            "Groups",
            total=total_expected,
            completed=snapshot.task_groups_posted,
        )

        # Task execution (successful + failed) vs posted tasks
        execution_total = safe_progress_total(
            snapshot.task_groups_posted,
            snapshot.tasks_succeeded + snapshot.tasks_failed,
        )
        progress.add_task(
            "Tasks",
            total=execution_total,
            completed=snapshot.tasks_succeeded + snapshot.tasks_failed,
        )

        # Result writing progress (results + skips) vs executed tasks
        result_total = safe_progress_total(
            snapshot.tasks_succeeded + snapshot.task_groups_skipped,
            snapshot.results_written + snapshot.skips_logged,
        )
        progress.add_task(
            "Results",
            total=result_total,
            completed=snapshot.results_written + snapshot.skips_logged,
        )

        return Panel(progress, title="Progress", border_style="bright_blue", padding=(1, 1))

    def _render_workers_panel(self, snapshot: StatsSnapshot) -> Panel:
        """Render workers panel showing TaskPoster and TaskRunner statistics."""
        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(justify="left", no_wrap=True)
        table.add_column(justify="right", no_wrap=True)

        elapsed = snapshot.elapsed_seconds if snapshot.elapsed_seconds > 0 else 1.0

        # TaskPoster Workers section
        if snapshot.poster_task_groups:
            table.add_row("[bold cyan]Posters[/bold cyan]", "", style="bold")
            for idx, count in enumerate(snapshot.poster_task_groups):
                throughput = count / elapsed if elapsed > 0 else 0.0
                # Format throughput using task time formatter (convert to seconds per task)
                avg_time = 1.0 / throughput if throughput > 0 else 0.0
                
                state = 0
                if snapshot.poster_states and idx < len(snapshot.poster_states):
                    state = snapshot.poster_states[idx]
                dot = "[green]●[/green]" if state == 2 else ("[yellow]●[/yellow]" if state == 1 else "[red]●[/red]")
                
                table.add_row(
                    f"{dot} #{idx}",
                    f"{count:5d} ({format_task_time(avg_time)})",
                )
            table.add_row("", "")  # Spacer

        # TaskRunner Workers section
        runner_counts = snapshot.runner_tasks_completed
        if runner_counts:
            table.add_row("[bold cyan]Runners[/bold cyan]", "", style="bold")
            n_runners = len(runner_counts)
            
            # Calculate throughput for each runner
            runner_throughputs = []
            total_runner_tasks = 0
            for count in runner_counts:
                throughput = count / elapsed if elapsed > 0 else 0.0
                runner_throughputs.append(throughput)
                total_runner_tasks += count
            
            avg_throughput = total_runner_tasks / (n_runners * elapsed) if n_runners > 0 and elapsed > 0 else 0.0
            avg_tasks = total_runner_tasks / n_runners if n_runners > 0 else 0.0
            
            if n_runners <= 12:
                # Show all runners individually
                for i, (count, throughput) in enumerate(zip(runner_counts, runner_throughputs)):
                    # Format throughput using task time formatter (convert to seconds per task)
                    avg_time = 1.0 / throughput if throughput > 0 else 0.0
                    
                    state = 0
                    if snapshot.runner_states and i < len(snapshot.runner_states):
                        state = snapshot.runner_states[i]
                    dot = "[green]●[/green]" if state == 2 else ("[yellow]●[/yellow]" if state == 1 else "[red]●[/red]")
                    
                    table.add_row(
                        f"{dot} #{i:2d}",
                        f"{count:5d} ({format_task_time(avg_time)})",
                    )
            else:
                # Show summary + top N performers
                # Format average using task time formatter
                avg_time = 1.0 / avg_throughput if avg_throughput > 0 else 0.0
                table.add_row(
                    "",
                    f"{n_runners} total, avg: {avg_tasks:.1f} ({format_task_time(avg_time)})",
                    style="dim"
                )
                
                # Sort by throughput (descending) and show top 12
                runner_data = list(enumerate(zip(runner_counts, runner_throughputs)))
                runner_data.sort(key=lambda x: x[1][1], reverse=True)  # Sort by throughput
                
                for i, (runner_id, (count, throughput)) in enumerate(runner_data[:12]):
                    # Format throughput using task time formatter (convert to seconds per task)
                    avg_time = 1.0 / throughput if throughput > 0 else 0.0
                    table.add_row(
                        f"    #{runner_id:2d}",
                        f"{count:5d} ({format_task_time(avg_time)})",
                        style="dim"
                    )
                
                if n_runners > 12:
                    table.add_row("", f"... {n_runners - 12} more", style="dim")

        # Collector worker section
        table.add_row("[bold cyan]Collector[/bold cyan]", "", style="bold")
        state = snapshot.collector_state
        dot = "[green]●[/green]" if state == 2 else ("[yellow]●[/yellow]" if state == 1 else "[red]●[/red]")
        
        # Calculate throughput for collector (results written / sec)
        results = snapshot.results_written
        throughput = results / elapsed if elapsed > 0 else 0.0
        avg_time = 1.0 / throughput if throughput > 0 else 0.0
        
        table.add_row(
            f"{dot} 主",
            f"{results:5d} ({format_task_time(avg_time)})",
        )
        table.add_row("", "")  # Spacer

        # If no workers, show empty message
        if not snapshot.poster_task_groups and not runner_counts and state == 0:
            empty_text = Align.center(Text("No worker statistics available", style="dim"))
            return Panel(empty_text, title="Workers", border_style="bright_blue", padding=(1, 1))

        return Panel(table, title="Workers", border_style="bright_blue", padding=(1, 1))

    def _render_statistics_panel(self, snapshot: StatsSnapshot) -> Panel:
        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(justify="left", no_wrap=True, ratio=2)  # Left column gets more space
        table.add_column(justify="right", no_wrap=True, ratio=1)  # Right column for values

        # Runtime
        table.add_row("Elapsed", format_duration(snapshot.elapsed_seconds))

        # Binaries
        binaries_done = snapshot.completed_binaries + snapshot.skipped_binaries
        binaries_total = max(snapshot.total_binaries, binaries_done)
        binary_pct = (binaries_done / binaries_total * 100) if binaries_total else 0.0
        table.add_row(
            "Binaries",
            f"{binaries_done}/{binaries_total} ({binary_pct:5.1f}%)",
        )
        if snapshot.skipped_binaries:
            table.add_row("└─ skipped", str(snapshot.skipped_binaries))

        # Task posting coverage
        total_expected = snapshot.task_groups_expected
        posted_pct = (
            snapshot.task_groups_posted / total_expected * 100
            if total_expected
            else 0.0
        )
        table.add_row(
            "Task groups posted",
            f"{snapshot.task_groups_posted}/{total_expected or '--'} ({posted_pct:5.1f}%)",
        )
        if snapshot.task_groups_skipped:
            table.add_row("└─ skipped", str(snapshot.task_groups_skipped))

        # Task execution statistics
        total_processed = snapshot.tasks_succeeded + snapshot.tasks_failed
        success_pct = (
            snapshot.tasks_succeeded / total_processed * 100
            if total_processed
            else 0.0
        )
        table.add_row(
            "Task results",
            f"{snapshot.tasks_succeeded} ok / {snapshot.tasks_failed} err ({success_pct:5.1f}% ok)",
        )

        table.add_row("Avg task time", format_task_time(snapshot.average_task_seconds))

        # Result collector
        table.add_row(
            "Results written",
            f"{snapshot.results_written} (+{snapshot.skips_logged} skips)",
        )
        if snapshot.result_errors:
            table.add_row("└─ errors", str(snapshot.result_errors))

        # Throughput metrics
        elapsed = snapshot.elapsed_seconds if snapshot.elapsed_seconds > 0 else 1.0
        csv_lines_per_sec = snapshot.results_written / elapsed if elapsed > 0 else 0.0
        tasks_per_sec = snapshot.tasks_succeeded / elapsed if elapsed > 0 else 0.0
        
        table.add_row("", "")  # Spacer
        table.add_row("Throughput", "", style="bold cyan")
        table.add_row(f"  {self.throughput_label}", f"{csv_lines_per_sec:6.2f}")
        table.add_row("  Tasks/sec", f"{tasks_per_sec:6.2f}")

        # Task type statistics (sliding window only)
        # Always show the section, even if windows are still filling
        table.add_row("", "")  # Spacer
        table.add_row("[bold cyan]Task Types[/bold cyan]", "")
        
        if snapshot.task_type_sliding_averages:
            # Sort by sliding average (descending) to show slowest first
            sorted_sliding = sorted(
                snapshot.task_type_sliding_averages.items(),
                key=lambda x: x[1].get("average", 0),
                reverse=True
            )
            for task_type, sliding_info in sorted_sliding:
                avg = sliding_info.get("average", 0)
                table.add_row(
                    f"  {task_type}",
                    f"{format_task_time(avg)}",
                )
        else:
            # Show placeholder while windows are filling
            table.add_row("  (filling...)", "", style="dim")

        # Queue depths
        table.add_row("", "")  # Spacer
        table.add_row("[bold cyan]Queues[/bold cyan]", "")
        
        def _make_queue_bar(size: int, max_size: int) -> Progress:
            p = Progress(BarColumn(bar_width=15), TextColumn("{task.completed}/{task.total}"))
            p.add_task("", total=max_size, completed=size)
            return p

        table.add_row("  Task", _make_queue_bar(snapshot.task_queue_size, 10000))
        table.add_row("  Result", _make_queue_bar(snapshot.result_queue_size, 100000))
        table.add_row("  Binary", _make_queue_bar(snapshot.binary_queue_size, 1000))

        # Log file path - show only filename with directory reference
        if self.log_file_path:
            log_path = self.log_file_path.resolve()
            log_dir = log_path.parent
            filename = log_path.name
            
            # Display filename prominently, directory path in dim text
            log_text = Text()
            log_text.append(filename, style="bright_blue")
            log_text.append(f" (file://{log_dir})", style="dim")
            table.add_row("Log file", log_text)

        return Panel(table, title="Statistics", border_style="bright_blue", padding=(1, 1))

    def _render_logs_panel(self) -> Panel:
        entries = self.log_buffer.snapshot(self.log_lines)
        if not entries:
            empty_text = Align.center(Text("No log messages captured yet", style="dim"))
            return Panel(empty_text, title="Logs", border_style="bright_blue", padding=(0, 1))

        log_lines: List[Text] = []
        for entry in entries:
            colour = LEVEL_COLOURS.get(entry.levelname, "white")
            timestamp = format_time_hms(entry.created)
            # Create text with entire line colored by level (no level label)
            # Use word wrapping for messages
            text = Text(f"[{timestamp}] ", style="dim")
            if entry.name:
                text.append(f"{entry.name} ", style="magenta")
            # Append message with word wrapping - use console width for wrapping
            text.append(entry.message, style=colour)
            log_lines.append(text)

        group = Group(*log_lines)
        return Panel(group, title="Logs", border_style="bright_blue", padding=(0, 1))


