"""
Logging system for binrankbench.modules.generate with multiprocess support.

This module provides:
- LoggerManager: Singleton managing all logging handlers
- TqdmLoggingHandler: Console handler that works with tqdm progress bars
- BinaryLogFilter: Filter logs by binary_name for per-binary log files
- Setup functions for main and worker processes
"""

import logging
import logging.handlers
import os
import time
import threading
import contextvars
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Mapping, Optional
from multiprocessing import Queue
from dataclasses import dataclass, field

from tqdm import tqdm
from binrankbench.common.context import ROOT_DIR
from binrankbench.common.config import Config, load_config


# Module-level constants
LOGGER = logging.getLogger("binrankbench.modules.generate")
LOG_FILE = "runtime.log"
LOG_PATH = ROOT_DIR / LOG_FILE

_BINARY_CONTEXT: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "binrankbench_generate_binary_context", default=None
)

BASE_LEVEL = logging.INFO
LOG_FILE_LEVEL = logging.INFO
BINARY_LOG_LEVEL = logging.INFO
QUEUE_LEVEL = logging.INFO
CONSOLE_LEVEL = logging.INFO


def _level_from_value(value: Optional[object], fallback: int) -> int:
    if value is None:
        return fallback
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        upper = value.upper()
        if upper.isdigit():
            return int(upper)
        level = logging._nameToLevel.get(upper)  # type: ignore[attr-defined]
        if isinstance(level, int):
            return level
    raise ValueError(f"Invalid log level: {value!r}")


@dataclass
class LoggingConfig:
    """Global singleton for logging configuration across all modules."""
    
    console_level: int = logging.INFO
    file_level: int = logging.WARNING
    tui_enabled: bool = True
    log_file_path: Optional[Path] = None
    default_level: int = logging.INFO
    component_levels: dict[str, int] = field(default_factory=dict)


# Singleton instance storage
_logging_config_instance: Optional[LoggingConfig] = None
_logging_config_lock = threading.Lock()


def get_logging_config() -> LoggingConfig:
    """Get the global LoggingConfig singleton instance."""
    global _logging_config_instance
    if _logging_config_instance is None:
        with _logging_config_lock:
            if _logging_config_instance is None:
                _logging_config_instance = LoggingConfig()
    return _logging_config_instance


def initialize_logging_config(config: Optional[Config] = None, 
                              console_level: Optional[str] = None,
                              file_level: Optional[str] = None,
                              tui_enabled: Optional[bool] = None,
                              log_file_path: Optional[Path] = None) -> LoggingConfig:
    """Initialize or update the singleton from Config and CLI overrides."""
    global _logging_config_instance
    
    if config is None:
        try:
            config = load_config()
        except Exception:
            config = None
    
    with _logging_config_lock:
        if _logging_config_instance is None:
            _logging_config_instance = LoggingConfig()
        
        # Get defaults from config or use hardcoded defaults
        if config is not None:
            logging_cfg = config.logging
            _logging_config_instance.default_level = _level_from_value(
                logging_cfg.get("default_level"), logging.INFO
            )
            _logging_config_instance.console_level = _level_from_value(
                logging_cfg.get("console_level"), logging.INFO
            )
            _logging_config_instance.file_level = _level_from_value(
                logging_cfg.get("file_level"), logging.WARNING
            )
            _logging_config_instance.tui_enabled = config.is_dashboard_enabled()
            
            # Convert component levels from strings to ints
            component_levels = logging_cfg.get("components", {})
            _logging_config_instance.component_levels = {
                name: _level_from_value(level, _logging_config_instance.default_level)
                for name, level in component_levels.items()
            }
        else:
            _logging_config_instance.default_level = logging.INFO
            _logging_config_instance.console_level = logging.INFO
            _logging_config_instance.file_level = logging.WARNING
            _logging_config_instance.tui_enabled = True
            _logging_config_instance.component_levels = {}
        
        # CLI overrides take precedence
        if console_level is not None:
            _logging_config_instance.console_level = _level_from_value(console_level, logging.INFO)
        if file_level is not None:
            _logging_config_instance.file_level = _level_from_value(file_level, logging.WARNING)
        if tui_enabled is not None:
            _logging_config_instance.tui_enabled = tui_enabled
        if log_file_path is not None:
            _logging_config_instance.log_file_path = log_file_path
        
        return _logging_config_instance


class BinaryContextFilter(logging.Filter):
    """Inject binary_name from contextvar into log records if missing."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        if getattr(record, "binary_name", None) is None:
            binary_name = _BINARY_CONTEXT.get()
            if binary_name is not None:
                record.binary_name = binary_name
        return True
DEFAULT_LEVEL = logging.WARNING


class TqdmLoggingHandler(logging.Handler):
    """Console handler that writes via tqdm.write() to avoid progress bar corruption."""
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit log record via tqdm.write()."""
        try:
            msg = self.format(record)
            tqdm.write(msg)
        except Exception:
            self.handleError(record)


ANSI_RESET = "\033[0m"
ANSI_LEVELS = {
    logging.DEBUG: f"\033[2mDEBUG{ANSI_RESET}",
    logging.INFO: f"\033[36mINFO{ANSI_RESET}",
    logging.WARNING: f"\033[33mWARNING{ANSI_RESET}",
    logging.ERROR: f"\033[31mERROR{ANSI_RESET}",
    logging.CRITICAL: f"\033[1;31mCRITICAL{ANSI_RESET}",
}


class ConsoleFormatter(logging.Formatter):
    """Formatter that adds coloured level names and time-only timestamps."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        short_time = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        coloured_level = ANSI_LEVELS.get(record.levelno, record.levelname)
        name = record.name.replace("binrankbench.modules.generate.", "")
        binary_name = getattr(record, "binary_name", None)
        if binary_name:
            name = f"{name}({binary_name})"

        setattr(record, "short_time", short_time)
        setattr(record, "level_coloured", coloured_level)
        setattr(record, "logger_short_name", name)

        return super().format(record)


class BinaryLogFilter(logging.Filter):
    """Filter logs by binary_name attribute for per-binary log files."""
    
    def __init__(self, binary_name: str):
        super().__init__()
        self.binary_name = binary_name
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Only pass records with matching binary_name and WARNING+."""
        return (
            record.levelno >= logging.WARNING and
            getattr(record, 'binary_name', None) == self.binary_name
        )


class SelectiveConsoleFilter(logging.Filter):
    """
    Filter for console output with selective log levels.
    
    - INFO+ for specific loggers (e.g., main, LoggingManager)
    - WARNING+ for everything else (workers, etc.)
    """
    
    def __init__(self, verbose_loggers: Optional[list[str]] = None):
        super().__init__()
        # Loggers that should show INFO level
        self.verbose_loggers = verbose_loggers or ["main", "LoggingManager"]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Allow INFO+ for verbose loggers, WARNING+ for others."""
        # Get the logger name relative to binrankbench.modules.generate
        logger_name = record.name.replace("binrankbench.modules.generate.", "")
        
        # Check if this is a verbose logger or child of one
        for verbose_logger in self.verbose_loggers:
            if logger_name == verbose_logger or logger_name.startswith(verbose_logger + "."):
                # Verbose logger: allow INFO and above
                return record.levelno >= logging.INFO
        
        # Default: only WARNING and above
        # For WARNING and above, we almost always want to see it regardless of logger
        return record.levelno >= logging.WARNING


@contextmanager
def binary_log_context(binary_name: Optional[str]):
    """Context manager to attach binary_name to all log records in scope."""
    if binary_name:
        token = _BINARY_CONTEXT.set(binary_name)
        try:
            yield
        finally:
            _BINARY_CONTEXT.reset(token)
    else:
        yield


class LoggerManager:
    """
    Singleton manager for all logging configuration.
    
    Responsibilities:
    - Prevent duplicate handler registration
    - Manage console, global, and per-binary log files
    - Integrate with tqdm for non-disruptive console output
    - Track .part files for atomic completion
    """
    
    _instance: Optional['LoggerManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs) -> 'LoggerManager':
        """Ensure singleton pattern (one instance per process)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False  # type: ignore[attr-defined]
                    cls._instance._pid = None  # type: ignore[attr-defined]
        return cls._instance
    
    def __init__(
        self, enable_file_logging: bool = True, attach_console: bool = True,
        console_level: Optional[int] = None, file_level: Optional[int] = None,
        log_file_path: Optional[Path] = None, 
        use_file_formatter_for_console: bool = False
    ):
        """
        Initialize manager. Reconfigure automatically when running in a new process.
        
        Args:
            enable_file_logging: Enable session-wide log file when True.
            attach_console: Attach console handler when True.
            console_level: Log level for console output 
                (default: from LoggingConfig or INFO).
            file_level: Log level for file output 
                (default: from LoggingConfig or WARNING).
            log_file_path: Override log file path 
                (default: auto-generated).
            use_file_formatter_for_console: Use file formatter for console 
                output (for non-TUI mode).
        """
        # Get levels from LoggingConfig singleton if not provided
        if console_level is None or file_level is None:
            logging_config = get_logging_config()
            if console_level is None:
                console_level = logging_config.console_level
            if file_level is None:
                file_level = logging_config.file_level
            if log_file_path is None:
                log_file_path = logging_config.log_file_path
        
        current_pid = os.getpid()
        with self._lock:
            needs_reconfigure = (not getattr(self, "_initialized", False) or
                                 getattr(self, "_pid", None) != current_pid)

            if needs_reconfigure:
                self._pid = current_pid
                self.enable_file_logging = enable_file_logging
                self.attach_console = attach_console
                self.console_level = console_level
                self.file_level = file_level
                self.use_file_formatter_for_console = use_file_formatter_for_console
                self.base_logger = LOGGER
                if log_file_path is not None:
                    self.global_log_path = log_file_path
                else:
                    self.global_log_path = LOG_PATH
                self._reset_handlers()
                self._setup_base_logger()
                self._initialized = True
            else:
                # Same process, adjust only if we need to enable extras
                if enable_file_logging and not getattr(self, "enable_file_logging", False):
                    self.enable_file_logging = True
                    if self.global_file_handler is None:
                        self._add_file_handler()
                # Update levels if provided
                if console_level is not None:
                    self.console_level = console_level
                if file_level is not None:
                    self.file_level = file_level
                if log_file_path is not None:
                    self.global_log_path = log_file_path
    
    def _setup_base_logger(self) -> None:
        """Configure base logger with console and global file handlers."""
        # Ensure log directory exists
        os.makedirs(self.global_log_path.parent, exist_ok=True)
        
        # Add context filter to base logger
        self.base_logger.addFilter(BinaryContextFilter())

        console_formatter = ConsoleFormatter(
            fmt="{short_time} | {level_coloured:<11} | {logger_short_name} | {message}",
            style="{"
        )

        file_formatter = logging.Formatter(
            fmt="{asctime} | {levelname:^7s} | {name:s} | {message:s}",
            datefmt="%Y-%m-%d %H:%M:%S",
            style="{"
        )

        if getattr(self, "attach_console", True):
            self.console_handler = TqdmLoggingHandler()
            self.console_handler.setLevel(getattr(self, "console_level", logging.INFO))
            # Use file formatter for console when TUI is disabled (non-TUI mode)
            if getattr(self, "use_file_formatter_for_console", False):
                self.console_handler.setFormatter(file_formatter)
            else:
                console_filter = SelectiveConsoleFilter(verbose_loggers=["main", "LoggingManager"])
                self.console_handler.addFilter(console_filter)
                self.console_handler.setFormatter(console_formatter)
            self.base_logger.addHandler(self.console_handler)
        else:
            self.console_handler = None

        if self.enable_file_logging:
            self._add_file_handler(file_formatter)
        
        # Set base logger level to minimum of console/file levels to allow all 
        # messages through. Handlers will filter based on their individual levels
        console_lvl = getattr(self, "console_level", logging.INFO)
        file_lvl = getattr(self, "file_level", logging.WARNING)
        base_level = min(console_lvl, file_lvl)
        self.base_logger.setLevel(base_level)
        self.base_logger.propagate = False

    def _reset_handlers(self) -> None:
        """Clear existing handlers and reset tracking structures."""
        # Close existing handlers if any
        for handler in getattr(self, "binary_handlers", {}).values():
            try:
                handler.close()
            except Exception:
                pass

        global_handler = getattr(self, "global_file_handler", None)
        if global_handler is not None:
            try:
                global_handler.close()
            except Exception:
                pass

        console_handler = getattr(self, "console_handler", None)
        if console_handler is not None:
            try:
                console_handler.close()
            except Exception:
                pass

        # Remove from base logger
        if hasattr(self, "base_logger"):
            self.base_logger.handlers.clear()
            self.base_logger.filters.clear()

        # Reset tracking structures
        self.console_handler = None
        self.global_file_handler = None
        self.binary_handlers = {}
        self.binary_log_files = {}
        self._last_flush = {}
        self._shutting_down = False

    def _add_file_handler(self, formatter: Optional[logging.Formatter] = None) -> None:
        """Attach global file handler if not already attached."""
        if self.global_file_handler is not None:
            return

        if formatter is None:
            formatter = logging.Formatter(
                fmt="{asctime} | {levelname:^7s} | {name:s} | {message:s}",
                datefmt="%Y-%m-%d %H:%M:%S",
                style="{"
            )

        self.global_file_handler = logging.FileHandler(
            self.global_log_path, mode='a', encoding='utf-8'
        )
        global_file_handler_level = getattr(self, "file_level", logging.WARNING)
        self.global_file_handler.setLevel(global_file_handler_level)
        self.global_file_handler.setFormatter(formatter)
        self.base_logger.addHandler(self.global_file_handler)

    def configure_levels(
        self,
        default_level: Optional[object] = None,
        component_levels: Optional[Mapping[str, object]] = None,
    ) -> None:
        try:
            base_level = _level_from_value(default_level, BASE_LEVEL)
        except ValueError:
            base_level = BASE_LEVEL
        self.base_logger.setLevel(base_level)

        if not component_levels:
            return

        for component, level in component_levels.items():
            try:
                resolved_level = _level_from_value(level, base_level)
            except ValueError:
                continue
            self.get_logger(component).setLevel(resolved_level)
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """
        Get configured logger without adding duplicate handlers.
        
        Args:
            name: Logger name suffix (will be child of binrankbench.modules.generate)
        
        Returns:
            Configured logger instance
        """
        if name is not None:
            logger = self.base_logger.getChild(name)
        else:
            logger = self.base_logger
        
        return logger
    
    def start_binary_logging(self, binary_name: str, output_dir: Path) -> None:
        """
        Create per-binary log file with .part extension.
        
        Args:
            binary_name: Name of binary being processed
            output_dir: Directory for output files
        """
        with self._lock:
            # Check if already started
            if binary_name in self.binary_handlers:
                return
            
            # Check if binary is already complete (has .log file)
            # If so, don't create a .part file - the binary is already done
            log_path = output_dir / f"{binary_name}.log"
            if log_path.exists():
                # Binary already completed, don't create .part file
                return
            
            # Create .part file path
            part_path = output_dir / f"{binary_name}.log.part"
            
            # Create handler with WARNING+ level
            handler = logging.FileHandler(
                part_path, mode='a', encoding='utf-8'
            )
            handler.setLevel(BINARY_LOG_LEVEL)
            
            # Add formatter
            formatter = logging.Formatter(
                fmt="{asctime} | {levelname:^7s} | {name:s} | {message:s}",
                datefmt="%Y-%m-%d %H:%M:%S",
                style="{"
            )
            handler.setFormatter(formatter)
            
            # Add filter for this binary
            handler.addFilter(BinaryLogFilter(binary_name))
            
            # Attach to base logger
            self.base_logger.addHandler(handler)
            
            # Track handler and file
            self.binary_handlers[binary_name] = handler
            self.binary_log_files[binary_name] = part_path
            self._last_flush[binary_name] = time.time()
    
    def finish_binary_logging(self, binary_name: str) -> None:
        """
        Flush, close handler, and rename .part to .log.
        
        Called when all the tasks for a binary have been posted.
        
        Args:
            binary_name: Name of binary that finished processing
        """
        with self._lock:
            # Get handler
            handler = self.binary_handlers.get(binary_name)
            if handler is None:
                return
            
            # Flush and close
            handler.flush()
            handler.close()
            
            # Remove from base logger
            self.base_logger.removeHandler(handler)
            
            # Remove from tracking
            del self.binary_handlers[binary_name]
            if binary_name in self._last_flush:
                del self._last_flush[binary_name]

            # Rename .part to .log (atomic completion marker)
            part_path = self.binary_log_files.get(binary_name)
            if part_path is None:
                return

            if part_path and part_path.exists():
                # Remove .part suffix (file is already named binary.log.part, we want binary.log)
                log_path = part_path.with_suffix('')  # Removes .part, leaving .log
                # Safety check: don't overwrite an existing .log file (shouldn't happen if start_binary_logging is correct)
                if not log_path.exists():
                    part_path.rename(log_path)
                else:
                    # .log file already exists, remove the .part file instead
                    part_path.unlink()
                del self.binary_log_files[binary_name]
    
    def _flush_handlers_internal(self, force: bool = False) -> None:
        """
        Internal flush method (assumes lock is already held for binary handlers).
        
        Args:
            force: If True, flush all immediately. Otherwise only flush if >5s since last flush.
        """
        current_time = time.time()
        
        # Always flush global handlers (no lock needed)
        if self.console_handler:
            self.console_handler.flush()
        if self.global_file_handler:
            self.global_file_handler.flush()
        
        # Flush binary handlers (caller must hold lock)
        for binary_name, handler in self.binary_handlers.items():
            last_flush = self._last_flush.get(binary_name, 0)
            if force or (current_time - last_flush) >= 5.0:
                handler.flush()
                self._last_flush[binary_name] = current_time
    
    def flush_handlers(self, force: bool = False) -> None:
        """
        Flush all handlers periodically.
        
        Args:
            force: If True, flush all immediately. Otherwise only flush if >5s since last flush.
        """
        with self._lock:
            self._flush_handlers_internal(force)
    
    def cleanup(self) -> None:
        """Close all handlers and flush buffers."""
        with self._lock:
            self._shutting_down = True
            
            # Flush all handlers (use internal method to avoid deadlock)
            self._flush_handlers_internal(force=True)
            
            # Close binary handlers
            for handler in self.binary_handlers.values():
                handler.close()
                self.base_logger.removeHandler(handler)
            self.binary_handlers.clear()
            self.binary_log_files.clear()
            self._last_flush.clear()
            
            # Close global handlers
            if self.console_handler:
                self.console_handler.close()
                self.base_logger.removeHandler(self.console_handler)
                self.console_handler = None
            
            if self.global_file_handler:
                self.global_file_handler.close()
                self.base_logger.removeHandler(self.global_file_handler)
                self.global_file_handler = None
    
    def is_binary_complete(self, binary_name: str, output_dir: Path) -> bool:
        """
        Check if binary processing completed successfully.
        
        Args:
            binary_name: Name of binary to check
            output_dir: Directory containing log files
        
        Returns:
            True if .log exists (not .part)
        """
        log_path = output_dir / f"{binary_name}.log"
        return log_path.is_file()


def setup_main_logging(log_queue: Queue, config: Optional[Config] = None) -> LoggerManager:
    """
    Configure logging for main process.
    
    Sets up LoggerManager with NO local handlers (no console, no file).
    All logs are sent to LoggingManager process via queue for handling.
    
    Args:
        log_queue: Queue for sending logs to LoggingManager process
    
    Returns:
        LoggerManager singleton instance
    """
    # Get singleton LoggerManager with NO local handlers (LoggingManager process handles output)
    if config is None:
        try:
            config = load_config()
        except Exception:
            config = None

    logger_manager = LoggerManager(enable_file_logging=False, attach_console=False)
    
    # Add QueueHandler to send logs to LoggingManager process for file writing
    base_logger = logging.getLogger("binrankbench.modules.generate")
    # Clear any existing handlers to prevent duplicates
    base_logger.handlers.clear()
    base_logger.propagate = False
    queue_handler = logging.handlers.QueueHandler(log_queue)
    queue_handler.setLevel(QUEUE_LEVEL)
    base_logger.addHandler(queue_handler)

    if config is not None:
        logging_cfg = config.logging
        logger_manager.configure_levels(
            logging_cfg.get("default_level"),
            logging_cfg.get("components", {}),
        )
    
    return logger_manager


def setup_worker_logging(log_queue: Queue, config: Optional[Config] = None) -> None:
    """
    Configure logging for worker process.
    
    Clears any existing handlers and adds only QueueHandler to send
    all logs to LoggingManager process.
    
    Args:
        log_queue: Queue for sending logs to LoggingManager process
    """
    # Reconfigure logger manager for worker process (no console/file handlers)
    if config is None:
        try:
            config = load_config()
        except Exception:
            config = None

    manager = LoggerManager(enable_file_logging=False, attach_console=False)

    # Get base logger
    base_logger = logging.getLogger("binrankbench.modules.generate")
    
    # Clear any existing handlers
    base_logger.handlers.clear()
    
    # Add QueueHandler only
    queue_handler = logging.handlers.QueueHandler(log_queue)
    queue_handler.setLevel(QUEUE_LEVEL)
    base_logger.addHandler(queue_handler)
    base_logger.setLevel(BASE_LEVEL)
    
    # Prevent propagation to root logger
    base_logger.propagate = False

    if config is not None:
        logging_cfg = config.logging
        manager.configure_levels(
            logging_cfg.get("default_level"),
            logging_cfg.get("components", {}),
        )


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get configured logger without duplicate handlers.
    
    This is the main API for getting loggers. It uses the LoggerManager
    singleton to ensure no duplicate handlers are added.
    
    Args:
        name: Logger name suffix (will be child of binrankbench.modules.generate)
    
    Returns:
        Configured logger instance
    
    Example:
        >>> logger = get_logger("mymodule")
        >>> logger.info("Hello world")
    """
    # Create/get LoggerManager without file logging and without console by default
    # (file logging only enabled in LoggingManager process)
    # (console only enabled in LoggingManager process when TUI disabled)
    logger_manager = LoggerManager(enable_file_logging=False, attach_console=False)
    return logger_manager.get_logger(name)
