"""Base logging configuration for BinRankBench, with tqdm-aware and binary-context handlers."""

import logging
from pathlib import Path

# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


class TqdmLoggingHandler(logging.Handler):
    """Console handler that writes via tqdm.write() to avoid progress bar corruption."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            import tqdm

            msg = self.format(record)
            tqdm.tqdm.write(msg)
        except (ImportError, Exception):
            self.handleError(record)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


class BinaryContextFilter(logging.Filter):
    """Inject a blank binary_name attribute into records that lack one."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "binary_name"):
            record.binary_name = ""
        return True


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class BinaryInfoFormatter(logging.Formatter):
    """Formatter that appends (binary_name) to the logger name when present."""

    def format(self, record: logging.LogRecord) -> str:
        binary_name = getattr(record, "binary_name", "")
        record.binary_info = f"({binary_name})" if binary_name else ""
        return super().format(record)


_DEFAULT_FORMATTER = BinaryInfoFormatter(
    fmt="{asctime} | {levelname:^7s} | {name:s}{binary_info} | {message:s}",
    datefmt="%Y-%m-%d %H:%M:%S",
    style="{",
)

_FILE_FORMATTER = BinaryInfoFormatter(
    fmt="{asctime} | {levelname:^7s} | {name:s}{binary_info} | {message:s}",
    datefmt="%Y-%m-%d %H:%M:%S",
    style="{",
)


# ---------------------------------------------------------------------------
# Root library logger — silent by default (library best practice)
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("binrankbench")
LOGGER.addHandler(logging.NullHandler())
# propagate = True so pytest's log-capture machinery works out of the box


# ---------------------------------------------------------------------------
# Setup helpers — call these from CLI / application entry points
# ---------------------------------------------------------------------------


def setup_console_logging(
    level: int = logging.INFO,
    formatter: logging.Formatter | None = None,
) -> TqdmLoggingHandler:
    """Attach a tqdm-aware console handler to the binrankbench logger.

    Safe to call multiple times — avoids adding duplicate handlers.

    Args:
        level:     Minimum log level for console output (default: INFO).
        formatter: Custom formatter; defaults to BinaryInfoFormatter.

    Returns:
        The (possibly newly created) TqdmLoggingHandler instance.

    """
    # Return existing handler if already attached
    for h in LOGGER.handlers:
        if isinstance(h, TqdmLoggingHandler):
            return h

    handler = TqdmLoggingHandler()
    handler.setLevel(level)
    handler.setFormatter(formatter or _DEFAULT_FORMATTER)
    handler.addFilter(BinaryContextFilter())

    LOGGER.addHandler(handler)
    # Ensure the logger itself doesn't filter out messages the handler wants
    if LOGGER.level == logging.NOTSET or LOGGER.level > level:
        LOGGER.setLevel(level)

    return handler


def setup_file_logging(
    path: Path | str,
    level: int = logging.WARNING,
    formatter: logging.Formatter | None = None,
    mode: str = "a",
    encoding: str = "utf-8",
) -> logging.FileHandler:
    """Attach a file handler to the binrankbench logger.

    Safe to call multiple times — avoids adding duplicate handlers for the
    same file path.

    Args:
        path:      Destination log file (created if it does not exist).
        level:     Minimum log level for file output (default: WARNING).
        formatter: Custom formatter; defaults to BinaryInfoFormatter.
        mode:      File open mode (default: 'a').
        encoding:  File encoding (default: 'utf-8').

    Returns:
        The (possibly newly created) FileHandler instance.

    """
    resolved = Path(path).resolve()

    # Return existing handler if already attached to the same file
    for h in LOGGER.handlers:
        if isinstance(h, logging.FileHandler):
            if Path(h.baseFilename).resolve() == resolved:
                return h

    resolved.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(resolved, mode=mode, encoding=encoding)
    handler.setLevel(level)
    handler.setFormatter(formatter or _FILE_FORMATTER)
    handler.addFilter(BinaryContextFilter())

    LOGGER.addHandler(handler)
    if LOGGER.level == logging.NOTSET or LOGGER.level > level:
        LOGGER.setLevel(level)

    return handler


def setup_default_logging(
    console_level: int = logging.INFO,
    file_path: Path | str | None = None,
    file_level: int = logging.WARNING,
) -> None:
    """Convenience wrapper: console handler + optional file handler.

    This reproduces the behaviour that was previously applied at import time,
    but only when explicitly called (e.g. from a CLI entry point).

    Args:
        console_level: Level for console output (default: INFO).
        file_path:     If provided, also attach a file handler at this path.
        file_level:    Level for file output (default: WARNING).

    """
    setup_console_logging(level=console_level)
    if file_path is not None:
        setup_file_logging(path=file_path, level=file_level)
