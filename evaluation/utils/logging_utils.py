"""Per-stage structured logging: INFO+ to console, DEBUG+ to log file."""
import logging
import sys
from pathlib import Path


def setup_logging(caller_path: str) -> logging.Logger:
    name = Path(caller_path).stem
    log_dir = Path(caller_path).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    fh = logging.FileHandler(log_dir / f"{name}.log", mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s"))

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger
