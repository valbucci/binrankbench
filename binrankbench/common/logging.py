"""Base logging configuration for BinRankBench, with tqdm-aware and binary-context handlers."""

import logging
import os
from datetime import datetime

class TqdmLoggingHandler(logging.Handler):
    def emit(self, record):
        try:
            import tqdm
            msg = self.format(record)
            tqdm.tqdm.write(msg)
        except (ImportError, Exception):
            self.handleError(record)

class BinaryContextFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "binary_name"):
            record.binary_name = ""
        return True

LOGGER = logging.getLogger("binrankbench")
LOGGER.propagate = False

stream_handler = TqdmLoggingHandler()
formatter = logging.Formatter(
    fmt="{asctime} | {levelname:^7s} | {name:s}{binary_info} | {message:s}",
    datefmt="%Y-%m-%d %H:%M:%S", style="{"
)

class BinaryInfoFormatter(logging.Formatter):
    def format(self, record):
        binary_name = getattr(record, "binary_name", "")
        record.binary_info = f"({binary_name})" if binary_name else ""
        return super().format(record)

formatter = BinaryInfoFormatter(
    fmt="{asctime} | {levelname:^7s} | {name:s}{binary_info} | {message:s}",
    datefmt="%Y-%m-%d %H:%M:%S", style="{"
)

stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO)
LOGGER.addHandler(stream_handler)
LOGGER.addFilter(BinaryContextFilter())
