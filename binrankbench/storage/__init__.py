"""
binrankbench.storage — Normalised relational storage layer.

Public surface
--------------
    from binrankbench.storage import get_engine, init_db, get_session
    from binrankbench.storage import DBWriter, ingest_binary
    from binrankbench.storage.models import (
        Project, Binary, Function,
        Dataset, BinaryDatasetTag,
        Signature, Catalog1Signature, CCBHashSignature, ...
    )
    # Analytics (requires duckdb):
    from binrankbench.storage.analytics import open_analytics, query, signature_dataframe

Note: ``analytics`` is NOT imported here because it requires the optional
``duckdb`` package.  Import it explicitly when needed.
"""
from .ingest import ingest_binary
from .models import BinaryDatasetTag, Dataset
from .session import get_engine, get_session, init_db, make_session_factory
from .writer import DBWriter

__all__ = [
    # Session / engine
    "get_engine",
    "init_db",
    "get_session",
    "make_session_factory",
    # Write
    "DBWriter",
    # Ingest
    "ingest_binary",
    # Dataset tagging
    "Dataset",
    "BinaryDatasetTag",
]
