"""
tests/test_ingest.py — integration tests for binrankbench.storage.ingest

These tests use the sample data in tests/test_data/bin2ml/ to run an
end-to-end ingest (data load → hash generation → DB write) against an
in-memory SQLite database.  No running Postgres is required.

Run with:
    pytest tests/test_ingest.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from binrankbench.storage.ingest import ingest_binary
from binrankbench.storage.models import (
    Base,
    Binary,
    BinaryDatasetTag,
    CCBHashFingerprint,
    Dataset,
    Function,
    FunctionCCBHash,
    Project,
    StrategyID,
    get_or_create,
)
from binrankbench.storage.session import _seed_strategy_types
from binrankbench.storage.writer import DBWriter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_DATA_DIR = Path(__file__).parent / "test_data" / "bin2ml"
TEST_BIN      = "git_2-47-1.exe"
TEST_PROJECT  = "git"
TEST_DATASET  = "sample_dataset"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine() -> Engine:
    """PostgreSQL engine for the entire module (schema created once)."""
    import os
    db_url = os.environ.get(
        "BINRANKBENCH_TEST_DB_URL",
        "sqlite:///:memory:"
    )
    eng = create_engine(db_url, echo=False)

    if db_url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def set_fk_pragma(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    _seed_strategy_types(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def session(engine: Engine):
    """Fresh session per test, rolled back after each test to keep isolation."""
    with Session(engine) as sess:
        yield sess
        sess.rollback()


# ---------------------------------------------------------------------------
# Smoke / skip guard
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def require_test_data():
    """Skip the whole module if sample data is not present."""
    bininfo = TEST_DATA_DIR / f"{TEST_BIN}_bininfo.json"
    if not bininfo.is_file():
        pytest.skip(f"Sample data not found at {TEST_DATA_DIR}")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_ingest(session: Session, **kwargs) -> Binary:
    """Run ingest_binary with sensible defaults for test parameters."""
    return ingest_binary(
        session=session,
        project=TEST_PROJECT,
        bin_name=TEST_BIN,
        raw_data_dir=TEST_DATA_DIR,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIngestBinaryEntities:
    """Verify that the correct ORM rows are created after a single ingest."""

    def test_project_is_created(self, session: Session):
        _run_ingest(session)
        proj = session.execute(
            select(Project).where(Project.name == TEST_PROJECT)
        ).scalar_one_or_none()
        assert proj is not None, "Project row was not created"
        assert proj.name == TEST_PROJECT

    def test_binary_is_created(self, session: Session):
        _run_ingest(session)
        binary = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalar_one_or_none()
        assert binary is not None, "Binary row was not created"
        assert binary.bin_name == TEST_BIN

    def test_binary_metadata_from_bininfo(self, session: Session):
        """arch, bits, cc and sha256 should be extracted from bininfo.json."""
        _run_ingest(session)
        binary = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalar_one_or_none()
        assert binary is not None
        # The sample bininfo should carry at least arch and sha256
        assert binary.arch is not None, "arch was not set from bininfo.json"
        assert binary.sha256 is not None, "sha256 was not set from bininfo.json"

    def test_functions_are_created(self, session: Session):
        """At least one Function row should be created per binary."""
        _run_ingest(session)
        binary = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalar_one()
        funcs = session.execute(
            select(Function).where(Function.binary_id == binary.id)
        ).scalars().all()
        assert len(funcs) > 0, "No Function rows were created"


class TestIngestSignatures:
    """Verify that CCBHash signatures are written for at least some functions."""

    def test_ccbhash_signatures_written(self, session: Session):
        _run_ingest(session, strategies=["ccbhash"])
        projs = session.execute(
            select(FunctionCCBHash)
        ).scalars().all()
        assert len(projs) > 0, "No CCBHash signatures were written"

    def test_ccbhash_digest_is_nonempty(self, session: Session):
        _run_ingest(session, strategies=["ccbhash"])
        proj = session.execute(
            select(CCBHashFingerprint)
        ).scalars().first()
        assert proj is not None
        assert proj.digest, "CCBHash digest is empty"


class TestDatasetTagging:
    """Verify dataset creation and binary ↔ dataset linkage."""

    def test_dataset_is_created(self, session: Session):
        _run_ingest(session, datasets=[TEST_DATASET])
        ds = session.execute(
            select(Dataset).where(Dataset.name == TEST_DATASET)
        ).scalar_one_or_none()
        assert ds is not None, "Dataset row was not created"
        assert ds.name == TEST_DATASET

    def test_binary_is_tagged_to_dataset(self, session: Session):
        _run_ingest(session, datasets=[TEST_DATASET])
        binary = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalar_one()
        ds = session.execute(
            select(Dataset).where(Dataset.name == TEST_DATASET)
        ).scalar_one()
        tag = session.execute(
            select(BinaryDatasetTag).where(
                BinaryDatasetTag.binary_id == binary.id,
                BinaryDatasetTag.dataset_id == ds.id,
            )
        ).scalar_one_or_none()
        assert tag is not None, "BinaryDatasetTag row was not created"

    def test_multiple_datasets(self, session: Session):
        ds_names = ["ds_alpha", "ds_beta"]
        _run_ingest(session, datasets=ds_names)
        binary = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalar_one()
        for ds_name in ds_names:
            ds = session.execute(
                select(Dataset).where(Dataset.name == ds_name)
            ).scalar_one()
            tag = session.execute(
                select(BinaryDatasetTag).where(
                    BinaryDatasetTag.binary_id == binary.id,
                    BinaryDatasetTag.dataset_id == ds.id,
                )
            ).scalar_one_or_none()
            assert tag is not None, f"BinaryDatasetTag missing for dataset '{ds_name}'"


class TestIdempotency:
    """Running ingest_binary twice on the same binary must not duplicate rows."""

    def test_binary_not_duplicated(self, session: Session):
        _run_ingest(session, datasets=[TEST_DATASET])
        _run_ingest(session, datasets=[TEST_DATASET])
        binaries = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalars().all()
        assert len(binaries) == 1, (
            f"Expected 1 Binary row, got {len(binaries)} after running ingest twice"
        )

    def test_dataset_not_duplicated(self, session: Session):
        _run_ingest(session, datasets=[TEST_DATASET])
        _run_ingest(session, datasets=[TEST_DATASET])
        datasets = session.execute(
            select(Dataset).where(Dataset.name == TEST_DATASET)
        ).scalars().all()
        assert len(datasets) == 1, (
            f"Expected 1 Dataset row, got {len(datasets)} after running ingest twice"
        )

    def test_tag_not_duplicated(self, session: Session):
        _run_ingest(session, datasets=[TEST_DATASET])
        _run_ingest(session, datasets=[TEST_DATASET])
        binary = session.execute(
            select(Binary).where(Binary.bin_name == TEST_BIN)
        ).scalar_one()
        ds = session.execute(
            select(Dataset).where(Dataset.name == TEST_DATASET)
        ).scalar_one()
        tags = session.execute(
            select(BinaryDatasetTag).where(
                BinaryDatasetTag.binary_id == binary.id,
                BinaryDatasetTag.dataset_id == ds.id,
            )
        ).scalars().all()
        assert len(tags) == 1, (
            f"Expected 1 BinaryDatasetTag, got {len(tags)} after running ingest twice"
        )

    def test_signatures_not_duplicated(self, session: Session):
        _run_ingest(session, strategies=["ccbhash"])
        count_first = session.execute(
            select(FunctionCCBHash)
        ).scalars().all()
        _run_ingest(session, strategies=["ccbhash"])
        count_second = session.execute(
            select(FunctionCCBHash)
        ).scalars().all()
        assert len(count_first) == len(count_second), (
            "CCBHash signatures were duplicated on second ingest: "
            f"{len(count_first)} → {len(count_second)}"
        )
