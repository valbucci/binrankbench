"""
Tests for SkipLog/SkipReason ORM tables and DBWriter.bulk_write_skips.
"""
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from binrankbench.storage.models import Base, Project, Binary, Function, SkipLog, SkipReason
from binrankbench.storage.models.signatures.strategy_type import StrategyID
from binrankbench.storage.session import init_db, get_session
from binrankbench.storage.writer import DBWriter
from binrankbench.modules.generate.result import SkipInfo
from pathlib import Path


@pytest.fixture(scope="function")
def engine():
    """In-memory SQLite engine with all tables created."""
    eng = create_engine("sqlite:///:memory:")
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def session(engine):
    with get_session(engine) as sess:
        yield sess


def _seed_binary(session: Session, project: str = "testproj", bin_name: str = "testbin") -> Binary:
    writer = DBWriter(session)
    binary = writer.get_or_create_binary(project, bin_name)
    session.flush()
    return binary


class TestSkipModels:
    def test_skip_reason_unique(self, engine):
        """SkipReason deduplicates on explanation."""
        with Session(engine) as sess:
            r1 = SkipReason(explanation="missing func_cfg")
            sess.add(r1)
            sess.flush()
            r2 = SkipReason(explanation="missing func_cfg")
            sess.add(r2)
            with pytest.raises(Exception):
                with sess.begin_nested():
                    sess.flush()

    def test_skip_log_orm_traversal(self, session):
        """skip_log.function.func_addr and skip_log.reason.explanation work."""
        binary = _seed_binary(session)
        func = Function(binary_id=binary.id, func_addr="0x401000")
        reason = SkipReason(explanation="missing func_cfg")
        session.add_all([func, reason])
        session.flush()

        log = SkipLog(function_id=func.id, strategy_id=StrategyID.ccbhash.value, reason_id=reason.id)
        session.add(log)
        session.flush()

        fetched = session.execute(select(SkipLog).where(SkipLog.id == log.id)).scalar_one()
        assert fetched.function.func_addr == "0x401000"
        assert fetched.reason.explanation == "missing func_cfg"

    def test_skip_log_unique_constraint(self, engine):
        """Duplicate (function_id, task_type) is rejected."""
        with Session(engine) as sess:
            binary = _seed_binary(sess)
            func = Function(binary_id=binary.id, func_addr="0x401000")
            reason = SkipReason(explanation="broken")
            sess.add_all([func, reason])
            sess.flush()

            log1 = SkipLog(function_id=func.id, strategy_id=StrategyID.bytes_signature.value, reason_id=reason.id)
            sess.add(log1)
            sess.flush()

            # Same function + same strategy should violate constraint
            log2 = SkipLog(function_id=func.id, strategy_id=StrategyID.bytes_signature.value, reason_id=reason.id)
            sess.add(log2)
            with pytest.raises(Exception):
                with sess.begin_nested():
                    sess.flush()


class TestBulkWriteSkips:
    def _make_skips(self, binary_name: str = "testbin") -> list:
        return [
            SkipInfo(func_addr=0x401000, task_type="ccbhash",
                     reason="missing func_cfg", output_path=Path("."), binary_name=binary_name),
            SkipInfo(func_addr=0x402000, task_type="machoke",
                     reason="missing bytes", output_path=Path("."), binary_name=binary_name),
        ]

    def test_basic_write(self, session):
        """bulk_write_skips creates SkipLog + SkipReason rows."""
        binary = _seed_binary(session, project="proj", bin_name="testbin")
        # Seed the functions first, as bulk_write_skips is now read-only for functions
        for addr in ["0x401000", "0x402000"]:
            session.add(Function(binary_id=binary.id, func_addr=addr))
        session.flush()

        writer = DBWriter(session)
        writer.bulk_write_skips(self._make_skips(), "proj")
        session.flush()

        logs = session.execute(select(SkipLog)).scalars().all()
        reasons = session.execute(select(SkipReason)).scalars().all()

        assert len(logs) == 2
        # Only 2 unique reasons: "missing func_cfg" and "missing bytes"
        assert len(reasons) == 2
        reason_texts = {r.explanation for r in reasons}
        assert "missing func_cfg" in reason_texts
        assert "missing bytes" in reason_texts

    def test_idempotent(self, session):
        """Calling bulk_write_skips twice silently ignores duplicates."""
        binary = _seed_binary(session, project="proj", bin_name="testbin")
        for addr in ["0x401000", "0x402000"]:
            session.add(Function(binary_id=binary.id, func_addr=addr))
        session.flush()

        writer = DBWriter(session)
        skips = self._make_skips()
        writer.bulk_write_skips(skips, "proj")
        session.flush()
        writer.bulk_write_skips(skips, "proj")  # second call — must not raise
        session.flush()

        logs = session.execute(select(SkipLog)).scalars().all()
        assert len(logs) == 2  # still 2, not 4

    def test_orm_traversal_after_bulk_write(self, session):
        """ORM traversal works on rows created by bulk_write_skips."""
        binary = _seed_binary(session, project="proj", bin_name="testbin")
        # Seed function
        session.add(Function(binary_id=binary.id, func_addr="0x401000"))
        session.flush()

        writer = DBWriter(session)
        writer.bulk_write_skips([
            SkipInfo(func_addr=0x401000, task_type="ccbhash",
                     reason="missing func_cfg", output_path=Path("."), binary_name="testbin"),
        ], "proj")
        session.flush()

        log = session.execute(select(SkipLog)).scalar_one()
        assert log.function.func_addr == "0x401000"
        assert log.reason.explanation == "missing func_cfg"
        assert log.function.binary.bin_name == "testbin"

    def test_empty_list_is_noop(self, session):
        """bulk_write_skips([]) must not raise."""
        writer = DBWriter(session)
        writer.bulk_write_skips([], "proj")  # should be a no-op
