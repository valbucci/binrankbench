"""Tests for the storage layer (SQLite in-memory)."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from binrankbench.storage.models import (
    Base,
    ByteFingerprint,
    Catalog1Fingerprint,
    CATALOG1_NUM_SLOTS,
    CCBHashFingerprint,
    CCBHashCFGSubhash,
    FunctionByteSig,
    FunctionCCBHash,
    FunctionCatalog1,
    FunctionFSSMarcelli,
    FunctionFSSOriginal,
    FunctionMachoke,
    FunctionName,
    FunctionScalars,
    FSSOriginalFingerprint,
    FSSMarcelliFingerprint,
    MachokeHash,
    Project,
    StrategyMembership,
    get_or_create,
)
from binrankbench.storage.session import _seed_strategy_types
from binrankbench.storage.writer import DBWriter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(eng, "connect")
    def set_fk(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")
        # Disable sqlite3 driver implicit transactions
        dbapi_conn.isolation_level = None

    @event.listens_for(eng, "begin")
    def do_begin(conn):
        # Force SQLAlchemy to emit explicit BEGIN
        conn.exec_driver_sql("BEGIN")

    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    _seed_strategy_types(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    with Session(engine) as sess:
        yield sess
        sess.rollback()


@pytest.fixture
def writer(session):
    return DBWriter(session)


# ---------------------------------------------------------------------------
# Schema smoke
# ---------------------------------------------------------------------------

class TestSchema:
    def test_expected_tables_exist(self, engine):
        tables = set(Base.metadata.tables.keys())
        for expected in [
            "ccbhash_fingerprint", "function_ccbhash",
            "catalog1_fingerprint", "function_catalog1",
            "byte_fingerprint", "function_byte_sig",
            "fss_original_fingerprint", "function_fss_original",
            "fss_marcelli_fingerprint", "function_fss_marcelli",
            "machoke_hash", "function_machoke",
            "strategy_membership", "function_name", "function_scalars",
        ]:
            assert expected in tables, f"Missing table: {expected}"

    def test_old_tables_gone(self, engine):
        tables = set(Base.metadata.tables.keys())
        for gone in ["signature", "ccbhash_signature",
                     "ccbhash_features"]:
            assert gone not in tables, f"Table should be gone: {gone}"


# ---------------------------------------------------------------------------
# get_or_create
# ---------------------------------------------------------------------------

class TestGetOrCreate:
    def test_creates_new(self, session):
        obj, created = get_or_create(
            session, CCBHashCFGSubhash, unique_on={"value": b"create_me"}
        )
        assert created and obj.id is not None

    def test_returns_existing(self, session):
        get_or_create(session, CCBHashCFGSubhash, unique_on={"value": b"shared"})
        _, created = get_or_create(session, CCBHashCFGSubhash, unique_on={"value": b"shared"})
        assert not created

    def test_dedup_same_id(self, session):
        a, _ = get_or_create(session, CCBHashCFGSubhash, unique_on={"value": b"same_id"})
        b, _ = get_or_create(session, CCBHashCFGSubhash, unique_on={"value": b"same_id"})
        assert a.id == b.id


# ---------------------------------------------------------------------------
# Core entities
# ---------------------------------------------------------------------------

class TestCoreEntities:
    def test_create_hierarchy(self, writer):
        func = writer.get_or_create_function("proj_a", "bin_a", "0x100", func_name="main")
        assert func.id is not None
        assert func.name == "main"
        assert func.binary.bin_name == "bin_a"

    def test_idempotent(self, writer):
        f1 = writer.get_or_create_function("proj_b", "bin_b", "0x200")
        f2 = writer.get_or_create_function("proj_b", "bin_b", "0x200")
        assert f1.id == f2.id

    def test_function_name_dedup(self, writer, session):
        writer.get_or_create_function("proj_nd", "bin_x", "0x10", func_name="foo")
        writer.get_or_create_function("proj_nd", "bin_y", "0x10", func_name="foo")
        assert session.query(FunctionName).filter_by(name="foo").count() == 1

    def test_function_scalars(self, writer, session):
        func = writer.get_or_create_function("proj_sc", "bin_sc", "0x20")
        s = writer.write_function_scalars(func, {
            "ninstructions": 42, "cc": 3, "edges": 8, "bbsum": 999
        })
        assert s.ninstructions == 42 and s.bbsum == 999


# ---------------------------------------------------------------------------
# CCBHash
# ---------------------------------------------------------------------------

class TestCCBHash:
    def _features(self, **kw):
        from types import SimpleNamespace
        d = dict(
            name_hash="22ff", cfg_hash="33ff", call_graph_hash="44ff",
            opcodes_hash="55ff", args_hash="66ff", locals_hash="77ff",
            ninstructions_hash="01",
            indegree_hash="1", outdegree_hash="2", nvars_hash="3",
            cc_hash="4", nblocks_hash="5", stackframe_hash="6",
        )
        d.update(kw)
        return SimpleNamespace(**d)

    def test_write_creates_fingerprint_and_pivot(self, writer, session):
        func = writer.get_or_create_function("ch_p", "ch_b", "0x100")
        pivot = writer.write_ccbhash(func, self._features())
        assert isinstance(pivot, FunctionCCBHash)
        assert pivot.fingerprint_id is not None
        fp = session.get(CCBHashFingerprint, pivot.fingerprint_id)
        assert fp.cc_bucket == 4

    def test_fingerprint_dedup_across_functions(self, writer, session):
        f1 = writer.get_or_create_function("ch_p", "ch_b", "0x200")
        f2 = writer.get_or_create_function("ch_p", "ch_b", "0x300")
        p1 = writer.write_ccbhash(f1, self._features())
        p2 = writer.write_ccbhash(f2, self._features())
        assert p1.fingerprint_id == p2.fingerprint_id  # same fingerprint row

    def test_digest_property_32_chars(self, writer, session):
        func = writer.get_or_create_function("ch_p", "ch_b", "0x400")
        pivot = writer.write_ccbhash(func, self._features())
        d = pivot.fingerprint.digest
        assert d is not None and len(d) == 32

    def test_strategy_membership_recorded(self, writer, session):
        func = writer.get_or_create_function("ch_p", "ch_b", "0x500")
        writer.write_ccbhash(func, self._features())
        mem = session.query(StrategyMembership).filter_by(
            function_id=func.id
        ).first()
        assert mem is not None

    def test_exact_match_lookup(self, writer, session):
        """Fingerprint-first lookup: find all functions with identical hash."""
        f1 = writer.get_or_create_function("ch_p", "ch_b", "0x600")
        f2 = writer.get_or_create_function("ch_p", "ch_b", "0x700")
        p1 = writer.write_ccbhash(f1, self._features())
        writer.write_ccbhash(f2, self._features())
        # Both should share the same fingerprint
        fp_id = p1.fingerprint_id
        pivots = session.query(FunctionCCBHash).filter_by(fingerprint_id=fp_id).all()
        assert len(pivots) == 2


# ---------------------------------------------------------------------------
# FSS
# ---------------------------------------------------------------------------

class TestFSS:
    def test_fss_original(self, writer, session):
        func = writer.get_or_create_function("fss_p", "fss_b", "0x100")
        first  = (0xDEADBEEF_CAFEBABE).to_bytes(8, "big")
        second = (0x0102030405060708).to_bytes(8, "big")
        pivot = writer.write_fss_original(func, first, second)
        assert isinstance(pivot, FunctionFSSOriginal)
        assert pivot.fingerprint.value == (
            int.from_bytes(first, "big") << 64 | int.from_bytes(second, "big")
        )

    def test_fss_fingerprint_dedup(self, writer, session):
        f1 = writer.get_or_create_function("fss_p", "fss_b", "0x200")
        f2 = writer.get_or_create_function("fss_p", "fss_b", "0x300")
        first, second = b"\xaa" * 8, b"\xbb" * 8
        p1 = writer.write_fss_original(f1, first, second)
        p2 = writer.write_fss_original(f2, first, second)
        assert p1.fingerprint_id == p2.fingerprint_id

    def test_fss_marcelli(self, writer):
        func = writer.get_or_create_function("fss_p", "fss_b", "0x400")
        pivot = writer.write_fss_marcelli(func, b"\xcc" * 8, b"\xdd" * 8)
        assert isinstance(pivot, FunctionFSSMarcelli)


# ---------------------------------------------------------------------------
# Machoke
# ---------------------------------------------------------------------------

class TestMachoke:
    def test_write_machoke(self, writer, session):
        func = writer.get_or_create_function("mk_p", "mk_b", "0x100")
        pivot = writer.write_machoke(func, b"\xa1\xb2\xc3\xd4", "1:2,3;3:;")
        assert isinstance(pivot, FunctionMachoke)
        assert pivot.fingerprint.line == "1:2,3;3:;"

    def test_machoke_dedup(self, writer, session):
        f1 = writer.get_or_create_function("mk_p", "mk_b", "0x200")
        f2 = writer.get_or_create_function("mk_p", "mk_b", "0x300")
        digest = b"\x11\x22\x33\x44"
        p1 = writer.write_machoke(f1, digest)
        p2 = writer.write_machoke(f2, digest)
        assert p1.fingerprint_id == p2.fingerprint_id
        assert session.query(MachokeHash).filter_by(digest=digest).count() == 1


# ---------------------------------------------------------------------------
# Byte Signature
# ---------------------------------------------------------------------------

class TestByteSig:
    def test_write_byte_sig(self, writer, session):
        func = writer.get_or_create_function("bs_p", "bs_b", "0x100")
        pivot = writer.write_byte_signature(
            func, raw_bytes=b"\xde\xad", nibble_mask=b"\xff\xf0", bit_mask=b"\xf0\xff"
        )
        assert isinstance(pivot, FunctionByteSig)
        assert pivot.fingerprint.raw_bytes_seq.bytes_sequence == b"\xde\xad"

    def test_byte_fingerprint_dedup(self, writer, session):
        f1 = writer.get_or_create_function("bs_p", "bs_b", "0x200")
        f2 = writer.get_or_create_function("bs_p", "bs_b", "0x300")
        p1 = writer.write_byte_signature(f1, b"\x11\x22", b"\xff\x00")
        p2 = writer.write_byte_signature(f2, b"\x11\x22", b"\xff\x00")
        assert p1.fingerprint_id == p2.fingerprint_id


# ---------------------------------------------------------------------------
# Catalog1
# ---------------------------------------------------------------------------

class TestCatalog1:
    def _values(self, seed=0):
        return [(i * 17 + seed) & 0xFFFFFFFF for i in range(CATALOG1_NUM_SLOTS)]

    def test_write_catalog1(self, writer, session):
        func = writer.get_or_create_function("c1_p", "c1_b", "0x100")
        pivot = writer.write_catalog1(func, self._values())
        assert isinstance(pivot, FunctionCatalog1)
        fp = session.get(Catalog1Fingerprint, pivot.fingerprint_id)
        assert fp is not None

    def test_slot_values_stored_directly(self, writer, session):
        """All 16 slot values are stored directly as columns on the fingerprint row."""
        vals = [0xDEADBEEF] * CATALOG1_NUM_SLOTS
        f1 = writer.get_or_create_function("c1_p", "c1_b", "0x200")
        pivot = writer.write_catalog1(f1, vals)
        fp = session.get(Catalog1Fingerprint, pivot.fingerprint_id)
        assert all(getattr(fp, f"slot_{i:02d}") == 0xDEADBEEF for i in range(CATALOG1_NUM_SLOTS))

    def test_fingerprint_dedup(self, writer, session):
        vals = self._values(seed=99)
        f1 = writer.get_or_create_function("c1_p", "c1_b", "0x300")
        f2 = writer.get_or_create_function("c1_p", "c1_b", "0x400")
        p1 = writer.write_catalog1(f1, vals)
        p2 = writer.write_catalog1(f2, vals)
        assert p1.fingerprint_id == p2.fingerprint_id

    def test_wrong_slot_count_raises(self, writer):
        func = writer.get_or_create_function("c1_p", "c1_b", "0x500")
        with pytest.raises(ValueError, match="Expected 16"):
            writer.write_catalog1(func, [0] * 10)

    def test_partitioned_lookup(self, writer, session):
        """Partitioned MinHash lookup: find all fingerprints sharing a slot_00 value."""
        shared_val = 0xABCD1234
        vals_a = [shared_val] + [(i * 13) & 0xFFFFFFFF for i in range(1, CATALOG1_NUM_SLOTS)]
        vals_b = [shared_val] + [(i * 7)  & 0xFFFFFFFF for i in range(1, CATALOG1_NUM_SLOTS)]
        f1 = writer.get_or_create_function("c1_p", "c1_b", "0x600")
        f2 = writer.get_or_create_function("c1_p", "c1_b", "0x700")
        writer.write_catalog1(f1, vals_a)
        writer.write_catalog1(f2, vals_b)

        fps = session.query(Catalog1Fingerprint).filter(
            Catalog1Fingerprint.slot_00 == shared_val
        ).all()
        assert len(fps) == 2
