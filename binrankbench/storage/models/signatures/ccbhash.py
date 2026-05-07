"""
CCBHash fingerprint and function association tables.

``CCBHashFingerprint`` is the deduplicated content entity: UNIQUE across all
13 feature columns (6 subhash FKs + 7 inline bucket values).  Two functions
with structurally identical CCBHash signatures share one fingerprint row.

``FunctionCCBHash`` is the association table linking each function to its
fingerprint.  PRIMARY KEY is ``function_id`` (one CCBHash per function).

Exact-match lookup
------------------
Given a set of feature values:
    1. Look up the fingerprint by its UNIQUE key (index hit).
    2. All functions with that fingerprint → index scan on
       ``function_ccbhash.fingerprint_id``.

``digest`` hybrid_property
--------------------------
Returns a 32-char hex string (16 bytes) assembled in ``SUBHASH_ORDER``:
    6 × 2-byte subhash values (4 hex each) +
    1 × 1-byte ninstructions bucket (2 hex) +
    6 × nibble buckets (1 hex each)
= 32 hex chars.
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, SmallInteger, UniqueConstraint
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base
from ..dedup import ByteDedupBase

_SUBHASH_ORDER = None


def _get_subhash_order():
    global _SUBHASH_ORDER
    if _SUBHASH_ORDER is None:
        from binrankbench.modules.ccbhash import SUBHASH_ORDER
        _SUBHASH_ORDER = SUBHASH_ORDER
    return _SUBHASH_ORDER


# ---------------------------------------------------------------------------
# CCBHash sub-hash deduplication tables  (private to CCBHash)
# ---------------------------------------------------------------------------

class CCBHashNameSubhash(ByteDedupBase):
    __tablename__ = "ccbhash_name_subhash"

class CCBHashCFGSubhash(ByteDedupBase):
    __tablename__ = "ccbhash_cfg_subhash"

class CCBHashCallGraphSubhash(ByteDedupBase):
    __tablename__ = "ccbhash_call_graph_subhash"

class CCBHashOpcodesSubhash(ByteDedupBase):
    __tablename__ = "ccbhash_opcodes_subhash"

class CCBHashVarArgsSubhash(ByteDedupBase):
    __tablename__ = "ccbhash_var_args_subhash"

class CCBHashVarLocalsSubhash(ByteDedupBase):
    __tablename__ = "ccbhash_var_locals_subhash"


# ---------------------------------------------------------------------------
# Fingerprint — unique content entity
# ---------------------------------------------------------------------------

class CCBHashFingerprint(Base):
    """
    Unique CCBHash content entity.

    One row per distinct combination of all 13 feature values.  The UNIQUE
    constraint deduplicates structurally identical functions across any number
    of binaries or projects.
    """

    __tablename__ = "ccbhash_fingerprint"
    __table_args__ = (
        UniqueConstraint(
            "name_subhash_id", "cfg_subhash_id", "call_graph_subhash_id",
            "opcodes_subhash_id", "var_args_subhash_id", "var_locals_subhash_id",
            "ninstructions_bucket", "indegree_bucket", "outdegree_bucket",
            "nvars_bucket", "cc_bucket", "nblocks_bucket", "stackframe_bucket",
            name="uq_ccbhash_fingerprint",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # 6 × content sub-hash FKs
    name_subhash_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccbhash_name_subhash.id"), nullable=True
    )
    cfg_subhash_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccbhash_cfg_subhash.id"), nullable=True
    )
    call_graph_subhash_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccbhash_call_graph_subhash.id"), nullable=True
    )
    opcodes_subhash_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccbhash_opcodes_subhash.id"), nullable=True
    )
    var_args_subhash_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccbhash_var_args_subhash.id"), nullable=True
    )
    var_locals_subhash_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccbhash_var_locals_subhash.id"), nullable=True
    )

    # 7 × inline quantile-bucket values (already compressed; dedup not worthwhile)
    ninstructions_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    indegree_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    outdegree_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    nvars_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    cc_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    nblocks_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    stackframe_bucket: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    # Relationships (lazy-joined for digest property)
    name_subhash: Mapped["CCBHashNameSubhash | None"] = relationship(
        foreign_keys=[name_subhash_id], lazy="joined"
    )
    cfg_subhash: Mapped["CCBHashCFGSubhash | None"] = relationship(
        foreign_keys=[cfg_subhash_id], lazy="joined"
    )
    call_graph_subhash: Mapped["CCBHashCallGraphSubhash | None"] = relationship(
        foreign_keys=[call_graph_subhash_id], lazy="joined"
    )
    opcodes_subhash: Mapped["CCBHashOpcodesSubhash | None"] = relationship(
        foreign_keys=[opcodes_subhash_id], lazy="joined"
    )
    var_args_subhash: Mapped["CCBHashVarArgsSubhash | None"] = relationship(
        foreign_keys=[var_args_subhash_id], lazy="joined"
    )
    var_locals_subhash: Mapped["CCBHashVarLocalsSubhash | None"] = relationship(
        foreign_keys=[var_locals_subhash_id], lazy="joined"
    )

    # Back-reference to all associated functions (via pivot)
    function_links: Mapped[list["FunctionCCBHash"]] = relationship(
        back_populates="fingerprint"
    )

    @hybrid_property
    def digest(self) -> str | None:
        """32-char hex digest assembled in SUBHASH_ORDER (16 bytes)."""
        subhash_order = _get_subhash_order()
        rel_map = {
            "name":       self.name_subhash,
            "cfg":        self.cfg_subhash,
            "call_graph": self.call_graph_subhash,
            "opcodes":    self.opcodes_subhash,
            "var_args":   self.var_args_subhash,
            "var_locals": self.var_locals_subhash,
        }
        bucket_map = {
            "ninstructions": (self.ninstructions_bucket, "02x"),
            "indegree":      (self.indegree_bucket,      "01x"),
            "outdegree":     (self.outdegree_bucket,     "01x"),
            "nvars":         (self.nvars_bucket,         "01x"),
            "cc":            (self.cc_bucket,            "01x"),
            "nblocks":       (self.nblocks_bucket,       "01x"),
            "stackframe":    (self.stackframe_bucket,    "01x"),
        }
        parts: list[str] = []
        for key in subhash_order:
            if key in rel_map:
                row = rel_map[key]
                if row is None:
                    return None
                parts.append(row.value.hex())
            else:
                val, fmt = bucket_map[key]
                if val is None:
                    return None
                parts.append(format(val, fmt))
        return "".join(parts)

    @digest.expression  # type: ignore[no-redef]
    @classmethod
    def digest(cls):
        raise NotImplementedError(
            "Server-side CCBHash digest expression not yet implemented. "
            "Filter by individual *_subhash_id / *_bucket columns."
        )


# ---------------------------------------------------------------------------
# Pivot — function ↔ fingerprint association
# ---------------------------------------------------------------------------

class FunctionCCBHash(Base):
    """
    Association table: one CCBHash fingerprint per function.

    PRIMARY KEY on ``function_id`` enforces the one-per-function invariant.
    Index on ``fingerprint_id`` enables fast reverse lookup
    (all functions with a given fingerprint).
    """

    __tablename__ = "function_ccbhash"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("ccbhash_fingerprint.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="ccbhash"
    )
    fingerprint: Mapped["CCBHashFingerprint"] = relationship(
        back_populates="function_links"
    )
