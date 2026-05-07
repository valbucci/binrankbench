"""
Catalog1 MinHash fingerprint and function association table.

Each Catalog1 digest is a sequence of N 32-bit MinHash values (one per
permutation).  For ``byte_size=64`` (the default), N=16.

``Catalog1Fingerprint`` stores the 16 MinHash values directly as BIGINT
columns (``slot_00`` … ``slot_15``).  The UNIQUE constraint across all 16
columns deduplicates identically fingerprinted functions.  Per-slot indexes
enable partitioned matching: to find all functions that share MinHash value V
at slot i, query ``SELECT fingerprint_id FROM catalog1_fingerprint WHERE slot_i = V``.

``FunctionCatalog1`` is the pivot: PRIMARY KEY on ``function_id``.
"""
from __future__ import annotations

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base

CATALOG1_NUM_SLOTS = 16


class Catalog1Fingerprint(Base):
    """
    Unique Catalog1 content entity — 16 direct MinHash slot values.

    UNIQUE constraint across all 16 slots deduplicates identical fingerprints.
    Per-slot index on each column enables partitioned MinHash band queries.
    """

    __tablename__ = "catalog1_fingerprint"
    __table_args__ = (
        UniqueConstraint(
            *(f"slot_{i:02d}" for i in range(CATALOG1_NUM_SLOTS)),
            name="uq_catalog1_fingerprint",
        ),
        *(
            Index(f"ix_catalog1_fp_slot_{i:02d}", f"slot_{i:02d}")
            for i in range(CATALOG1_NUM_SLOTS)
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    slot_00: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_01: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_02: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_03: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_04: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_05: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_06: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_07: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_08: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_09: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_10: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_11: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_12: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_13: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_14: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_15: Mapped[int] = mapped_column(BigInteger, nullable=False)

    function_links: Mapped[list["FunctionCatalog1"]] = relationship(
        back_populates="fingerprint"
    )

    @property
    def minhash_values(self) -> list[int]:
        """Return the 16 MinHash values in slot order."""
        return [getattr(self, f"slot_{i:02d}") for i in range(CATALOG1_NUM_SLOTS)]


class FunctionCatalog1(Base):
    """Association table: one Catalog1 fingerprint per function."""

    __tablename__ = "function_catalog1"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("catalog1_fingerprint.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="catalog1"
    )
    fingerprint: Mapped["Catalog1Fingerprint"] = relationship(
        back_populates="function_links"
    )
