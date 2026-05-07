"""
Function Similarity Search (FSS) fingerprint and association tables.

Two variants: Original (Aho-Schneier) and Marcelli-modified.
Each stores a 128-bit hash as two 64-bit BYTEA halves.

For each variant:
  - ``FSSXxxFingerprint``  — unique content entity, UNIQUE(first, second)
  - ``FunctionFSSXxx``     — pivot, PRIMARY KEY (function_id)
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, LargeBinary, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class FSSOriginalFingerprint(Base):
    """Unique FSS-Original 128-bit hash content entity."""

    __tablename__ = "fss_original_fingerprint"
    __table_args__ = (UniqueConstraint("first", "second", name="uq_fss_original"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    first:  Mapped[bytes] = mapped_column(LargeBinary(8), nullable=False)
    second: Mapped[bytes] = mapped_column(LargeBinary(8), nullable=False)

    function_links: Mapped[list["FunctionFSSOriginal"]] = relationship(
        back_populates="fingerprint"
    )

    @property
    def value(self) -> int:
        """Reconstitute the full 128-bit integer."""
        return (int.from_bytes(self.first, "big") << 64) | int.from_bytes(self.second, "big")


class FunctionFSSOriginal(Base):
    """Association table: one FSS-Original fingerprint per function."""

    __tablename__ = "function_fss_original"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("fss_original_fingerprint.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="fss_original"
    )
    fingerprint: Mapped["FSSOriginalFingerprint"] = relationship(
        back_populates="function_links"
    )


class FSSMarcelliFingerprint(Base):
    """Unique FSS-Marcelli 128-bit hash content entity."""

    __tablename__ = "fss_marcelli_fingerprint"
    __table_args__ = (UniqueConstraint("first", "second", name="uq_fss_marcelli"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    first:  Mapped[bytes] = mapped_column(LargeBinary(8), nullable=False)
    second: Mapped[bytes] = mapped_column(LargeBinary(8), nullable=False)

    function_links: Mapped[list["FunctionFSSMarcelli"]] = relationship(
        back_populates="fingerprint"
    )

    @property
    def value(self) -> int:
        return (int.from_bytes(self.first, "big") << 64) | int.from_bytes(self.second, "big")


class FunctionFSSMarcelli(Base):
    """Association table: one FSS-Marcelli fingerprint per function."""

    __tablename__ = "function_fss_marcelli"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("fss_marcelli_fingerprint.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="fss_marcelli"
    )
    fingerprint: Mapped["FSSMarcelliFingerprint"] = relationship(
        back_populates="function_links"
    )

class FSSMarcelliWeightedFingerprint(Base):
    """Unique FSS-Marcelli-Weighted 128-bit hash content entity."""

    __tablename__ = "fss_marcelli_weighted_fingerprint"
    __table_args__ = (UniqueConstraint("first", "second", name="uq_fss_marcelli_weighted"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    first:  Mapped[bytes] = mapped_column(LargeBinary(8), nullable=False)
    second: Mapped[bytes] = mapped_column(LargeBinary(8), nullable=False)

    function_links: Mapped[list["FunctionFSSMarcelliWeighted"]] = relationship(
        back_populates="fingerprint"
    )

    @property
    def value(self) -> int:
        return (int.from_bytes(self.first, "big") << 64) | int.from_bytes(self.second, "big")


class FunctionFSSMarcelliWeighted(Base):
    """Association table: one FSS-Marcelli-Weighted fingerprint per function."""

    __tablename__ = "function_fss_marcelli_weighted"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("fss_marcelli_weighted_fingerprint.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="fss_marcelli_weighted"
    )
    fingerprint: Mapped["FSSMarcelliWeightedFingerprint"] = relationship(
        back_populates="function_links"
    )
