"""
Byte signature fingerprint and function association table.

``ByteFingerprint`` deduplicates the (raw_bytes, nibble_mask, bit_mask)
triple.  Each component is already deduped via ``ByteSequence``.

``FunctionByteSig`` is the pivot: PRIMARY KEY on ``function_id``.
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base
from ..dedup import ByteSequence


class ByteFingerprint(Base):
    """Unique byte-signature content entity — triple of ByteSequence FKs."""

    __tablename__ = "byte_fingerprint"
    __table_args__ = (
        UniqueConstraint(
            "raw_bytes_id", "nibble_mask_id", "bit_mask_id",
            name="uq_byte_fingerprint",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    raw_bytes_id: Mapped[int] = mapped_column(
        ForeignKey("byte_sequence.id"), nullable=False
    )
    nibble_mask_id: Mapped[int | None] = mapped_column(
        ForeignKey("byte_sequence.id"), nullable=True
    )
    bit_mask_id: Mapped[int | None] = mapped_column(
        ForeignKey("byte_sequence.id"), nullable=True
    )

    raw_bytes_seq: Mapped["ByteSequence"] = relationship(
        foreign_keys=[raw_bytes_id], lazy="joined"
    )
    nibble_mask_seq: Mapped["ByteSequence | None"] = relationship(
        foreign_keys=[nibble_mask_id], lazy="joined"
    )
    bit_mask_seq: Mapped["ByteSequence | None"] = relationship(
        foreign_keys=[bit_mask_id], lazy="joined"
    )

    function_links: Mapped[list["FunctionByteSig"]] = relationship(
        back_populates="fingerprint"
    )


class FunctionByteSig(Base):
    """Association table: one byte-signature fingerprint per function."""

    __tablename__ = "function_byte_sig"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("byte_fingerprint.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="byte_sig"
    )
    fingerprint: Mapped["ByteFingerprint"] = relationship(
        back_populates="function_links"
    )
