"""
Machoke fingerprint and function association table.

``MachokeHash`` is already a content-dedup table (UNIQUE on ``digest``).
It serves directly as the fingerprint entity.

``FunctionMachoke`` is the pivot: PRIMARY KEY on ``function_id``.
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class MachokeHash(Base):
    """
    Deduplicated Machoke structural encoding.

    One row per unique (digest, line) pair.  ``digest`` is the MurmurHash3
    of the Machoke encoding string; ``line`` is the string itself.
    """

    __tablename__ = "machoke_hash"
    __table_args__ = ()    # UNIQUE enforced by digest column

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    digest: Mapped[bytes] = mapped_column(LargeBinary(4), nullable=False, unique=True)
    line: Mapped[str] = mapped_column(Text, nullable=False, default="")

    function_links: Mapped[list["FunctionMachoke"]] = relationship(
        back_populates="fingerprint"
    )


class FunctionMachoke(Base):
    """Association table: one Machoke fingerprint per function."""

    __tablename__ = "function_machoke"

    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint_id: Mapped[int] = mapped_column(
        ForeignKey("machoke_hash.id"), nullable=False, index=True
    )

    function: Mapped["Function"] = relationship(  # type: ignore[name-defined]
        back_populates="machoke"
    )
    fingerprint: Mapped["MachokeHash"] = relationship(
        back_populates="function_links"
    )
