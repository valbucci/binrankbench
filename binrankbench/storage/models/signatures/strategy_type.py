"""
StrategyType — lookup table for signature strategy names.

``StrategyID`` is a stable ``IntEnum`` whose integer values are used as
``polymorphic_identity`` on each ``Signature`` subclass.  The matching
``strategy_type`` DB table is seeded by ``init_db`` so the FK on
``signature.strategy_id`` remains a true foreign key.

Adding a new strategy
---------------------
1. Add a new member to ``StrategyID`` (pick the next available integer).
2. Define your ``Signature`` subclass with ``strategy_id=StrategyID.<name>``.
3. The seed step in ``init_db`` will insert the new row automatically.
"""
from __future__ import annotations

from enum import IntEnum

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base


class StrategyID(IntEnum):
    """Stable integer identifiers for each registered signature strategy.

    These values are stored in ``signature.strategy_id`` and MUST NOT change
    once rows exist in the database.  To add a strategy, append a new member
    with the next available integer; never renumber existing members.
    """
    catalog1 = 1
    ccbhash = 5
    fss_original = 6
    fss_marcelli = 7
    machoke = 4
    bytes_signature = 8
    fss_marcelli_weighted = 10


class StrategyType(Base):
    """One row per signature strategy — the normalised lookup for the FK.

    Rows are seeded automatically by ``init_db``; do not insert manually.
    """

    __tablename__ = "strategy_type"

    id:   Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"StrategyType(id={self.id}, name={self.name!r})"
