"""
Deduplicated content tables and the ``get_or_create`` helper.

``ByteDedupBase`` is the shared abstract for all content-addressed byte
deduplication tables: each concrete subclass holds unique byte sequences
under a single UNIQUE constraint on ``value``.

CCBHash sub-hash dedup tables live in
``binrankbench.storage.models.signatures.ccbhash`` — they are private to
that signature strategy and imported from there when needed.

Usage
-----
    from binrankbench.storage.models.dedup import get_or_create
"""
from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import Integer, LargeBinary, select
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.exc import IntegrityError

from .base import Base

T = TypeVar("T", bound=Base)


# ---------------------------------------------------------------------------
# Shared abstract base
# ---------------------------------------------------------------------------

class ByteDedupBase(Base):
    """Abstract base class for typed raw bytes deduplication."""
    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[bytes] = mapped_column(LargeBinary, unique=True, index=True, nullable=False)

    def __repr__(self) -> str:
        preview = self.value.hex()[:10] + "…" if len(self.value) > 5 else self.value.hex()
        return f"{self.__class__.__name__}(id={self.id}, hex={preview})"


# ---------------------------------------------------------------------------
# Byte Signature Deduplication
# ---------------------------------------------------------------------------

class ByteSequence(Base):
    """
    Deduplicated storage for byte sequences (raw function bytes, masks, etc.).

    A UNIQUE constraint on ``bytes_hash`` ensures identical byte sequences share
    one row, deduplicating data across identical signatures or masks.
    """
    __tablename__ = "byte_sequence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bytes_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, index=True, nullable=False)
    bytes_sequence: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    def __repr__(self) -> str:
        return f"ByteSequence(id={self.id}, len={len(self.bytes_sequence)})"


# ---------------------------------------------------------------------------
# get_or_create
# ---------------------------------------------------------------------------

def get_or_create(
    session: Session,
    model: type[T],
    *,
    unique_on: dict[str, Any],
    defaults: dict[str, Any] | None = None,
) -> tuple[T, bool]:
    """
    Fetch an existing row matching ``unique_on`` or insert a new one.

    Parameters
    ----------
    session:
        Active SQLAlchemy session (must be within a transaction).
    model:
        The ORM model class to query/insert.
    unique_on:
        Column→value mapping that uniquely identifies the row.
    defaults:
        Additional columns to set only on INSERT (ignored on SELECT).

    Returns
    -------
    (instance, created)
        ``created`` is ``True`` if a new row was inserted.

    Notes
    -----
    * Uses ``session.flush()`` after INSERT to materialise the server-assigned
      primary key without committing the surrounding transaction.
    * Thread / process safety comes from the DB-level UNIQUE constraint: if two
      writers race, the loser gets an IntegrityError on commit (caller should
      retry or use ``INSERT … ON CONFLICT DO NOTHING``).
    * ``None`` values are compared with ``IS NULL`` (not ``= NULL``) to avoid
      both incorrect SQL semantics and the Python 3.14 infinite __eq__ loop
      that SQLAlchemy triggers when coercing None via filter_by().
    """
    # Build WHERE clauses: use IS NULL for None, equality for everything else.
    filters = []
    for col_name, value in unique_on.items():
        col = getattr(model, col_name)
        if value is None:
            filters.append(col.is_(None))
        else:
            filters.append(col == value)

    obj = session.execute(
        select(model).where(*filters)
    ).scalar_one_or_none()

    if obj is not None:
        return obj, False

    kwargs = dict(unique_on)
    if defaults:
        kwargs.update(defaults)
    obj = model(**kwargs)
    
    try:
        with session.begin_nested():
            session.add(obj)
            session.flush()          # get server-assigned id before commit
        return obj, True
    except IntegrityError:
        # A concurrent writer inserted the row after our initial select.
        # The savepoint rolled back automatically, we can now safely fetch it.
        obj = session.execute(
            select(model).where(*filters)
        ).scalar_one()
        return obj, False

def bulk_get_or_create(
    session: Session,
    model: type[T],
    *,
    unique_on_col: str,
    values: list[Any],
    defaults: dict[str, Any] | None = None,
) -> dict[Any, T]:
    """
    Fetch existing rows or insert new ones for a batch of values.
    Returns a mapping of value -> instance.

    Currently implemented using a SELECT then INSERT approach for simplicity.
    Can be optimized further with INSERT ... ON CONFLICT if needed.
    """
    if not values:
        return {}

    values = list(set(values))  # Unique values only
    
    # 1. Fetch existing
    col = getattr(model, unique_on_col)
    existing = session.execute(
        select(model).where(col.in_(values))
    ).scalars().all()
    
    mapping = {getattr(obj, unique_on_col): obj for obj in existing}
    
    # 2. Identify missing
    missing_values = [v for v in values if v not in mapping]
    
    if missing_values:
        for val in missing_values:
            kwargs = {unique_on_col: val}
            if defaults:
                kwargs.update(defaults)
            obj = model(**kwargs)
            session.add(obj)
        
        try:
            with session.begin_nested():
                session.flush()
        except IntegrityError:
            # Race condition: someone else inserted some of these.
            # Re-fetch everything to be safe.
            session.rollback() # Rolls back the nested transaction
            existing = session.execute(
                select(model).where(col.in_(values))
            ).scalars().all()
            mapping = {getattr(obj, unique_on_col): obj for obj in existing}
        else:
            # Re-fetch or just update mapping from session
            # For simplicity, just re-fetch to ensure we have IDs
            existing = session.execute(
                select(model).where(col.in_(values))
            ).scalars().all()
            mapping = {getattr(obj, unique_on_col): obj for obj in existing}
            
    return mapping
