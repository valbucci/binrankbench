"""
Core entity models: Project → Binary → Function.

``FunctionName``     — deduplicated function name strings.
``FunctionScalars``  — raw algorithm-agnostic integer metrics per function.
``StrategyMembership`` — records which signature strategies have been computed
                          for each function (bookkeeping; one row per (function, strategy)).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import (
    BigInteger, ForeignKey, Integer, SmallInteger,
    String, Text, UniqueConstraint, LargeBinary
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .signatures.ccbhash import FunctionCCBHash
    from .signatures.fss import FunctionFSSOriginal, FunctionFSSMarcelli, FunctionFSSMarcelliWeighted
    from .signatures.machoke import FunctionMachoke
    from .signatures.bytes import FunctionByteSig
    from .signatures.catalog1 import FunctionCatalog1


class Project(Base):
    __tablename__ = "project"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    binaries: Mapped[List["Binary"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"Project(id={self.id}, name={self.name!r})"


class Binary(Base):
    __tablename__ = "binary"
    __table_args__ = (UniqueConstraint("project_id", "bin_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id", ondelete="CASCADE"), nullable=False
    )
    bin_name: Mapped[str] = mapped_column(Text, nullable=False)
    arch: Mapped[str | None] = mapped_column(String(64))
    bits: Mapped[int | None] = mapped_column(SmallInteger)
    cc: Mapped[str | None] = mapped_column(String(32))
    compiler: Mapped[str | None] = mapped_column(String(64))
    opt_level: Mapped[str | None] = mapped_column(String(16))
    sha256: Mapped[str | None] = mapped_column(String(64))

    project: Mapped["Project"] = relationship(back_populates="binaries")
    functions: Mapped[List["Function"]] = relationship(
        back_populates="binary", cascade="all, delete-orphan"
    )
    dataset_tags: Mapped[List["BinaryDatasetTag"]] = relationship(  # type: ignore[name-defined]
        back_populates="binary", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"Binary(id={self.id}, bin_name={self.bin_name!r})"


class FunctionName(Base):
    """Deduplicated function name — one row per unique name string."""

    __tablename__ = "function_name"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"FunctionName(id={self.id}, name={self.name!r})"


class Function(Base):
    __tablename__ = "function"
    __table_args__ = (UniqueConstraint("binary_id", "func_addr"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    binary_id: Mapped[int] = mapped_column(
        ForeignKey("binary.id", ondelete="CASCADE"), nullable=False
    )
    func_addr: Mapped[str] = mapped_column(Text, nullable=False)
    name_id: Mapped[int | None] = mapped_column(
        ForeignKey("function_name.id", ondelete="SET NULL"), nullable=True, index=True
    )

    binary: Mapped["Binary"] = relationship(back_populates="functions")
    func_name: Mapped["FunctionName | None"] = relationship(lazy="joined")
    scalars: Mapped[Optional["FunctionScalars"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    strategy_memberships: Mapped[List["StrategyMembership"]] = relationship(
        back_populates="function", cascade="all, delete-orphan"
    )

    # Per-strategy pivot relationships
    ccbhash: Mapped[Optional["FunctionCCBHash"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    fss_original: Mapped[Optional["FunctionFSSOriginal"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    fss_marcelli: Mapped[Optional["FunctionFSSMarcelli"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    fss_marcelli_weighted: Mapped[Optional["FunctionFSSMarcelliWeighted"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    machoke: Mapped[Optional["FunctionMachoke"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    byte_sig: Mapped[Optional["FunctionByteSig"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )
    catalog1: Mapped[Optional["FunctionCatalog1"]] = relationship(
        back_populates="function", cascade="all, delete-orphan", uselist=False
    )

    @property
    def name(self) -> str | None:
        return self.func_name.name if self.func_name else None

    def __repr__(self) -> str:
        return f"Function(id={self.id}, addr={self.func_addr!r})"


class FunctionScalars(Base):
    """Raw, algorithm-agnostic integer properties of a function."""

    __tablename__ = "function_scalars"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # From R2FunctionInfoIn (afij)
    ninstructions: Mapped[int | None] = mapped_column(BigInteger)
    nbbs: Mapped[int | None] = mapped_column(BigInteger)
    indegree: Mapped[int | None] = mapped_column(BigInteger)
    outdegree: Mapped[int | None] = mapped_column(BigInteger)
    nlocals: Mapped[int | None] = mapped_column(BigInteger)
    nargs: Mapped[int | None] = mapped_column(BigInteger)
    stackframe: Mapped[int | None] = mapped_column(BigInteger)
    size: Mapped[int | None] = mapped_column(BigInteger)

    # From R2GraphZignature (zj → graph)
    cc: Mapped[int | None] = mapped_column(BigInteger)
    ebbs: Mapped[int | None] = mapped_column(BigInteger)
    edges: Mapped[int | None] = mapped_column(BigInteger)
    bbsum: Mapped[int | None] = mapped_column(BigInteger)

    function: Mapped["Function"] = relationship(back_populates="scalars")


class StrategyMembership(Base):
    """
    Records which signature strategies have been computed for each function.

    Useful for avoiding re-analysis and for auditing coverage.
    ``strategy_id`` references the ``strategy_type`` seeded lookup table.
    """

    __tablename__ = "strategy_membership"
    __table_args__ = (UniqueConstraint("function_id", "strategy_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), nullable=False, index=True
    )
    strategy_id: Mapped[int] = mapped_column(
        ForeignKey("strategy_type.id"), nullable=False
    )

    function: Mapped["Function"] = relationship(back_populates="strategy_memberships")


class SkipReason(Base):
    """Normalised skip-reason string — one row per unique explanation."""

    __tablename__ = "skip_reason"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"SkipReason(id={self.id}, explanation={self.explanation!r})"


class SkipLog(Base):
    """One row per (function, task_type) that was skipped during ingestion.

    ORM traversal examples::

        skip_log.function.func_addr   # → hex address string
        skip_log.function.binary      # → Binary row
        skip_log.reason.explanation   # → human-readable reason string
    """

    __tablename__ = "skip_log"
    __table_args__ = (UniqueConstraint("function_id", "strategy_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    function_id: Mapped[int] = mapped_column(
        ForeignKey("function.id", ondelete="CASCADE"), nullable=False, index=True
    )
    strategy_id: Mapped[int] = mapped_column(
        ForeignKey("strategy_type.id", ondelete="CASCADE"), nullable=False
    )
    reason_id: Mapped[int] = mapped_column(
        ForeignKey("skip_reason.id"), nullable=False
    )

    function: Mapped["Function"] = relationship(lazy="joined")
    reason: Mapped["SkipReason"] = relationship(lazy="joined")

    def __repr__(self) -> str:
        return f"SkipLog(id={self.id}, strategy_id={self.strategy_id!r})"
