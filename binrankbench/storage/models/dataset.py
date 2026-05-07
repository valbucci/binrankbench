"""
Dataset and tagging models.

A **Dataset** is a named collection of binaries (e.g. an experiment or a
benchmark set).  The ``BinaryDatasetTag`` join-table links any number of
binaries to any number of datasets in a many-to-many relationship.

A binary can belong to zero or more datasets — the association is fully
optional.  The same binary (project + bin_name) can appear in multiple
datasets, and the same dataset can contain binaries from multiple projects.

Usage::

    from binrankbench.storage.writer import DBWriter

    with get_session(engine) as sess:
        w = DBWriter(sess)
        ds = w.get_or_create_dataset("sample_dataset", "Initial test set")
        bin_ = w.get_or_create_binary(project="git", bin_name="git_2-47-1.exe")
        w.tag_binary(bin_, ds)
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class Dataset(Base):
    """A named collection / experiment label."""

    __tablename__ = "dataset"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Back-ref to BinaryDatasetTag rows
    tags: Mapped[list["BinaryDatasetTag"]] = relationship(
        back_populates="dataset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"Dataset(id={self.id}, name={self.name!r})"


class BinaryDatasetTag(Base):
    """Many-to-many join between Binary and Dataset."""

    __tablename__ = "binary_dataset_tag"
    __table_args__ = (UniqueConstraint("binary_id", "dataset_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    binary_id: Mapped[int] = mapped_column(
        ForeignKey("binary.id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[int] = mapped_column(
        ForeignKey("dataset.id", ondelete="CASCADE"), nullable=False
    )

    binary: Mapped["Binary"] = relationship(back_populates="dataset_tags")  # type: ignore[name-defined]
    dataset: Mapped[Dataset] = relationship(back_populates="tags")

    def __repr__(self) -> str:
        return (
            f"BinaryDatasetTag(binary_id={self.binary_id}, "
            f"dataset_id={self.dataset_id})"
        )
