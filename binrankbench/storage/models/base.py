"""
Shared SQLAlchemy declarative base for the binrankbench storage layer.

All ORM models import `Base` from here — never re-declare it.
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Project-wide declarative base class."""
    pass
