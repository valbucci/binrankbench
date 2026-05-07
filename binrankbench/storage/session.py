"""
Database session and engine factory.

Usage
-----
    from binrankbench.storage.session import get_engine, get_session, init_db

    engine = get_engine("postgresql+psycopg2://user:pw@localhost/binrankbench")
    init_db(engine)                    # CREATE TABLE IF NOT EXISTS for all models
    with get_session(engine) as sess:
        sess.add(project)
        sess.commit()

Environment variable
--------------------
    BINRANKBENCH_DB_URL   — default DSN used by ``get_engine()`` when no url is passed.
    Uses the project configuration ``storage.db_url`` as the ultimate fallback.
"""
from __future__ import annotations


import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from binrankbench.common.config import load_config
from .models import Base  # triggers model registration


# ---------------------------------------------------------------------------
# Engine factory
# ---------------------------------------------------------------------------

_DEFAULT_URL_ENV = "BINRANKBENCH_DB_URL"


def get_engine(url: str | None = None, **kwargs: object) -> Engine:
    """
    Create (or return) a SQLAlchemy engine.

    Parameters
    ----------
    url:
        SQLAlchemy DSN, e.g. ``"postgresql+psycopg2://user:pw@host/db"``.
        Falls back to the ``BINRANKBENCH_DB_URL`` env variable if omitted,
        and then to the project configuration ``storage.db_url`` if still missing.
    **kwargs:
        Passed directly to ``create_engine()`` (e.g. ``pool_size=10``).
    """
    resolved = url or os.environ.get(_DEFAULT_URL_ENV) or load_config().storage.get("db_url")
    if not resolved:
        raise ValueError(
            f"No database URL provided. Pass url=, set {_DEFAULT_URL_ENV}, "
            f"or specify storage.db_url in configuration.yml."
        )
    return create_engine(resolved, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Schema management
# ---------------------------------------------------------------------------

def init_db(engine: Engine) -> None:
    """
    Create all tables that do not yet exist and seed static lookup rows.

    Safe to call on every startup — uses ``CREATE TABLE IF NOT EXISTS``.
    """
    Base.metadata.create_all(engine)
    _seed_strategy_types(engine)


def drop_db(engine: Engine) -> None:
    """Drop all tables — useful for test teardown."""
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
            conn.execute(text("GRANT ALL ON SCHEMA public TO postgres;"))
            conn.execute(text("GRANT ALL ON SCHEMA public TO public;"))
    else:
        Base.metadata.drop_all(engine)


def _seed_strategy_types(engine: Engine) -> None:
    """
    Insert a row into ``strategy_type`` for every ``StrategyID`` member.

    Idempotent — existing rows are left untouched.  Must be called after
    ``create_all`` so the table exists.  The FK on ``signature.strategy_id``
    enforces validity, making the old trigger-based allow-list unnecessary.
    """
    from .models.signatures.strategy_type import StrategyID, StrategyType

    with Session(engine) as sess:
        for s in StrategyID:
            if sess.get(StrategyType, s.value) is None:
                sess.add(StrategyType(id=s.value, name=s.name))
        sess.commit()


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a sessionmaker bound to ``engine``."""
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def get_session(engine: Engine) -> Generator[Session, None, None]:
    """
    Context manager yielding a transactional session.

    Commits on clean exit; rolls back and re-raises on exception.

    Example
    -------
        with get_session(engine) as sess:
            sess.add(some_object)
    """
    factory = make_session_factory(engine)
    with factory() as sess:
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
