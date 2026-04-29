"""Database session management for Net Sentry."""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import Column, Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from src.models import Base

logger = logging.getLogger(__name__)

_DEFAULT_DB_URL = "sqlite:///net-sentry.db"


def get_database_url() -> str:
    """Get database URL from environment or use default."""
    return os.environ.get("DATABASE_URL", _DEFAULT_DB_URL)


def create_db_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine.

    Args:
        database_url: Database connection string. Defaults to env var or SQLite.

    Returns:
        SQLAlchemy Engine instance.
    """
    url = database_url or get_database_url()
    logger.info("Connecting to database: %s", url.split("@")[-1] if "@" in url else url)
    engine = create_engine(url, echo=False)
    return engine


def init_database(database_url: str | None = None) -> Engine:
    """Initialize the database, creating tables if needed.

    Also migrates existing tables by adding any missing columns
    defined in the models (handles schema evolution without Alembic).

    Args:
        database_url: Database connection string.

    Returns:
        SQLAlchemy Engine instance with tables created.
    """
    engine = create_db_engine(database_url)
    Base.metadata.create_all(engine)
    _migrate_missing_columns(engine)
    logger.info("Database tables initialized.")
    return engine


def _build_default_clause(column: Column, col_type: str) -> str:  # type: ignore[type-arg]
    """Build the DEFAULT clause for a column being added via ALTER TABLE.

    Args:
        column: SQLAlchemy Column object.
        col_type: Compiled column type string.

    Returns:
        SQL DEFAULT clause string (e.g. " DEFAULT 0") or empty string.
    """
    # Explicit model-level default
    if column.default is not None and hasattr(column.default, "arg"):
        return f" DEFAULT {column.default.arg!r}"

    if column.nullable:
        return " DEFAULT NULL"

    # server_default is handled by the DB engine; nothing extra needed here
    if column.server_default is not None:
        return ""

    # SQLite requires a default for NOT NULL columns added via ALTER TABLE
    upper_type = col_type.upper()
    if "INT" in upper_type or "BOOL" in upper_type:
        return " DEFAULT 0"
    return " DEFAULT ''"


def _migrate_missing_columns(engine: Engine) -> None:
    """Add any columns defined in models but missing from the database.

    SQLAlchemy's create_all only creates new tables — it does NOT add
    columns to existing tables.  This function inspects each table and
    issues ALTER TABLE ADD COLUMN for any that are absent.
    """
    insp = inspect(engine)

    for table_name, table in Base.metadata.tables.items():
        if not insp.has_table(table_name):
            continue  # table doesn't exist yet; create_all will handle it

        existing_columns = {col["name"] for col in insp.get_columns(table_name)}
        missing = [c for c in table.columns if c.name not in existing_columns]

        for column in missing:
            col_type = column.type.compile(engine.dialect)
            nullable = "" if column.nullable else " NOT NULL"
            default_clause = _build_default_clause(column, col_type)

            ddl = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}{nullable}{default_clause}"
            logger.info("Migrating schema: %s", ddl)
            with engine.begin() as conn:
                conn.execute(text(ddl))


def get_session_factory(engine: Engine) -> sessionmaker:
    """Create a session factory bound to the given engine.

    Args:
        engine: SQLAlchemy Engine instance.

    Returns:
        Configured sessionmaker.
    """
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def get_session(engine: Engine) -> Generator[Session, None, None]:
    """Context manager for database sessions with automatic commit/rollback.

    Args:
        engine: SQLAlchemy Engine instance.

    Yields:
        SQLAlchemy Session.
    """
    session_factory = get_session_factory(engine)
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Database session error, rolling back.")
        raise
    finally:
        session.close()


def purge_old_windows(engine: Engine, retention_days: int) -> int:
    """Delete visibility windows older than ``retention_days`` days.

    When ``retention_days`` is 0 (the default), nothing is deleted.

    After deletion, VACUUM is run on SQLite databases to reclaim space.

    Args:
        engine: SQLAlchemy Engine instance.
        retention_days: Number of days to keep.  0 = keep forever.

    Returns:
        Number of rows deleted.
    """
    if retention_days <= 0:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    deleted = 0

    with engine.begin() as conn:
        result = conn.execute(
            text("DELETE FROM visibility_windows WHERE last_seen < :cutoff"),
            {"cutoff": cutoff},
        )
        deleted = result.rowcount

    if deleted:
        logger.info("Purged %d visibility windows older than %d days", deleted, retention_days)

    # Reclaim space in SQLite only when rows were actually removed
    if deleted and "sqlite" in engine.dialect.name.lower():
        with engine.begin() as conn:
            conn.execute(text("VACUUM"))
        logger.debug("SQLite VACUUM completed after purge")

    return deleted
