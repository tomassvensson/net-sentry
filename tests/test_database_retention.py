"""Tests for src/database.py — data retention / VACUUM helpers."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine

from src.database import purge_old_windows
from src.models import Base, VisibilityWindow


def _in_memory_engine():
    """Create a fresh in-memory SQLite engine with schema applied."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


def _make_window(session, mac: str, days_ago_end: float) -> VisibilityWindow:
    """Insert a VisibilityWindow whose last_seen is ``days_ago_end`` days in the past."""
    now = datetime.now(timezone.utc)
    end = now - timedelta(days=days_ago_end)
    start = end - timedelta(hours=1)
    window = VisibilityWindow(
        mac_address=mac,
        first_seen=start,
        last_seen=end,
    )
    session.add(window)
    session.flush()
    return window


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_purge_old_windows_zero_retention_keeps_all():
    """retention_days=0 should keep every row (no deletion)."""
    from sqlalchemy.orm import Session

    engine = _in_memory_engine()
    with Session(engine) as session:
        _make_window(session, "AA:BB:CC:DD:EE:01", days_ago_end=100)
        _make_window(session, "AA:BB:CC:DD:EE:01", days_ago_end=200)
        session.commit()

    deleted = purge_old_windows(engine, retention_days=0)

    with Session(engine) as session:
        count = session.query(VisibilityWindow).count()

    assert deleted == 0
    assert count == 2


def test_purge_old_windows_removes_old_records():
    """Windows older than retention_days should be deleted; newer ones kept."""
    from sqlalchemy.orm import Session

    engine = _in_memory_engine()
    with Session(engine) as session:
        _make_window(session, "AA:BB:CC:DD:EE:02", days_ago_end=60)  # old — should be deleted
        _make_window(session, "AA:BB:CC:DD:EE:02", days_ago_end=10)  # recent — should be kept
        session.commit()

    deleted = purge_old_windows(engine, retention_days=30)

    with Session(engine) as session:
        remaining = session.query(VisibilityWindow).all()

    assert deleted == 1
    assert len(remaining) == 1
    # The surviving window ended only 10 days ago (SQLite stores as naive datetimes)
    last_seen = remaining[0].last_seen
    # Normalise to naive UTC for comparison regardless of SQLAlchemy dialect behaviour
    if last_seen.tzinfo is not None:
        last_seen = last_seen.replace(tzinfo=None)
    naive_cutoff = (datetime.now(timezone.utc) - timedelta(days=11)).replace(tzinfo=None)
    assert last_seen > naive_cutoff


def test_purge_old_windows_all_old_records():
    """All records older than retention_days are deleted."""
    from sqlalchemy.orm import Session

    engine = _in_memory_engine()
    with Session(engine) as session:
        _make_window(session, "AA:BB:CC:DD:EE:03", days_ago_end=90)
        _make_window(session, "AA:BB:CC:DD:EE:03", days_ago_end=120)
        session.commit()

    deleted = purge_old_windows(engine, retention_days=30)

    with Session(engine) as session:
        count = session.query(VisibilityWindow).count()

    assert deleted == 2
    assert count == 0


def test_purge_old_windows_does_not_raise():
    """purge_old_windows completes without exceptions on a real SQLite engine."""
    from sqlalchemy.orm import Session

    engine = _in_memory_engine()
    with Session(engine) as session:
        _make_window(session, "AA:BB:CC:DD:EE:04", days_ago_end=60)
        session.commit()

    # Just run for real and verify it doesn't crash
    deleted = purge_old_windows(engine, retention_days=30)
    assert deleted >= 0


def test_purge_old_windows_no_vacuum_when_no_rows_deleted():
    """VACUUM should not run if no rows were deleted (avoids unnecessary disk I/O)."""
    from sqlalchemy.orm import Session

    engine = _in_memory_engine()
    with Session(engine) as session:
        _make_window(session, "AA:BB:CC:DD:EE:05", days_ago_end=5)  # very recent — not deleted
        session.commit()

    # Track VACUUM calls by wrapping the raw DBAPI connection
    vacuum_issued = []

    from sqlalchemy import event as sa_event  # noqa: PLC0415

    @sa_event.listens_for(engine, "before_execute")
    def _track(conn, clauseelement, multiparams, params, execution_options):
        sql = str(clauseelement)
        if "VACUUM" in sql.upper():
            vacuum_issued.append(sql)

    deleted = purge_old_windows(engine, retention_days=30)

    assert deleted == 0
    assert vacuum_issued == [], "VACUUM should not run when nothing was deleted"
