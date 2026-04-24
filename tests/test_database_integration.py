"""Integration tests for the database layer using TestContainers (PostgreSQL).

These tests spin up a real PostgreSQL container and verify that:
- SQLAlchemy models map correctly to a non-SQLite database.
- Alembic migrations apply cleanly from scratch.
- CRUD operations work end-to-end.
- The _migrate_missing_columns helper is a no-op when columns already exist.

Tests are skipped automatically when Docker is unavailable (local Windows
without Docker Desktop, Windows CI runners, etc.).
"""

from __future__ import annotations

import logging

import pytest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Availability guards — skip entire module if testcontainers or Docker is
# missing rather than failing hard.
# ---------------------------------------------------------------------------
testcontainers = pytest.importorskip(
    "testcontainers.postgres",
    reason="testcontainers[postgres] not installed — integration tests skipped",
)

try:
    import docker

    _docker_client = docker.from_env()
    _docker_client.ping()
    _DOCKER_AVAILABLE = True
except Exception:
    _DOCKER_AVAILABLE = False

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker daemon not available"),
]

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_container():
    """Start a PostgreSQL container for the test module and tear it down after."""
    from testcontainers.postgres import PostgreSqlContainer

    with PostgreSqlContainer(
        image="postgres:16-alpine",
        driver="pg8000",
    ) as pg:
        yield pg


@pytest.fixture
def pg_engine(pg_container):
    """Create a fresh SQLAlchemy engine + schema for each test function."""
    from sqlalchemy import create_engine

    from src.models import Base

    engine = create_engine(pg_container.get_connection_url(), echo=False)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


# ---------------------------------------------------------------------------
# Table creation tests
# ---------------------------------------------------------------------------


class TestPostgresTableCreation:
    """Verify that all ORM tables are created correctly on PostgreSQL."""

    @pytest.mark.timeout(120)
    def test_devices_table_exists(self, pg_engine) -> None:
        from sqlalchemy import inspect

        inspector = inspect(pg_engine)
        assert "devices" in inspector.get_table_names()

    @pytest.mark.timeout(120)
    def test_visibility_windows_table_exists(self, pg_engine) -> None:
        from sqlalchemy import inspect

        inspector = inspect(pg_engine)
        assert "visibility_windows" in inspector.get_table_names()

    @pytest.mark.timeout(120)
    def test_devices_columns(self, pg_engine) -> None:
        from sqlalchemy import inspect

        inspector = inspect(pg_engine)
        cols = {c["name"] for c in inspector.get_columns("devices")}
        required = {
            "id",
            "mac_address",
            "device_type",
            "vendor",
            "device_name",
            "ssid",
            "hostname",
            "ip_address",
            "category",
            "is_whitelisted",
            "reconnect_count",
            "created_at",
            "updated_at",
        }
        assert required.issubset(cols), f"Missing columns: {required - cols}"


# ---------------------------------------------------------------------------
# CRUD tests
# ---------------------------------------------------------------------------


class TestPostgresCRUD:
    """Basic create-read-update-delete operations against PostgreSQL."""

    @pytest.mark.timeout(120)
    def test_insert_and_query_device(self, pg_engine) -> None:
        from src.database import get_session
        from src.models import Device

        with get_session(pg_engine) as session:
            device = Device(
                mac_address="AA:BB:CC:DD:EE:01",
                device_type="wifi_ap",
                vendor="Test Vendor",
                ssid="IntegrationNet",
            )
            session.add(device)
            session.flush()

            loaded = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:01").first()
            assert loaded is not None
            assert loaded.vendor == "Test Vendor"
            assert loaded.ssid == "IntegrationNet"

    @pytest.mark.timeout(120)
    def test_mac_uniqueness_enforced(self, pg_engine) -> None:
        from sqlalchemy.exc import IntegrityError

        from src.database import get_session
        from src.models import Device

        with pytest.raises(IntegrityError), get_session(pg_engine) as session:
            session.add(Device(mac_address="AA:BB:CC:DD:EE:02", device_type="wifi_ap"))
            session.add(Device(mac_address="AA:BB:CC:DD:EE:02", device_type="bluetooth"))
            session.flush()

    @pytest.mark.timeout(120)
    def test_insert_visibility_window(self, pg_engine) -> None:
        from datetime import datetime, timezone

        from src.database import get_session
        from src.models import Device, VisibilityWindow

        with get_session(pg_engine) as session:
            session.add(Device(mac_address="AA:BB:CC:DD:EE:03", device_type="bluetooth"))
            session.flush()

            now = datetime.now(timezone.utc)
            window = VisibilityWindow(
                mac_address="AA:BB:CC:DD:EE:03",
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-65.0,
                scan_count=1,
            )
            session.add(window)
            session.flush()

            loaded = session.query(VisibilityWindow).filter_by(mac_address="AA:BB:CC:DD:EE:03").first()
            assert loaded is not None
            assert loaded.signal_strength_dbm == pytest.approx(-65.0)
            assert loaded.scan_count == 1

    @pytest.mark.timeout(120)
    def test_multiple_windows_per_device(self, pg_engine) -> None:
        from datetime import datetime, timedelta, timezone

        from src.database import get_session
        from src.models import Device, VisibilityWindow

        with get_session(pg_engine) as session:
            session.add(Device(mac_address="AA:BB:CC:DD:EE:04", device_type="wifi_ap"))
            session.flush()

            base = datetime.now(timezone.utc)
            for i in range(3):
                session.add(
                    VisibilityWindow(
                        mac_address="AA:BB:CC:DD:EE:04",
                        first_seen=base + timedelta(hours=i),
                        last_seen=base + timedelta(hours=i, minutes=30),
                        signal_strength_dbm=-70.0 - i,
                    )
                )
            session.flush()

            count = session.query(VisibilityWindow).filter_by(mac_address="AA:BB:CC:DD:EE:04").count()
            assert count == 3

    @pytest.mark.timeout(120)
    def test_reconnect_count_default_zero(self, pg_engine) -> None:
        from src.database import get_session
        from src.models import Device

        with get_session(pg_engine) as session:
            device = Device(mac_address="AA:BB:CC:DD:EE:05", device_type="wifi_ap")
            session.add(device)
            session.flush()

            loaded = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:05").first()
            assert loaded is not None
            assert loaded.reconnect_count == 0

    @pytest.mark.timeout(120)
    def test_update_reconnect_count(self, pg_engine) -> None:
        from src.database import get_session
        from src.models import Device

        with get_session(pg_engine) as session:
            device = Device(mac_address="AA:BB:CC:DD:EE:06", device_type="wifi_ap")
            session.add(device)
            session.flush()

        with get_session(pg_engine) as session:
            device = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:06").first()
            assert device is not None
            device.reconnect_count = 3
            session.flush()

        with get_session(pg_engine) as session:
            device = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:06").first()
            assert device is not None
            assert device.reconnect_count == 3


# ---------------------------------------------------------------------------
# Migration helper tests
# ---------------------------------------------------------------------------


class TestMigrateColumnsPostgres:
    """Verify _migrate_missing_columns is a no-op when columns already exist."""

    @pytest.mark.timeout(120)
    def test_no_op_when_schema_up_to_date(self, pg_engine) -> None:
        """_migrate_missing_columns must not crash or alter an up-to-date schema."""
        from src.database import _migrate_missing_columns

        # Should complete without error
        _migrate_missing_columns(pg_engine)

    @pytest.mark.timeout(120)
    def test_device_count_unchanged_after_migration(self, pg_engine) -> None:
        from src.database import _migrate_missing_columns, get_session
        from src.models import Device

        with get_session(pg_engine) as session:
            session.add(Device(mac_address="AA:BB:CC:DD:EE:07", device_type="wifi_ap"))
            session.flush()

        _migrate_missing_columns(pg_engine)

        with get_session(pg_engine) as session:
            count = session.query(Device).count()
        assert count == 1


# ---------------------------------------------------------------------------
# Alembic migration tests
# ---------------------------------------------------------------------------


class TestAlembicMigrationsPostgres:
    """Run Alembic migrations against PostgreSQL from scratch."""

    @pytest.mark.timeout(120)
    def test_alembic_upgrade_head(self, pg_container) -> None:
        """Alembic migrations should apply cleanly to a fresh PostgreSQL DB."""
        from alembic.config import Config
        from sqlalchemy import create_engine, inspect

        from alembic import command

        # Point Alembic at the container URL
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", pg_container.get_connection_url())

        # Fresh engine (no tables yet)
        engine = create_engine(pg_container.get_connection_url(), echo=False)
        try:
            command.upgrade(alembic_cfg, "head")

            inspector = inspect(engine)
            tables = inspector.get_table_names()
            assert "devices" in tables, "Alembic upgrade did not create 'devices' table"
        finally:
            # Clean up so other tests start fresh
            from sqlalchemy import text

            with engine.connect() as conn:
                conn.execute(text("DROP TABLE IF EXISTS visibility_windows CASCADE"))
                conn.execute(text("DROP TABLE IF EXISTS devices CASCADE"))
                conn.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE"))
                conn.commit()
            engine.dispose()

    @pytest.mark.timeout(120)
    def test_alembic_downgrade_base(self, pg_container) -> None:
        """Alembic downgrade to base should remove all managed tables."""
        from alembic.config import Config
        from sqlalchemy import create_engine, inspect

        from alembic import command

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", pg_container.get_connection_url())

        engine = create_engine(pg_container.get_connection_url(), echo=False)
        try:
            command.upgrade(alembic_cfg, "head")
            command.downgrade(alembic_cfg, "base")

            inspector = inspect(engine)
            tables = inspector.get_table_names()
            assert "devices" not in tables
        finally:
            from sqlalchemy import text

            with engine.connect() as conn:
                conn.execute(text("DROP TABLE IF EXISTS visibility_windows CASCADE"))
                conn.execute(text("DROP TABLE IF EXISTS devices CASCADE"))
                conn.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE"))
                conn.commit()
            engine.dispose()
