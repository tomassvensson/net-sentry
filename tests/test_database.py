"""Tests for database models and session management."""

from datetime import UTC

import pytest
from sqlalchemy import create_engine, inspect, text

from src.database import _migrate_missing_columns, get_session, init_database
from src.models import Base, Device, VisibilityWindow


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


class TestDatabaseInit:
    """Tests for database initialization."""

    @pytest.mark.timeout(30)
    def test_init_creates_tables(self) -> None:
        engine = init_database("sqlite:///:memory:")
        # Verify tables exist by querying them
        with get_session(engine) as session:
            # Should not raise
            session.query(Device).all()
            session.query(VisibilityWindow).all()

    @pytest.mark.timeout(30)
    def test_init_idempotent(self) -> None:
        """Calling init_database twice should not fail."""
        engine = init_database("sqlite:///:memory:")
        # Call again — should be fine
        Base.metadata.create_all(engine)


class TestDeviceModel:
    """Tests for the Device model."""

    @pytest.mark.timeout(30)
    def test_create_wifi_device(self, in_memory_engine) -> None:
        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="AA:BB:CC:DD:EE:FF",
                device_type="wifi_ap",
                vendor="Test Vendor",
                ssid="TestNetwork",
            )
            session.add(device)
            session.flush()

            loaded = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:FF").first()
            assert loaded is not None
            assert loaded.device_type == "wifi_ap"
            assert loaded.vendor == "Test Vendor"
            assert loaded.ssid == "TestNetwork"

    @pytest.mark.timeout(30)
    def test_create_bluetooth_device(self, in_memory_engine) -> None:
        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="11:22:33:44:55:66",
                device_type="bluetooth",
                device_name="My Phone",
            )
            session.add(device)
            session.flush()

            loaded = session.query(Device).filter_by(mac_address="11:22:33:44:55:66").first()
            assert loaded is not None
            assert loaded.device_type == "bluetooth"
            assert loaded.device_name == "My Phone"

    @pytest.mark.timeout(30)
    def test_mac_address_unique(self, in_memory_engine) -> None:
        from sqlalchemy.exc import IntegrityError

        with get_session(in_memory_engine) as session:
            d1 = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
            session.add(d1)
            session.flush()

        with pytest.raises(IntegrityError), get_session(in_memory_engine) as session:
            d2 = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="bluetooth")
            session.add(d2)
            session.flush()

    @pytest.mark.timeout(30)
    def test_device_repr(self, in_memory_engine) -> None:
        device = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap", ssid="Home")
        repr_str = repr(device)
        assert "AA:BB:CC:DD:EE:FF" in repr_str
        assert "wifi_ap" in repr_str


class TestVisibilityWindowModel:
    """Tests for the VisibilityWindow model."""

    @pytest.mark.timeout(30)
    def test_create_window(self, in_memory_engine) -> None:
        from datetime import datetime

        now = datetime.now(UTC)
        with get_session(in_memory_engine) as session:
            window = VisibilityWindow(
                mac_address="AA:BB:CC:DD:EE:FF",
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-65.0,
                scan_count=1,
            )
            session.add(window)
            session.flush()

            loaded = session.query(VisibilityWindow).first()
            assert loaded is not None
            assert loaded.mac_address == "AA:BB:CC:DD:EE:FF"
            assert loaded.signal_strength_dbm == -65.0
            assert loaded.scan_count == 1

    @pytest.mark.timeout(30)
    def test_window_repr(self) -> None:
        from datetime import datetime

        now = datetime.now(UTC)
        window = VisibilityWindow(
            mac_address="AA:BB:CC:DD:EE:FF",
            first_seen=now,
            last_seen=now,
            signal_strength_dbm=-70.0,
        )
        repr_str = repr(window)
        assert "AA:BB:CC:DD:EE:FF" in repr_str


class TestMigrateMissingColumns:
    """Tests for automatic schema migration of missing columns."""

    @pytest.mark.timeout(30)
    def test_adds_missing_columns_to_existing_table(self) -> None:
        """Simulate an old DB schema missing hostname/ip_address/category/extra_info/is_whitelisted."""
        engine = create_engine("sqlite:///:memory:", echo=False)

        # Create a minimal 'devices' table missing the newer columns
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address VARCHAR(17) NOT NULL UNIQUE,
                        device_type VARCHAR(20) NOT NULL,
                        vendor VARCHAR(255),
                        device_name VARCHAR(255),
                        ssid VARCHAR(255),
                        network_type VARCHAR(50),
                        authentication VARCHAR(100),
                        encryption VARCHAR(100),
                        radio_type VARCHAR(50),
                        channel INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                    )
                    """
                )
            )
            # Also create visibility_windows so create_all won't fail
            conn.execute(
                text(
                    """
                    CREATE TABLE visibility_windows (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address VARCHAR(17) NOT NULL,
                        first_seen DATETIME NOT NULL,
                        last_seen DATETIME NOT NULL,
                        signal_strength_dbm FLOAT,
                        min_signal_dbm FLOAT,
                        max_signal_dbm FLOAT,
                        scan_count INTEGER DEFAULT 1 NOT NULL
                    )
                    """
                )
            )

        # Verify hostname is missing before migration
        insp = inspect(engine)
        old_cols = {c["name"] for c in insp.get_columns("devices")}
        assert "hostname" not in old_cols
        assert "ip_address" not in old_cols
        assert "category" not in old_cols

        # Run migration
        _migrate_missing_columns(engine)

        # Verify new columns were added
        insp = inspect(engine)
        new_cols = {c["name"] for c in insp.get_columns("devices")}
        assert "hostname" in new_cols
        assert "ip_address" in new_cols
        assert "category" in new_cols
        assert "extra_info" in new_cols
        assert "is_whitelisted" in new_cols

    @pytest.mark.timeout(30)
    def test_migration_idempotent(self) -> None:
        """Running migration twice should not fail."""
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        # First call — nothing to do
        _migrate_missing_columns(engine)
        # Second call — still nothing to do, should not raise
        _migrate_missing_columns(engine)

    @pytest.mark.timeout(30)
    def test_init_database_migrates_old_schema(self) -> None:
        """init_database should be able to query Device after migrating an old schema."""
        engine = create_engine("sqlite:///:memory:", echo=False)

        # Create old schema manually
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address VARCHAR(17) NOT NULL UNIQUE,
                        device_type VARCHAR(20) NOT NULL,
                        vendor VARCHAR(255),
                        device_name VARCHAR(255),
                        ssid VARCHAR(255),
                        network_type VARCHAR(50),
                        authentication VARCHAR(100),
                        encryption VARCHAR(100),
                        radio_type VARCHAR(50),
                        channel INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE visibility_windows (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address VARCHAR(17) NOT NULL,
                        first_seen DATETIME NOT NULL,
                        last_seen DATETIME NOT NULL,
                        signal_strength_dbm FLOAT,
                        min_signal_dbm FLOAT,
                        max_signal_dbm FLOAT,
                        scan_count INTEGER DEFAULT 1 NOT NULL
                    )
                    """
                )
            )

        # Insert a device using old schema
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO devices (mac_address, device_type) VALUES ('AA:BB:CC:DD:EE:FF', 'wifi_ap')"))

        # Now run migration
        _migrate_missing_columns(engine)

        # Query should work with the full ORM model including hostname etc.
        with get_session(engine) as session:
            device = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:FF").first()
            assert device is not None
            assert device.hostname is None
            assert device.ip_address is None
            assert device.category is None
            assert device.is_whitelisted is not None  # should have default
