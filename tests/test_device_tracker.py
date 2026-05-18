"""Tests for device tracker (visibility window management)."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine

from src.bluetooth_scanner import BluetoothDevice
from src.database import get_session
from src.device_tracker import (
    get_all_devices_with_latest_window,
    track_bluetooth_scan,
    track_wifi_scan,
    update_visibility,
    upsert_bluetooth_device,
    upsert_wifi_device,
)
from src.models import Base, Device, VisibilityWindow
from src.wifi_scanner import WifiNetwork


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


def _make_wifi_network(**kwargs) -> WifiNetwork:
    """Create a WifiNetwork with defaults for testing."""
    defaults = {
        "ssid": "TestNet",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "network_type": "Infrastructure",
        "authentication": "WPA2-Personal",
        "encryption": "CCMP",
        "signal_percent": 75,
        "signal_dbm": -62.5,
        "radio_type": "802.11ac",
        "channel": 36,
    }
    defaults.update(kwargs)
    return WifiNetwork(**defaults)


class TestUpsertWifiDevice:
    """Tests for WiFi device upsert."""

    @pytest.mark.timeout(30)
    def test_insert_new_device(self, in_memory_engine) -> None:
        network = _make_wifi_network()
        with get_session(in_memory_engine) as session:
            device = upsert_wifi_device(session, network)
            session.flush()
            assert device.mac_address == "AA:BB:CC:DD:EE:FF"
            assert device.device_type == "wifi_ap"
            assert device.ssid == "TestNet"

    @pytest.mark.timeout(30)
    def test_update_existing_device(self, in_memory_engine) -> None:
        network1 = _make_wifi_network(ssid="OldName")
        network2 = _make_wifi_network(ssid="NewName")
        with get_session(in_memory_engine) as session:
            upsert_wifi_device(session, network1)
            session.flush()
            device = upsert_wifi_device(session, network2)
            session.flush()
            assert device.ssid == "NewName"
            # Should still be only one device
            count = session.query(Device).count()
            assert count == 1


class TestUpsertBluetoothDevice:
    """Tests for Bluetooth device upsert."""

    @pytest.mark.timeout(30)
    def test_insert_new_device(self, in_memory_engine) -> None:
        bt = BluetoothDevice(mac_address="11:22:33:44:55:66", device_name="Phone")
        with get_session(in_memory_engine) as session:
            device = upsert_bluetooth_device(session, bt)
            session.flush()
            assert device is not None
            assert device.device_type == "bluetooth"
            assert device.device_name == "Phone"

    @pytest.mark.timeout(30)
    def test_skip_no_mac(self, in_memory_engine) -> None:
        bt = BluetoothDevice(mac_address="", device_name="Unknown")
        with get_session(in_memory_engine) as session:
            device = upsert_bluetooth_device(session, bt)
            assert device is None


class TestUpdateVisibility:
    """Tests for visibility window management."""

    @pytest.mark.timeout(30)
    def test_create_new_window(self, in_memory_engine) -> None:
        now = datetime.now(timezone.utc)
        with get_session(in_memory_engine) as session:
            window, is_new, prev = update_visibility(session, "AA:BB:CC:DD:EE:FF", now, -65.0)
            session.flush()
            assert is_new is True
            assert prev is None
            assert window.first_seen == now
            assert window.last_seen == now
            assert window.signal_strength_dbm == -65.0
            assert window.scan_count == 1

    @pytest.mark.timeout(30)
    def test_extend_existing_window(self, in_memory_engine) -> None:
        now = datetime.now(timezone.utc)
        later = now + timedelta(seconds=60)
        with get_session(in_memory_engine) as session:
            update_visibility(session, "AA:BB:CC:DD:EE:FF", now, -65.0)
            session.flush()
            window, is_new, _ = update_visibility(session, "AA:BB:CC:DD:EE:FF", later, -70.0)
            session.flush()
            assert is_new is False
            # SQLite strips timezone info, so compare without tz
            assert window.first_seen.replace(tzinfo=None) == now.replace(tzinfo=None)
            assert window.last_seen.replace(tzinfo=None) == later.replace(tzinfo=None)
            assert window.scan_count == 2
            assert window.signal_strength_dbm == -70.0
            assert window.min_signal_dbm == -70.0  # -70 < -65
            assert window.max_signal_dbm == -65.0

    @pytest.mark.timeout(30)
    def test_new_window_after_gap(self, in_memory_engine) -> None:
        now = datetime.now(timezone.utc)
        much_later = now + timedelta(seconds=600)  # 10 minutes > 5 minute gap
        with get_session(in_memory_engine) as session:
            update_visibility(session, "AA:BB:CC:DD:EE:FF", now, -65.0, gap_seconds=300)
            session.flush()
            update_visibility(session, "AA:BB:CC:DD:EE:FF", much_later, -70.0, gap_seconds=300)
            session.flush()

            windows = session.query(VisibilityWindow).filter_by(mac_address="AA:BB:CC:DD:EE:FF").all()
            assert len(windows) == 2

    @pytest.mark.timeout(30)
    def test_signal_min_max_tracking(self, in_memory_engine) -> None:
        now = datetime.now(timezone.utc)
        with get_session(in_memory_engine) as session:
            update_visibility(session, "AA:BB:CC:DD:EE:FF", now, -60.0)
            update_visibility(session, "AA:BB:CC:DD:EE:FF", now + timedelta(seconds=10), -80.0)
            update_visibility(session, "AA:BB:CC:DD:EE:FF", now + timedelta(seconds=20), -50.0)
            session.flush()

            window = session.query(VisibilityWindow).first()
            assert window.min_signal_dbm == -80.0
            assert window.max_signal_dbm == -50.0


class TestTrackWifiScan:
    """Tests for WiFi scan tracking."""

    @pytest.mark.timeout(30)
    def test_track_multiple_networks(self, in_memory_engine) -> None:
        networks = [
            _make_wifi_network(bssid="AA:BB:CC:DD:EE:01", ssid="Net1"),
            _make_wifi_network(bssid="AA:BB:CC:DD:EE:02", ssid="Net2"),
        ]
        with get_session(in_memory_engine) as session:
            results = track_wifi_scan(session, networks)
            assert len(results) == 2
            session.flush()

            devices = session.query(Device).count()
            assert devices == 2


class TestTrackBluetoothScan:
    """Tests for Bluetooth scan tracking."""

    @pytest.mark.timeout(30)
    def test_track_bluetooth_devices(self, in_memory_engine) -> None:
        bt_devices = [
            BluetoothDevice(mac_address="11:22:33:44:55:01", device_name="Phone"),
            BluetoothDevice(mac_address="11:22:33:44:55:02", device_name="Headphones"),
        ]
        with get_session(in_memory_engine) as session:
            results = track_bluetooth_scan(session, bt_devices)
            assert len(results) == 2


class TestGetAllDevicesWithLatestWindow:
    """Tests for retrieving all devices with visibility data."""

    @pytest.mark.timeout(30)
    def test_returns_devices_with_windows(self, in_memory_engine) -> None:
        now = datetime.now(timezone.utc)
        with get_session(in_memory_engine) as session:
            device = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap", ssid="Test")
            session.add(device)
            session.flush()

            update_visibility(session, "AA:BB:CC:DD:EE:FF", now, -65.0)
            session.flush()

            results = get_all_devices_with_latest_window(session)
            assert len(results) == 1
            d, w = results[0]
            assert d.mac_address == "AA:BB:CC:DD:EE:FF"
            assert w is not None
            assert w.signal_strength_dbm == -65.0

    @pytest.mark.timeout(30)
    def test_returns_devices_without_windows(self, in_memory_engine) -> None:
        with get_session(in_memory_engine) as session:
            device = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
            session.add(device)
            session.flush()

            results = get_all_devices_with_latest_window(session)
            assert len(results) == 1
            _, w = results[0]
            assert w is None
