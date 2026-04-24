"""Shared pytest fixtures for the Net Sentry test suite.

Provides deterministic mock scanner data so tests run without real hardware
(WiFi adaptor, Bluetooth, network interfaces, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from src.bluetooth_scanner import BluetoothDevice
from src.models import Base, Device, VisibilityWindow
from src.network_discovery import NetworkDevice
from src.wifi_scanner import WifiNetwork

# ---------------------------------------------------------------------------
# Fixed timestamps for reproducible tests
# ---------------------------------------------------------------------------
_T0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2025, 1, 1, 12, 5, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# In-memory database fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def in_memory_engine():
    """Create a fresh in-memory SQLite engine with all tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def db_session(in_memory_engine) -> Generator[Session, None, None]:
    """Yield a database session backed by the in-memory engine."""
    from src.database import get_session

    with get_session(in_memory_engine) as session:
        yield session


# ---------------------------------------------------------------------------
# Mock scanner data fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_wifi_networks() -> list[WifiNetwork]:
    """Return a deterministic list of mock WiFi network objects."""
    return [
        WifiNetwork(
            ssid="TestNet-Office",
            bssid="AA:BB:CC:00:01:01",
            network_type="Infrastructure",
            authentication="WPA2-Personal",
            encryption="CCMP",
            signal_percent=80,
            signal_dbm=-55.0,
            radio_type="802.11ac",
            channel=6,
            vendor="Mock Vendor",
            scan_time=_T0,
        ),
        WifiNetwork(
            ssid="TestNet-IoT",
            bssid="AA:BB:CC:00:01:02",
            network_type="Infrastructure",
            authentication="Open",
            encryption="None",
            signal_percent=40,
            signal_dbm=-75.0,
            radio_type="802.11n",
            channel=11,
            vendor="Mock Vendor",
            scan_time=_T0,
        ),
    ]


@pytest.fixture()
def mock_bluetooth_devices() -> list[BluetoothDevice]:
    """Return a deterministic list of mock Bluetooth device objects."""
    return [
        BluetoothDevice(
            mac_address="BB:CC:DD:00:02:01",
            device_name="Test Headphones",
            is_connected=False,
            is_paired=True,
            device_class="Audio",
            vendor="Mock BT Vendor",
            scan_time=_T0,
        ),
        BluetoothDevice(
            mac_address="BB:CC:DD:00:02:02",
            device_name="Test Speaker",
            is_connected=True,
            is_paired=False,
            device_class="Audio",
            vendor="Mock BT Vendor 2",
            scan_time=_T0,
        ),
    ]


@pytest.fixture()
def mock_arp_devices() -> list[NetworkDevice]:
    """Return a deterministic list of mock ARP-discovered network devices."""
    return [
        NetworkDevice(
            ip_address="192.168.1.10",
            mac_address="CC:DD:EE:00:03:01",
            interface="eth0",
            hostname="printer.local",
            vendor="Mock Net Vendor",
            arp_type="dynamic",
            network_segment="office",
            scan_time=_T0,
        ),
        NetworkDevice(
            ip_address="192.168.1.20",
            mac_address="CC:DD:EE:00:03:02",
            interface="eth0",
            hostname="nas.local",
            vendor="Synology",
            arp_type="dynamic",
            network_segment="office",
            scan_time=_T0,
        ),
    ]


@pytest.fixture()
def seeded_device(db_session: Session) -> Device:
    """Insert a single known Device + VisibilityWindow and return the Device."""
    device = Device(
        mac_address="AA:BB:CC:11:22:33",
        device_type="wifi_ap",
        vendor="TestVendor",
        device_name="TestRouter",
        ssid="TestNet",
        category="access_point",
        is_whitelisted=False,
        created_at=_T0,
        updated_at=_T0,
    )
    db_session.add(device)
    db_session.flush()

    window = VisibilityWindow(
        mac_address=device.mac_address,
        first_seen=_T0,
        last_seen=_T1,
        signal_strength_dbm=-60.0,
        scan_count=3,
    )
    db_session.add(window)
    db_session.commit()
    return device
