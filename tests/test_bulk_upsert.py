"""Tests for bulk_upsert_network_devices() in src/device_tracker.py."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from src.device_tracker import bulk_upsert_network_devices
from src.models import Base, Device
from src.network_discovery import NetworkDevice


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _make_device(mac: str, ip: str = "10.0.0.1", hostname: str | None = None) -> NetworkDevice:
    return NetworkDevice(mac_address=mac, ip_address=ip, hostname=hostname, vendor=None)


class TestBulkUpsertNetworkDevices:
    """Unit tests for bulk_upsert_network_devices()."""

    @pytest.mark.timeout(10)
    def test_empty_list_returns_zero(self, db_session: Session) -> None:
        count = bulk_upsert_network_devices(db_session, [])
        assert count == 0

    @pytest.mark.timeout(10)
    def test_inserts_new_devices(self, db_session: Session) -> None:
        devices = [
            _make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1"),
            _make_device("11:22:33:44:55:66", "10.0.0.2"),
        ]
        count = bulk_upsert_network_devices(db_session, devices)
        db_session.commit()

        assert count == 2
        all_devices = db_session.query(Device).all()
        macs = {d.mac_address for d in all_devices}
        assert "AA:BB:CC:DD:EE:FF" in macs
        assert "11:22:33:44:55:66" in macs

    @pytest.mark.timeout(10)
    def test_updates_existing_device(self, db_session: Session) -> None:
        db_session.add(Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="network", ip_address="10.0.0.1"))
        db_session.commit()

        # Same MAC, new IP
        devices = [_make_device("AA:BB:CC:DD:EE:FF", ip="10.0.0.99")]
        bulk_upsert_network_devices(db_session, devices)
        db_session.commit()

        device = db_session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:FF").one()
        assert device.ip_address == "10.0.0.99"

    @pytest.mark.timeout(10)
    def test_skips_devices_without_mac(self, db_session: Session) -> None:
        devices = [NetworkDevice(mac_address="", ip_address="10.0.0.1")]
        count = bulk_upsert_network_devices(db_session, devices)
        assert count == 0

    @pytest.mark.timeout(10)
    def test_device_type_set_to_network(self, db_session: Session) -> None:
        devices = [_make_device("AA:BB:CC:DD:EE:FF")]
        bulk_upsert_network_devices(db_session, devices)
        db_session.commit()

        device = db_session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:FF").one()
        assert device.device_type == "network"
