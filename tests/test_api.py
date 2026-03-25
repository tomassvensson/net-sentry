"""Tests for FastAPI application and REST API endpoints."""

from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from src.api import app, get_db, set_engine
from src.database import get_session
from src.models import Base, Device, VisibilityWindow


@pytest.fixture()
def db_engine():
    """Create an in-memory database engine for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def client(db_engine):
    """Create a test client with dependency override."""

    def _override_get_db() -> Generator[Session, None, None]:
        with get_session(db_engine) as session:
            yield session

    set_engine(db_engine)
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    set_engine(None)


@pytest.fixture()
def seeded_client(db_engine):
    """Create a test client with seeded data."""
    now = datetime.now(timezone.utc)
    with get_session(db_engine) as session:
        d = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            vendor="TestVendor",
            device_name="TestDevice",
            ssid="TestNet",
            category="access_point",
            is_whitelisted=False,
            created_at=now,
            updated_at=now,
        )
        session.add(d)
        session.flush()
        w = VisibilityWindow(
            mac_address="AA:BB:CC:DD:EE:FF",
            first_seen=now,
            last_seen=now,
            signal_strength_dbm=-50.0,
            min_signal_dbm=-55.0,
            max_signal_dbm=-45.0,
            scan_count=3,
        )
        session.add(w)

    def _override_get_db() -> Generator[Session, None, None]:
        with get_session(db_engine) as session:
            yield session

    set_engine(db_engine)
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    set_engine(None)


class TestHealthCheck:
    """Tests for /api/v1/health endpoint."""

    def test_healthy_with_db(self, client) -> None:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["database"]["connected"] is True
        assert "timestamp" in data

    def test_degraded_without_engine(self) -> None:
        set_engine(None)
        app.dependency_overrides.clear()
        with patch("src.api.init_database", side_effect=RuntimeError("no db")), TestClient(app) as c:
            resp = c.get("/api/v1/health")
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["database"]["connected"] is False


class TestPrometheusMetrics:
    """Tests for /metrics endpoint."""

    def test_metrics_returns_text(self, client) -> None:
        import src.metrics  # noqa: F401 — ensure metrics registered

        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "btwifi" in resp.text


class TestListDevices:
    """Tests for GET /api/v1/devices."""

    def test_empty_db(self, client) -> None:
        resp = client.get("/api/v1/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["devices"] == []

    def test_with_data(self, seeded_client) -> None:
        resp = seeded_client.get("/api/v1/devices")
        data = resp.json()
        assert data["total"] == 1
        assert data["devices"][0]["mac_address"] == "AA:BB:CC:DD:EE:FF"

    def test_pagination_params(self, client) -> None:
        resp = client.get("/api/v1/devices?page=2&page_size=10")
        data = resp.json()
        assert data["page"] == 2
        assert data["page_size"] == 10

    def test_device_type_filter(self, seeded_client) -> None:
        resp = seeded_client.get("/api/v1/devices?device_type=bluetooth")
        data = resp.json()
        assert data["total"] == 0

        resp = seeded_client.get("/api/v1/devices?device_type=wifi_ap")
        data = resp.json()
        assert data["total"] == 1


class TestGetDevice:
    """Tests for GET /api/v1/devices/{mac_address}."""

    def test_existing_device(self, seeded_client) -> None:
        resp = seeded_client.get("/api/v1/devices/AA:BB:CC:DD:EE:FF")
        data = resp.json()
        assert data["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert data["vendor"] == "TestVendor"
        assert data["latest_window"] is not None
        assert data["latest_window"]["scan_count"] == 3

    def test_missing_device(self, client) -> None:
        resp = client.get("/api/v1/devices/00:00:00:00:00:00")
        data = resp.json()
        assert data["error"] == "Device not found"


class TestGetDeviceWindows:
    """Tests for GET /api/v1/devices/{mac}/windows."""

    def test_device_windows(self, seeded_client) -> None:
        resp = seeded_client.get("/api/v1/devices/AA:BB:CC:DD:EE:FF/windows")
        data = resp.json()
        assert data["total"] == 1
        assert data["windows"][0]["signal_strength_dbm"] == pytest.approx(-50.0)

    def test_no_windows(self, client) -> None:
        resp = client.get("/api/v1/devices/00:00:00:00:00:00/windows")
        data = resp.json()
        assert data["total"] == 0


class TestSummary:
    """Tests for GET /api/v1/summary."""

    def test_summary_empty(self, client) -> None:
        resp = client.get("/api/v1/summary")
        data = resp.json()
        assert data["total_devices"] == 0
        assert "timestamp" in data

    def test_summary_with_data(self, seeded_client) -> None:
        resp = seeded_client.get("/api/v1/summary")
        data = resp.json()
        assert data["total_devices"] == 1
        assert data["device_types"]["wifi_ap"] == 1


class TestDashboard:
    """Tests for GET / (HTMX dashboard)."""

    def test_dashboard_renders(self, client) -> None:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "BtWiFi" in resp.text

    def test_dashboard_with_data(self, seeded_client) -> None:
        resp = seeded_client.get("/")
        assert resp.status_code == 200
        assert "AA:BB:CC:DD:EE:FF" in resp.text


class TestDevicesTableFragment:
    """Tests for GET /api/v1/devices-table (HTMX fragment)."""

    def test_fragment_renders(self, client) -> None:
        resp = client.get("/api/v1/devices-table")
        assert resp.status_code == 200


class TestSetEngine:
    """Tests for set_engine helper."""

    def test_set_and_clear(self, db_engine) -> None:
        from collections.abc import Generator

        def _override() -> Generator[Session, None, None]:
            with get_session(db_engine) as session:
                yield session

        set_engine(db_engine)
        app.dependency_overrides[get_db] = _override
        with TestClient(app) as c:
            resp = c.get("/api/v1/health")
            assert resp.json()["database"]["connected"] is True
        app.dependency_overrides.clear()
        set_engine(None)


class TestSerializeDevice:
    """Tests for _serialize_device helper."""

    def test_serialize_fields(self, seeded_client) -> None:
        resp = seeded_client.get("/api/v1/devices/AA:BB:CC:DD:EE:FF")
        data = resp.json()
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data
        assert data["ssid"] == "TestNet"
