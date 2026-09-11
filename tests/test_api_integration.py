"""Integration tests for the FastAPI server.

These tests start the FastAPI application with a real in-memory SQLite
database and hit every major endpoint to verify correct responses.
No external services (MQTT, Home Assistant, real WiFi adapter) are needed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api import app, set_engine
from src.models import Device


@pytest.fixture(autouse=True)
def _isolated_api_engine(in_memory_engine):
    """Wire up the FastAPI app with the in-memory engine before each test."""
    set_engine(in_memory_engine)
    yield
    set_engine(None)


@pytest.fixture()
def client(in_memory_engine):
    """Return a TestClient bound to the isolated in-memory engine."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Health / liveness
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_body_has_status_ok(self, client):
        data = client.get("/api/v1/health").json()
        assert data.get("status") == "healthy"


# ---------------------------------------------------------------------------
# Root / dashboard
# ---------------------------------------------------------------------------


class TestDashboardRoot:
    def test_root_returns_html(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# Devices API
# ---------------------------------------------------------------------------


class TestDevicesEndpoint:
    def test_devices_returns_200_empty(self, client):
        response = client.get("/api/v1/devices")
        assert response.status_code == 200

    def test_devices_returns_list(self, client):
        data = client.get("/api/v1/devices").json()
        # API returns paginated envelope
        assert isinstance(data, dict)
        assert "devices" in data
        assert isinstance(data["devices"], list)

    def test_devices_returns_seeded_device(self, client, seeded_device):
        data = client.get("/api/v1/devices").json()
        macs = [d["mac_address"] for d in data["devices"]]
        assert seeded_device.mac_address in macs

    def test_devices_pagination(self, client, in_memory_engine, db_session):
        """Verify limit/offset query parameters work."""

        # Add extra devices
        for i in range(5):
            db_session.add(
                Device(
                    mac_address=f"DE:AD:BE:EF:00:{i:02d}",
                    device_type="wifi_ap",
                    vendor="PaginationVendor",
                )
            )
        db_session.commit()

        page1 = client.get("/api/v1/devices?page=1&page_size=3").json()
        page2 = client.get("/api/v1/devices?page=2&page_size=3").json()

        # Both pages return the envelope
        assert "devices" in page1
        assert "devices" in page2
        # No overlap between pages
        macs1 = {d["mac_address"] for d in page1["devices"]}
        macs2 = {d["mac_address"] for d in page2["devices"]}
        assert macs1.isdisjoint(macs2)


# ---------------------------------------------------------------------------
# Device detail page
# ---------------------------------------------------------------------------


class TestDeviceDetailPage:
    def test_known_device_returns_html(self, client, seeded_device):
        response = client.get(f"/devices/{seeded_device.mac_address}")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_unknown_device_returns_404(self, client):
        response = client.get("/devices/FF:FF:FF:FF:FF:FF")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_content_type_is_text(self, client):
        response = client.get("/metrics")
        assert "text/plain" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------


class TestExportEndpoints:
    def test_export_csv_returns_200(self, client):
        response = client.get("/api/v1/export/devices.csv")
        assert response.status_code == 200

    def test_export_json_returns_200(self, client):
        response = client.get("/api/v1/export/devices.json")
        assert response.status_code == 200

    def test_export_json_is_valid_list(self, client):
        data = client.get("/api/v1/export/devices.json").json()
        assert isinstance(data, list)

    def test_export_csv_seeded_device(self, client, seeded_device):
        body = client.get("/api/v1/export/devices.csv").text
        assert seeded_device.mac_address in body


# ---------------------------------------------------------------------------
# OpenAPI docs
# ---------------------------------------------------------------------------


class TestApiDocs:
    def test_openapi_docs_returns_200(self, client):
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_json_is_valid(self, client):
        data = client.get("/openapi.json").json()
        assert "openapi" in data
