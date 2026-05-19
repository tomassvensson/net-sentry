"""Tests for timeline and merge-candidates API endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from src.api import app, get_db, set_engine
from src.database import get_session
from src.models import Base, Device, VisibilityWindow

if TYPE_CHECKING:
    from collections.abc import Generator

    from sqlalchemy.orm import Session

_GLOBAL_MAC = "B8:27:EB:01:02:05"  # 0xB8 & 0x02 == 0 → globally-administered
_RAND_MAC = "02:BB:CC:DD:EE:02"  # locally-administered bit set (0x02 & 0x02 != 0)


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def _override() -> Generator[Session]:
        with get_session(engine) as session:
            yield session

    set_engine(engine)
    app.dependency_overrides[get_db] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    set_engine(None)


def _seed(engine, mac: str = _GLOBAL_MAC, windows: int = 3) -> None:
    now = datetime.now(UTC)
    with get_session(engine) as session:
        device = Device(
            mac_address=mac,
            device_type="wifi_client",
            vendor="Acme",
            device_name="TestBox",
            created_at=now,
            updated_at=now,
        )
        session.add(device)
        session.flush()
        for i in range(windows):
            offset_hours = i * 5
            session.add(
                VisibilityWindow(
                    mac_address=mac,
                    first_seen=now - timedelta(hours=offset_hours + 2),
                    last_seen=now - timedelta(hours=offset_hours + 1),
                    signal_strength_dbm=-60.0,
                    scan_count=4,
                )
            )


# ---------------------------------------------------------------------------
# Timeline endpoint tests
# ---------------------------------------------------------------------------


class TestTimelineEndpoint:
    """Tests for GET /api/v1/devices/{mac}/timeline."""

    @pytest.mark.timeout(30)
    def test_returns_windows_in_order(self, client, engine):
        _seed(engine)
        resp = client.get(f"/api/v1/devices/{_GLOBAL_MAC}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mac_address"] == _GLOBAL_MAC
        assert data["total_windows"] == 3
        # Chronological order
        window_entries = [e for e in data["entries"] if e["type"] == "window"]
        assert len(window_entries) == 3
        starts = [e["first_seen"] for e in window_entries]
        assert starts == sorted(starts)

    @pytest.mark.timeout(30)
    def test_gaps_inserted(self, client, engine):
        """Windows separated by > gap_minutes should produce gap entries."""
        _seed(engine, windows=2)  # each window is ~2h apart → 3h gap between
        resp = client.get(f"/api/v1/devices/{_GLOBAL_MAC}/timeline?gap_minutes=60")
        data = resp.json()
        types = [e["type"] for e in data["entries"]]
        assert "gap" in types

    @pytest.mark.timeout(30)
    def test_no_gaps_when_threshold_high(self, client, engine):
        """Large threshold means no gap entries."""
        _seed(engine, windows=2)
        resp = client.get(f"/api/v1/devices/{_GLOBAL_MAC}/timeline?gap_minutes=10000")
        data = resp.json()
        types = [e["type"] for e in data["entries"]]
        assert "gap" not in types

    @pytest.mark.timeout(30)
    def test_404_for_unknown_device(self, client, engine):
        resp = client.get("/api/v1/devices/00:11:22:33:44:55/timeline")
        assert resp.status_code == 404

    @pytest.mark.timeout(30)
    def test_empty_entries_for_device_without_windows(self, client, engine):
        now = datetime.now(UTC)
        with get_session(engine) as session:
            session.add(
                Device(
                    mac_address="CC:DD:EE:FF:00:11",
                    device_type="bluetooth",
                    created_at=now,
                    updated_at=now,
                )
            )
        resp = client.get("/api/v1/devices/CC:DD:EE:FF:00:11/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entries"] == []
        assert data["total_windows"] == 0

    @pytest.mark.timeout(30)
    def test_timeline_html_page(self, client, engine):
        """HTML timeline page renders without errors."""
        _seed(engine)
        resp = client.get(f"/devices/{_GLOBAL_MAC}/timeline")
        assert resp.status_code == 200
        assert b"Timeline" in resp.content

    @pytest.mark.timeout(30)
    def test_timeline_html_404_unknown(self, client, engine):
        resp = client.get("/devices/00:11:22:33:44:55/timeline")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Merge-candidates endpoint tests
# ---------------------------------------------------------------------------


class TestMergeCandidatesEndpoint:
    """Tests for GET /api/v1/devices/{mac}/merge-candidates."""

    @pytest.mark.timeout(30)
    def test_global_mac_not_randomized(self, client, engine):
        _seed(engine)
        resp = client.get(f"/api/v1/devices/{_GLOBAL_MAC}/merge-candidates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_randomized"] is False
        assert data["candidates"] == []

    @pytest.mark.timeout(30)
    def test_randomized_mac_with_candidate(self, client, engine):
        now = datetime.now(UTC)
        with get_session(engine) as session:
            session.add(
                Device(
                    mac_address=_RAND_MAC,
                    device_type="wifi_client",
                    vendor="Acme",
                    device_name="MyPhone",
                    created_at=now,
                    updated_at=now,
                )
            )
            session.add(
                Device(
                    mac_address=_GLOBAL_MAC,
                    device_type="wifi_client",
                    vendor="Acme",
                    device_name="MyPhone",
                    created_at=now,
                    updated_at=now,
                )
            )
        resp = client.get(f"/api/v1/devices/{_RAND_MAC}/merge-candidates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_randomized"] is True
        assert len(data["candidates"]) >= 1
        assert data["candidates"][0]["target_mac"] == _GLOBAL_MAC
        assert data["candidates"][0]["confidence"] == "high"

    @pytest.mark.timeout(30)
    def test_404_for_unknown_device(self, client, engine):
        resp = client.get("/api/v1/devices/02:11:22:33:44:55/merge-candidates")
        assert resp.status_code == 404
