"""Tests for randomized MAC merging heuristics (src/mac_merge.py)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from src.database import get_session
from src.mac_merge import (
    MergeCandidate,
    auto_merge_randomized,
    find_merge_candidates,
    merge_device,
)
from src.models import Base, Device, VisibilityWindow

# Randomized MAC: locally-administered bit set in first octet (0x02 & 0x02 != 0)
_RAND_MAC = "02:BB:CC:DD:EE:01"
_RAND_MAC2 = "02:BB:CC:DD:EE:02"
# Globally-administered MAC: 0xB8 & 0x02 == 0 (stable, OUI-assigned)
_GLOBAL_MAC = "B8:27:EB:01:02:03"
_GLOBAL_MAC2 = "B8:27:EB:01:02:04"


@pytest.fixture()
def engine():
    """In-memory SQLite engine."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    return eng


def _make_device(session, mac: str, device_type: str = "wifi_client", **kwargs) -> Device:
    now = datetime.now(UTC)
    d = Device(
        mac_address=mac,
        device_type=device_type,
        created_at=now,
        updated_at=now,
        **kwargs,
    )
    session.add(d)
    session.flush()
    return d


def _make_window(
    session,
    mac: str,
    first_seen: datetime,
    last_seen: datetime,
) -> VisibilityWindow:
    w = VisibilityWindow(
        mac_address=mac,
        first_seen=first_seen,
        last_seen=last_seen,
        scan_count=1,
    )
    session.add(w)
    session.flush()
    return w


# ---------------------------------------------------------------------------
# find_merge_candidates
# ---------------------------------------------------------------------------


class TestFindMergeCandidates:
    """Tests for find_merge_candidates()."""

    def test_no_candidates_for_global_mac(self, engine):
        """Global MAC has no merge candidates (not randomized)."""
        with get_session(engine) as session:
            device = _make_device(session, _GLOBAL_MAC, device_name="Laptop")
            _make_device(session, _GLOBAL_MAC2, device_name="Laptop")
            candidates = find_merge_candidates(session, device)
        assert candidates == []

    def test_no_candidates_when_already_merged(self, engine):
        """Already-merged device returns no candidates."""
        with get_session(engine) as session:
            device = _make_device(session, _RAND_MAC, device_name="Phone", merged_into=_GLOBAL_MAC)
            _make_device(session, _GLOBAL_MAC, device_name="Phone")
            candidates = find_merge_candidates(session, device)
        assert candidates == []

    def test_high_confidence_name_and_vendor(self, engine):
        """Name + vendor match → high confidence."""
        with get_session(engine) as session:
            rand_dev = _make_device(session, _RAND_MAC, device_name="Alice's iPhone", vendor="Apple")
            _make_device(session, _GLOBAL_MAC, device_name="Alice's iPhone", vendor="Apple")
            candidates = find_merge_candidates(session, rand_dev)

        assert len(candidates) >= 1
        best = candidates[0]
        assert best.source_mac == _RAND_MAC
        assert best.target_mac == _GLOBAL_MAC
        assert best.confidence == "high"

    def test_medium_confidence_name_only(self, engine):
        """Name match without vendor → medium confidence."""
        with get_session(engine) as session:
            rand_dev = _make_device(session, _RAND_MAC, device_name="iPad")
            _make_device(session, _GLOBAL_MAC, device_name="iPad")
            candidates = find_merge_candidates(session, rand_dev)

        assert len(candidates) >= 1
        assert candidates[0].confidence == "medium"

    def test_low_confidence_ip_only(self, engine):
        """IP-only match → low confidence."""
        with get_session(engine) as session:
            rand_dev = _make_device(session, _RAND_MAC, ip_address="192.168.1.50")
            _make_device(session, _GLOBAL_MAC, ip_address="192.168.1.50")
            candidates = find_merge_candidates(session, rand_dev)

        assert len(candidates) >= 1
        assert candidates[0].confidence == "low"

    def test_temporal_overlap_downgrades_to_low(self, engine):
        """Temporal overlap downgrades high confidence to low."""
        now = datetime.now(UTC)
        with get_session(engine) as session:
            rand_dev = _make_device(session, _RAND_MAC, device_name="Phone", vendor="Samsung")
            _make_device(session, _GLOBAL_MAC, device_name="Phone", vendor="Samsung")
            # Add overlapping windows
            _make_window(session, _RAND_MAC, now - timedelta(hours=2), now - timedelta(hours=1))
            _make_window(session, _GLOBAL_MAC, now - timedelta(hours=3), now - timedelta(hours=1, minutes=30))
            session.commit()
            candidates = find_merge_candidates(session, rand_dev)

        assert len(candidates) >= 1
        assert candidates[0].confidence == "low"
        assert any("temporal overlap" in r for r in candidates[0].reasons)

    def test_no_match_different_type(self, engine):
        """Different device_type prevents matching."""
        with get_session(engine) as session:
            rand_dev = _make_device(session, _RAND_MAC, device_type="bluetooth", device_name="Speaker")
            _make_device(session, _GLOBAL_MAC, device_type="wifi_client", device_name="Speaker")
            candidates = find_merge_candidates(session, rand_dev)

        assert candidates == []

    def test_no_match_randomized_anchor_excluded(self, engine):
        """A randomized MAC is not used as a merge target."""
        with get_session(engine) as session:
            rand_dev = _make_device(session, _RAND_MAC, device_name="Tablet")
            _make_device(session, _RAND_MAC2, device_name="Tablet")  # also randomized
            candidates = find_merge_candidates(session, rand_dev)

        assert candidates == []


# ---------------------------------------------------------------------------
# merge_device
# ---------------------------------------------------------------------------


class TestMergeDevice:
    """Tests for merge_device()."""

    def test_merge_moves_windows(self, engine):
        """Visibility windows are re-attributed to the target MAC."""
        now = datetime.now(UTC)
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC)
            _make_device(session, _GLOBAL_MAC)
            _make_window(session, _RAND_MAC, now - timedelta(hours=2), now - timedelta(hours=1))
            _make_window(session, _RAND_MAC, now - timedelta(hours=4), now - timedelta(hours=3))
            session.commit()

        with get_session(engine) as session:
            count = merge_device(session, _RAND_MAC, _GLOBAL_MAC)

        assert count == 2

        with get_session(engine) as session:
            windows = session.query(VisibilityWindow).filter_by(mac_address=_GLOBAL_MAC).all()
            assert len(windows) == 2
            source = session.query(Device).filter_by(mac_address=_RAND_MAC).first()
            assert source is not None
            assert source.merged_into == _GLOBAL_MAC

    def test_merge_dry_run_no_changes(self, engine):
        """Dry-run does not modify the database."""
        now = datetime.now(UTC)
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC)
            _make_device(session, _GLOBAL_MAC)
            _make_window(session, _RAND_MAC, now - timedelta(hours=1), now)
            session.commit()

        with get_session(engine) as session:
            merge_device(session, _RAND_MAC, _GLOBAL_MAC, dry_run=True)

        with get_session(engine) as session:
            windows = session.query(VisibilityWindow).filter_by(mac_address=_RAND_MAC).all()
            assert len(windows) == 1  # unchanged
            source = session.query(Device).filter_by(mac_address=_RAND_MAC).first()
            assert source.merged_into is None  # unchanged

    def test_merge_raises_for_global_source(self, engine):
        """Merging a globally-administered MAC raises ValueError."""
        with get_session(engine) as session:
            _make_device(session, _GLOBAL_MAC)
            _make_device(session, _GLOBAL_MAC2)
            session.commit()

        with get_session(engine) as session, pytest.raises(ValueError, match="not randomized"):
            merge_device(session, _GLOBAL_MAC, _GLOBAL_MAC2)

    def test_merge_raises_for_randomized_target(self, engine):
        """Merging into a randomized MAC raises ValueError."""
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC)
            _make_device(session, _RAND_MAC2)
            session.commit()

        with get_session(engine) as session, pytest.raises(ValueError, match="itself randomized"):
            merge_device(session, _RAND_MAC, _RAND_MAC2)

    def test_merge_raises_for_missing_source(self, engine):
        """Missing source device raises ValueError."""
        with get_session(engine) as session:
            _make_device(session, _GLOBAL_MAC)
            session.commit()

        with get_session(engine) as session, pytest.raises(ValueError, match="Source device not found"):
            merge_device(session, _RAND_MAC, _GLOBAL_MAC)

    def test_merge_raises_for_missing_target(self, engine):
        """Missing target device raises ValueError."""
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC)
            session.commit()

        with get_session(engine) as session, pytest.raises(ValueError, match="Target device not found"):
            merge_device(session, _RAND_MAC, _GLOBAL_MAC)


# ---------------------------------------------------------------------------
# auto_merge_randomized
# ---------------------------------------------------------------------------


class TestAutoMergeRandomized:
    """Tests for auto_merge_randomized()."""

    def test_dry_run_returns_candidates(self, engine):
        """Dry-run returns candidates without modifying the DB."""
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC, device_name="TV", vendor="LG")
            _make_device(session, _GLOBAL_MAC, device_name="TV", vendor="LG")
            session.commit()

        with get_session(engine) as session:
            acted = auto_merge_randomized(session, min_confidence="high", dry_run=True)

        assert len(acted) >= 1
        assert isinstance(acted[0], MergeCandidate)

    def test_dry_run_does_not_merge(self, engine):
        """Dry-run does not modify merged_into."""
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC, device_name="TV", vendor="LG")
            _make_device(session, _GLOBAL_MAC, device_name="TV", vendor="LG")
            session.commit()

        with get_session(engine) as session:
            auto_merge_randomized(session, dry_run=True)

        with get_session(engine) as session:
            source = session.query(Device).filter_by(mac_address=_RAND_MAC).first()
            assert source.merged_into is None

    def test_live_run_merges(self, engine):
        """Live run (dry_run=False) actually sets merged_into."""
        with get_session(engine) as session:
            _make_device(session, _RAND_MAC, device_name="TV", vendor="LG")
            _make_device(session, _GLOBAL_MAC, device_name="TV", vendor="LG")
            session.commit()

        with get_session(engine) as session:
            auto_merge_randomized(session, min_confidence="high", dry_run=False)

        with get_session(engine) as session:
            source = session.query(Device).filter_by(mac_address=_RAND_MAC).first()
            assert source.merged_into == _GLOBAL_MAC

    def test_medium_threshold_not_merged_at_high(self, engine):
        """medium-confidence candidate is not acted on with min_confidence='high'."""
        with get_session(engine) as session:
            # No vendor → medium confidence
            _make_device(session, _RAND_MAC, device_name="Laptop")
            _make_device(session, _GLOBAL_MAC, device_name="Laptop")
            session.commit()

        with get_session(engine) as session:
            acted = auto_merge_randomized(session, min_confidence="high", dry_run=True)

        # 'medium' > threshold for 'high' → not included
        assert all(c.confidence == "high" for c in acted)
