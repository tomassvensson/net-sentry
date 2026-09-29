"""Tests for presence monitoring system."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine

from src.config import PresenceWatchEntry
from src.database import get_session
from src.models import Base, Device, VisibilityWindow
from src.presence_monitor import PresenceMonitor


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


def _add_device(session, mac: str, hostname: str) -> Device:
    device = Device(
        mac_address=mac,
        device_type="network",
        hostname=hostname,
    )
    session.add(device)
    session.flush()
    return device


def _add_window(session, mac: str, first_seen: datetime, last_seen: datetime) -> VisibilityWindow:
    window = VisibilityWindow(
        mac_address=mac,
        first_seen=first_seen,
        last_seen=last_seen,
        scan_count=1,
    )
    session.add(window)
    session.flush()
    return window


class TestPresenceMonitorBaseline:
    """First check establishes baseline, never notifies."""

    def test_first_check_returns_nothing(self, in_memory_engine) -> None:
        now = datetime(2026, 4, 21, 12, 0, 0)
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=0)
        monitor = PresenceMonitor([watch])

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_window(session, "AA:BB:CC:DD:EE:01", now - timedelta(minutes=5), now)
            notifications = monitor.check(session, gap_seconds=300, now=now)

        assert notifications == []

    def test_no_matching_device(self, in_memory_engine) -> None:
        now = datetime(2026, 4, 21, 12, 0, 0)
        watch = PresenceWatchEntry(hostname="nonexistent.fritz.box")
        monitor = PresenceMonitor([watch])

        with get_session(in_memory_engine) as session:
            notifications = monitor.check(session, gap_seconds=300, now=now)

        assert notifications == []


class TestPresenceMonitorTransitions:
    """Tests for detecting state transitions."""

    def test_device_disappears_after_stable_present(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="Mi-10T-Pro.fritz.box", stable_minutes=180)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 9, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "Mi-10T-Pro.fritz.box")
            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(hours=4), t0)
            # First check: device present, baseline established
            n1 = monitor.check(session, gap_seconds=300, now=t0)
            assert n1 == []

            # Second check: 10 minutes later, device gone (last_seen was t0, now gap exceeded)
            t1 = t0 + timedelta(minutes=10)
            n2 = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n2) == 1
        assert n2[0].transition == "gone"
        assert n2[0].name == "Mi-10T-Pro.fritz.box"

    def test_device_appears_after_stable_gone(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="Mi-10T-Pro.fritz.box", stable_minutes=180)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "Mi-10T-Pro.fritz.box")
            # First check: device has no recent window → gone (baseline)
            n1 = monitor.check(session, gap_seconds=300, now=t0)
            assert n1 == []

            # Device reappears
            t1 = t0 + timedelta(minutes=5)
            _add_window(session, "AA:BB:CC:DD:EE:01", t1 - timedelta(seconds=30), t1)
            n2 = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n2) == 1
        assert n2[0].transition == "present"

    def test_stable_minutes_zero_fires_on_any_transition(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=0)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(minutes=1), t0)
            # Baseline: present
            monitor.check(session, gap_seconds=300, now=t0)

            # Device disappears
            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n) == 1
        assert n[0].transition == "gone"

    def test_fires_only_once_per_transition(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=0)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(minutes=1), t0)
            monitor.check(session, gap_seconds=300, now=t0)  # baseline

            t1 = t0 + timedelta(minutes=10)
            n1 = monitor.check(session, gap_seconds=300, now=t1)  # fires
            n2 = monitor.check(session, gap_seconds=300, now=t1 + timedelta(minutes=1))  # same state

        assert len(n1) == 1
        assert n2 == []


class TestPresenceMonitorStability:
    """Tests for stable_minutes filtering."""

    def test_not_stable_enough_suppresses(self, in_memory_engine) -> None:
        """Device was present briefly, then gone — should not fire because
        the previous state (present) wasn't held for most of the lookback."""
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=180)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            # Device was present for only 30 min in the last 3 hours
            _add_window(
                session,
                "AA:BB:CC:DD:EE:01",
                t0 - timedelta(minutes=30),
                t0,
            )
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: present

            # Device gone
            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert n == []

    def test_stable_present_then_gone_fires(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=180)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            # Device present for 2.5 hours (> 50% of 3h)
            _add_window(
                session,
                "AA:BB:CC:DD:EE:01",
                t0 - timedelta(hours=2, minutes=30),
                t0,
            )
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: present

            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n) == 1
        assert n[0].transition == "gone"


class TestPresenceMonitorFiltering:
    """Tests for notify_on_appear / notify_on_disappear filtering."""

    def test_notify_on_appear_false_suppresses(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(
            hostname="phone.local",
            stable_minutes=0,
            notify_on_appear=False,
        )
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: gone

            t1 = t0 + timedelta(minutes=1)
            _add_window(session, "AA:BB:CC:DD:EE:01", t1 - timedelta(seconds=10), t1)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert n == []

    def test_notify_on_disappear_false_suppresses(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(
            hostname="phone.local",
            stable_minutes=0,
            notify_on_disappear=False,
        )
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(minutes=1), t0)
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: present

            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert n == []


class TestPresenceMonitorMultipleDevices:
    """Tests for multiple MAC addresses matching the same hostname."""

    def test_any_present_means_present(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=0)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_device(session, "AA:BB:CC:DD:EE:02", "phone.local")
            # Only one MAC has a recent window
            _add_window(session, "AA:BB:CC:DD:EE:02", t0 - timedelta(seconds=30), t0)
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: present (via MAC 02)

            # Both MACs now stale
            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n) == 1
        assert n[0].transition == "gone"

    def test_case_insensitive_match(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="mi-10t-pro.fritz.box", stable_minutes=0)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "Mi-10T-Pro.fritz.box")
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: gone

            t1 = t0 + timedelta(minutes=1)
            _add_window(session, "AA:BB:CC:DD:EE:01", t1 - timedelta(seconds=10), t1)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n) == 1
        assert n[0].transition == "present"


class TestPresenceMonitorDisplayName:
    """Tests for notification display name."""

    def test_custom_name(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(
            hostname="phone.local",
            name="My Phone",
            stable_minutes=0,
        )
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(minutes=1), t0)
            monitor.check(session, gap_seconds=300, now=t0)

            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert n[0].name == "My Phone"

    def test_falls_back_to_hostname(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="phone.local", stable_minutes=0)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            _add_device(session, "AA:BB:CC:DD:EE:01", "phone.local")
            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(minutes=1), t0)
            monitor.check(session, gap_seconds=300, now=t0)

            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert n[0].name == "phone.local"


class TestPresenceMonitorDeviceNameFallback:
    """Tests that matching also works on device_name, not just hostname."""

    def test_matches_device_name_when_hostname_is_null(self, in_memory_engine) -> None:
        watch = PresenceWatchEntry(hostname="Mi-10T-Pro.fritz.box", stable_minutes=0)
        monitor = PresenceMonitor([watch])
        t0 = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="AA:BB:CC:DD:EE:01",
                device_type="network",
                device_name="Mi-10T-Pro.fritz.box",
                hostname=None,
            )
            session.add(device)
            session.flush()

            _add_window(session, "AA:BB:CC:DD:EE:01", t0 - timedelta(minutes=1), t0)
            monitor.check(session, gap_seconds=300, now=t0)  # baseline: present

            t1 = t0 + timedelta(minutes=10)
            n = monitor.check(session, gap_seconds=300, now=t1)

        assert len(n) == 1
        assert n[0].transition == "gone"


class TestPresenceMonitorEmpty:
    """Tests with empty watch lists."""

    def test_no_watches(self, in_memory_engine) -> None:
        monitor = PresenceMonitor([])
        now = datetime(2026, 4, 21, 12, 0, 0)

        with get_session(in_memory_engine) as session:
            notifications = monitor.check(session, gap_seconds=300, now=now)

        assert notifications == []
