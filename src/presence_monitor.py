"""Presence monitoring for watched devices.

Tracks device presence state over time and triggers notifications
when a device appears or disappears after being in a stable state.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.config import PresenceWatchEntry
from src.models import Device, VisibilityWindow

logger = logging.getLogger(__name__)

_alert_logger = logging.getLogger("btwifi.alerts")


class PresenceNotification:
    """A triggered presence state change notification."""

    __slots__ = ("hostname", "name", "transition", "stable_minutes")

    def __init__(self, hostname: str, name: str, transition: str, stable_minutes: int) -> None:
        self.hostname = hostname
        self.name = name
        self.transition = transition
        self.stable_minutes = stable_minutes


class PresenceMonitor:
    """Monitors watched devices for presence state changes."""

    def __init__(self, watches: list[PresenceWatchEntry]) -> None:
        self._watches = watches
        self._last_state: dict[str, str] = {}

    def check(
        self,
        session: Session,
        gap_seconds: int,
        now: datetime,
    ) -> list[PresenceNotification]:
        """Check all watched devices for state changes.

        Returns list of notifications triggered this cycle.
        """
        notifications: list[PresenceNotification] = []
        for watch in self._watches:
            notification = self._check_one(session, watch, gap_seconds, now)
            if notification is not None:
                notifications.append(notification)
        return notifications

    def _check_one(
        self,
        session: Session,
        watch: PresenceWatchEntry,
        gap_seconds: int,
        now: datetime,
    ) -> PresenceNotification | None:
        pattern = f"%{watch.hostname}%"
        devices = (
            session.query(Device)
            .filter(
                or_(
                    Device.hostname.ilike(pattern),
                    Device.device_name.ilike(pattern),
                )
            )
            .all()
        )

        if not devices:
            return None

        mac_addresses = [d.mac_address for d in devices]
        current_state = self._current_state(session, mac_addresses, gap_seconds, now)
        prev_state = self._last_state.get(watch.hostname)

        if prev_state is None:
            self._last_state[watch.hostname] = current_state
            return None

        if current_state == prev_state:
            return None

        if watch.stable_minutes > 0:
            stable_state = self._stable_state(session, mac_addresses, watch.stable_minutes, now)
            if stable_state != prev_state:
                self._last_state[watch.hostname] = current_state
                return None

        self._last_state[watch.hostname] = current_state
        display_name = watch.name or watch.hostname

        if current_state == "present" and not watch.notify_on_appear:
            return None
        if current_state == "gone" and not watch.notify_on_disappear:
            return None

        notification = PresenceNotification(
            hostname=watch.hostname,
            name=display_name,
            transition=current_state,
            stable_minutes=watch.stable_minutes,
        )

        if current_state == "present":
            logger.warning(
                "PRESENCE: %s has APPEARED (was gone for most of the last %d minutes)",
                display_name,
                watch.stable_minutes,
            )
        else:
            logger.warning(
                "PRESENCE: %s has DISAPPEARED (was present for most of the last %d minutes)",
                display_name,
                watch.stable_minutes,
            )

        _alert_logger.info(
            "[PRESENCE] %s → %s (stable %d min)",
            display_name,
            current_state,
            watch.stable_minutes,
        )

        return notification

    def _current_state(
        self,
        session: Session,
        mac_addresses: list[str],
        gap_seconds: int,
        now: datetime,
    ) -> str:
        cutoff = now - timedelta(seconds=gap_seconds)
        recent = (
            session.query(VisibilityWindow)
            .filter(
                VisibilityWindow.mac_address.in_(mac_addresses),
                VisibilityWindow.last_seen >= cutoff,
            )
            .first()
        )
        return "present" if recent is not None else "gone"

    def _stable_state(
        self,
        session: Session,
        mac_addresses: list[str],
        stable_minutes: int,
        now: datetime,
    ) -> str | None:
        lookback = timedelta(minutes=stable_minutes)
        start = now - lookback
        total_seconds = lookback.total_seconds()

        windows = (
            session.query(VisibilityWindow)
            .filter(
                VisibilityWindow.mac_address.in_(mac_addresses),
                VisibilityWindow.last_seen >= start,
                VisibilityWindow.first_seen <= now,
            )
            .all()
        )

        if not windows:
            return "gone"

        seen_seconds = 0.0
        for w in windows:
            w_start = max(w.first_seen, start)
            w_end = min(w.last_seen, now)
            if w_end > w_start:
                seen_seconds += (w_end - w_start).total_seconds()

        if seen_seconds > total_seconds / 2:
            return "present"
        return "gone"
