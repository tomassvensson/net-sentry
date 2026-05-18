"""Heuristic merging of devices that appear under different randomized MAC addresses.

IMPORTANT CAVEATS — read before using:

1. **Heuristics are not perfect.** Every merge is based on circumstantial
   evidence.  False positives (merging two *different* physical devices) ARE
   possible, especially when multiple identical device models share the same
   network (e.g. a fleet of company iPhones).

2. **Device names change.** Users rename devices, factory-reset them, or
   connect them to a new network profile.  A name match today may not be valid
   tomorrow.

3. **Hostname ≠ device.** DHCP can reassign the same hostname to a different
   machine.  An IP match alone is very weak evidence.

4. **Merging is non-destructive.** The randomized-MAC ``Device`` record is
   never deleted; ``merged_into`` is set to the canonical MAC so that the full
   audit trail is preserved.

5. **Visibility windows are re-attributed.** All ``VisibilityWindow`` rows that
   belonged to the randomized MAC are updated to use the canonical MAC.  This
   changes historical aggregation.  If you care about per-MAC accuracy, do not
   run merges automatically.

6. **Two randomized-MAC devices with the same name may be different.** E.g.
   two iPhones both named "iPhone" — the heuristic will confidently (but
   incorrectly) merge them.

Confidence levels
-----------------
* ``high``   — device_name + vendor + device_type all match, and the
               randomized-MAC device was never seen at the same time as the
               canonical device (no temporal overlap).
* ``medium`` — device_name + device_type match but vendor is missing/unknown
               (common for Bluetooth which randomizes OUI too).
* ``low``    — only IP address + device_type match, OR hostname + device_type.
               Treat these as hints only.

Dry-run mode
------------
Call :func:`find_merge_candidates` or :func:`auto_merge_randomized` with
``dry_run=True`` to inspect candidates without writing to the database.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import update

from src.models import Device, VisibilityWindow
from src.oui_lookup import is_randomized_mac

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class MergeCandidate:
    """A candidate pair for merging."""

    source_mac: str
    """Randomized MAC that should be merged away."""
    target_mac: str
    """Canonical MAC that should absorb the source."""
    confidence: str
    """'high', 'medium', or 'low'."""
    reasons: list[str] = field(default_factory=list)
    """Human-readable reasons for the match."""


def _collect_reasons(device: Device, anchor: Device) -> list[str]:
    """Return a list of human-readable reasons why *device* might match *anchor*."""
    reasons: list[str] = []
    if (
        device.device_name
        and anchor.device_name
        and device.device_name.strip().lower() == anchor.device_name.strip().lower()
    ):
        reasons.append(f"device_name='{device.device_name}'")
    if device.vendor and anchor.vendor and device.vendor.strip().lower() == anchor.vendor.strip().lower():
        reasons.append(f"vendor='{device.vendor}'")
    if device.hostname and anchor.hostname and device.hostname.strip().lower() == anchor.hostname.strip().lower():
        reasons.append(f"hostname='{device.hostname}'")
    if device.ip_address and anchor.ip_address and device.ip_address.strip() == anchor.ip_address.strip():
        reasons.append(f"ip_address='{device.ip_address}'")
    return reasons


def _determine_confidence(
    device: Device,
    anchor: Device,
    session: Session,
    reasons: list[str],
) -> str:
    """Determine the confidence level for a merge candidate."""
    name_match = any(r.startswith("device_name=") for r in reasons)
    vendor_match = any(r.startswith("vendor=") for r in reasons)
    if name_match and vendor_match:
        if _has_temporal_overlap(session, device.mac_address, anchor.mac_address):
            reasons.append("WARNING: temporal overlap detected — may be two distinct devices")
            return "low"
        return "high"
    if name_match:
        return "medium"
    return "low"


def _evaluate_anchor(device: Device, anchor: Device, session: Session) -> MergeCandidate | None:
    """Score *anchor* as a merge target for *device*; return None if no match."""
    reasons = _collect_reasons(device, anchor)
    if not reasons:
        return None
    confidence = _determine_confidence(device, anchor, session, reasons)
    return MergeCandidate(
        source_mac=device.mac_address,
        target_mac=anchor.mac_address,
        confidence=confidence,
        reasons=reasons,
    )


def find_merge_candidates(
    session: Session,
    device: Device,
) -> list[MergeCandidate]:
    """Find canonical-device candidates for a single randomized-MAC device.

    Only examines devices whose MAC is *not* itself randomized (globally
    administered MACs only) — those are the stable anchors we merge *into*.

    Args:
        session: Database session.
        device: The randomized-MAC device to find a canonical match for.

    Returns:
        List of :class:`MergeCandidate` objects, best match first.
        Empty list if no suitable candidate was found.
    """
    if not is_randomized_mac(device.mac_address):
        return []
    if device.merged_into is not None:
        # Already merged — skip
        return []

    candidates: list[MergeCandidate] = []

    # ------------------------------------------------------------------
    # Potential anchor devices: same device_type, not randomized, not yet
    # merged into something else themselves.
    # ------------------------------------------------------------------
    anchors: list[Device] = (
        session.query(Device)
        .filter(
            Device.device_type == device.device_type,
            Device.mac_address != device.mac_address,
            Device.merged_into.is_(None),
        )
        .all()
    )

    # Filter: keep only anchors with a globally-administered (non-random) MAC
    anchors = [a for a in anchors if not is_randomized_mac(a.mac_address)]

    for anchor in anchors:
        candidate = _evaluate_anchor(device, anchor, session)
        if candidate is not None:
            candidates.append(candidate)

    # Best first: high > medium > low, then by number of matching signals
    _confidence_order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: (_confidence_order.get(c.confidence, 9), -len(c.reasons)))
    return candidates


def _has_temporal_overlap(session: Session, mac_a: str, mac_b: str) -> bool:
    """Return True if the two devices were ever visible at the same time.

    A temporal overlap means the same physical space showed *both* MAC
    addresses simultaneously, which suggests they are two different devices.

    Args:
        session: Database session.
        mac_a: First MAC address.
        mac_b: Second MAC address.

    Returns:
        True if any visibility windows overlap in time.
    """
    windows_a: list[VisibilityWindow] = session.query(VisibilityWindow).filter_by(mac_address=mac_a).all()
    windows_b: list[VisibilityWindow] = session.query(VisibilityWindow).filter_by(mac_address=mac_b).all()
    for wa in windows_a:
        for wb in windows_b:
            # Overlap if neither ends before the other starts
            if wa.first_seen <= wb.last_seen and wb.first_seen <= wa.last_seen:
                return True
    return False


def merge_device(
    session: Session,
    source_mac: str,
    target_mac: str,
    *,
    dry_run: bool = False,
) -> int:
    """Merge a randomized-MAC device record into a canonical device.

    Steps:
    1. Re-attribute all ``VisibilityWindow`` rows from *source* → *target*.
    2. Set ``source.merged_into = target_mac`` on the source ``Device`` row.
    3. The source ``Device`` row is kept for auditing.

    Args:
        session: Database session.
        source_mac: Randomized MAC to merge away.
        target_mac: Canonical MAC to absorb the source.
        dry_run: If True, log what *would* happen but do not write.

    Returns:
        Number of visibility windows re-attributed.

    Raises:
        ValueError: If source or target device is not found, or if source MAC
                    is not randomized, or if target MAC is randomized (we only
                    merge *into* globally-administered MACs).
    """
    source = session.query(Device).filter_by(mac_address=source_mac).first()
    target = session.query(Device).filter_by(mac_address=target_mac).first()

    if source is None:
        raise ValueError(f"Source device not found: {source_mac!r}")
    if target is None:
        raise ValueError(f"Target device not found: {target_mac!r}")
    if not is_randomized_mac(source_mac):
        raise ValueError(f"Source MAC {source_mac!r} is not randomized — refusing to merge to avoid data loss.")
    if is_randomized_mac(target_mac):
        raise ValueError(
            f"Target MAC {target_mac!r} is itself randomized — only merge into globally-administered MACs."
        )

    window_count: int = session.query(VisibilityWindow).filter_by(mac_address=source_mac).count()

    logger.info(
        "Merging %s → %s (%d visibility windows, dry_run=%s)",
        source_mac,
        target_mac,
        window_count,
        dry_run,
    )

    if not dry_run:
        # Re-attribute visibility windows
        session.execute(
            update(VisibilityWindow).where(VisibilityWindow.mac_address == source_mac).values(mac_address=target_mac)
        )
        # Mark source as merged
        source.merged_into = target_mac
        source.updated_at = datetime.now(timezone.utc)
        session.commit()

    return window_count


def auto_merge_randomized(
    session: Session,
    *,
    min_confidence: str = "high",
    dry_run: bool = True,
) -> list[MergeCandidate]:
    """Scan all randomized-MAC devices and auto-merge high-confidence ones.

    Only merges candidates where confidence >= *min_confidence*.

    By default this runs in **dry-run mode** (safe to call without side effects).
    Set ``dry_run=False`` to actually write changes.

    Args:
        session: Database session.
        min_confidence: Minimum confidence level to act on
                        ('high', 'medium', or 'low').
        dry_run: If True, return candidates without modifying the database.

    Returns:
        List of all candidates that met the threshold (merged or not in dry-run).
    """
    _order = {"high": 0, "medium": 1, "low": 2}
    threshold = _order.get(min_confidence, 0)

    randomized_devices: list[Device] = [
        d for d in session.query(Device).filter(Device.merged_into.is_(None)).all() if is_randomized_mac(d.mac_address)
    ]

    acted: list[MergeCandidate] = []
    for device in randomized_devices:
        candidates = find_merge_candidates(session, device)
        if not candidates:
            continue
        best = candidates[0]
        if _order.get(best.confidence, 9) <= threshold:
            acted.append(best)
            if not dry_run:
                try:
                    merge_device(session, best.source_mac, best.target_mac)
                except ValueError:
                    logger.exception("Could not merge %s → %s", best.source_mac, best.target_mac)

    return acted
