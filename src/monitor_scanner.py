"""Promiscuous/monitor mode WiFi scanner using scapy.

Captures raw 802.11 frames in monitor mode to detect devices
that are not associated with the network (probe requests, beacons, etc.).

Requires:
- A monitor-mode capable adapter (e.g. Goshyda AR9271)
- Root/admin privileges
- scapy (pip install btwifi[monitor])

IMPORTANT: Devices detected this way do NOT get network access.
The adapter operates in passive receive-only monitor mode.
"""

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class MonitorModeDevice:
    """A device detected via monitor mode capture."""

    mac_address: str
    signal_dbm: float | None = None
    frame_type: str = ""  # beacon, probe_request, probe_response, data
    ssid: str | None = None
    vendor: str | None = None
    channel: int | None = None
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<MonitorModeDevice(mac={self.mac_address}, "
            f"signal={self.signal_dbm}dBm, type={self.frame_type})>"
        )


def is_scapy_available() -> bool:
    """Check if scapy is installed.

    Returns:
        True if scapy can be imported.
    """
    try:
        import scapy.all  # noqa: F401

        return True
    except ImportError:
        return False


def scan_monitor_mode(
    interface: str = "wlan0mon",
    duration_seconds: int = 30,
    channel_hop: bool = True,
) -> list[MonitorModeDevice]:
    """Capture WiFi frames in monitor mode.

    This puts the adapter in passive receive mode and captures
    802.11 management and data frames. The adapter does NOT
    transmit or associate — detected devices get no network access.

    Args:
        interface: Monitor mode interface name.
        duration_seconds: How long to capture.
        channel_hop: Whether to hop channels during capture.

    Returns:
        List of detected devices.
    """
    if not is_scapy_available():
        logger.warning(
            "scapy not installed. Install with: pip install btwifi[monitor]. "
            "Monitor mode scanning disabled."
        )
        return []

    try:
        return _capture_frames(interface, duration_seconds, channel_hop)
    except PermissionError:
        logger.error(
            "Monitor mode requires root/admin privileges. "
            "Run with sudo or as administrator."
        )
        return []
    except Exception:
        logger.exception("Monitor mode capture failed on interface %s", interface)
        return []


def _capture_frames(
    interface: str,
    duration_seconds: int,
    channel_hop: bool,
) -> list[MonitorModeDevice]:
    """Perform the actual frame capture using scapy.

    Args:
        interface: Monitor mode interface.
        duration_seconds: Capture duration.
        channel_hop: Whether to hop channels.

    Returns:
        List of detected devices.
    """
    # Import scapy only when actually needed
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, sniff  # type: ignore[import-untyped]

    devices: dict[str, MonitorModeDevice] = {}
    scan_time = datetime.now(timezone.utc)

    logger.info(
        "Starting monitor mode capture on %s for %ds (channel_hop=%s)",
        interface,
        duration_seconds,
        channel_hop,
    )

    def process_packet(pkt: object) -> None:
        """Process a captured 802.11 frame."""
        if not hasattr(pkt, "haslayer"):
            return

        if not pkt.haslayer(Dot11):  # type: ignore[union-attr]
            return

        dot11 = pkt.getlayer(Dot11)  # type: ignore[attr-defined]
        if dot11 is None:
            return

        # Extract source MAC
        src_mac = dot11.addr2
        if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff":
            return

        src_mac = src_mac.upper()

        # Extract signal strength from RadioTap header
        signal = None
        if pkt.haslayer(RadioTap):  # type: ignore[union-attr]
            radiotap = pkt.getlayer(RadioTap)  # type: ignore[attr-defined]
            if hasattr(radiotap, "dBm_AntSignal"):
                signal = float(radiotap.dBm_AntSignal)

        # Determine frame type
        frame_type = "data"
        ssid = None

        if pkt.haslayer(Dot11Beacon):  # type: ignore[union-attr]
            frame_type = "beacon"
            elt = pkt.getlayer(Dot11Elt)  # type: ignore[attr-defined]
            if elt and elt.ID == 0:
                with contextlib.suppress(UnicodeDecodeError, AttributeError):
                    ssid = elt.info.decode("utf-8", errors="replace")
        elif pkt.haslayer(Dot11ProbeReq):  # type: ignore[union-attr]
            frame_type = "probe_request"
            elt = pkt.getlayer(Dot11Elt)  # type: ignore[attr-defined]
            if elt and elt.ID == 0:
                with contextlib.suppress(UnicodeDecodeError, AttributeError):
                    ssid = elt.info.decode("utf-8", errors="replace")

        if src_mac not in devices:
            devices[src_mac] = MonitorModeDevice(
                mac_address=src_mac,
                signal_dbm=signal,
                frame_type=frame_type,
                ssid=ssid if ssid else None,
                scan_time=scan_time,
            )
        else:
            # Update signal if stronger
            existing = devices[src_mac]
            if signal is not None and (existing.signal_dbm is None or signal > existing.signal_dbm):
                existing.signal_dbm = signal
            # Prefer beacon/probe_request frame types over generic data
            if frame_type in ("beacon", "probe_request"):
                existing.frame_type = frame_type
            if ssid and not existing.ssid:
                existing.ssid = ssid

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            timeout=duration_seconds,
            store=False,
        )
    except OSError as exc:
        logger.error("Cannot open interface %s: %s", interface, exc)
        return []

    logger.info("Monitor mode capture complete: %d unique devices", len(devices))
    return list(devices.values())
