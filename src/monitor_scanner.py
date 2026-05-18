"""Promiscuous/monitor mode WiFi scanner using scapy.

Captures raw 802.11 frames in monitor mode to detect devices
that are not associated with the network (probe requests, beacons, etc.).

Requires:
- A monitor-mode capable adapter (e.g. Goshyda AR9271)
- Root/admin privileges
- scapy (pip install net-sentry[monitor])

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
    probed_ssids: list[str] = field(default_factory=list)
    """All unique SSIDs this device was observed probing for."""

    def __repr__(self) -> str:
        """Return string representation."""
        return f"<MonitorModeDevice(mac={self.mac_address}, signal={self.signal_dbm}dBm, type={self.frame_type})>"


@dataclass
class ProbeRequest:
    """A single 802.11 probe-request frame captured from a device.

    Probe requests are management frames broadcast by WiFi clients to find
    known networks.  Collecting these reveals which SSIDs a device has
    previously connected to.

    Attributes:
        mac_address: Source MAC of the probing device.
        probed_ssid: The SSID being probed (empty string = wildcard/broadcast probe).
        signal_dbm: Received signal strength in dBm, or ``None`` if unavailable.
        scan_time: When the frame was captured.
    """

    mac_address: str
    probed_ssid: str
    signal_dbm: float | None = None
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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
            "scapy not installed. Install with: pip install net-sentry[monitor]. Monitor mode scanning disabled."
        )
        return []

    try:
        return _capture_frames(interface, duration_seconds, channel_hop)
    except PermissionError:
        logger.error("Monitor mode requires root/admin privileges. Run with sudo or as administrator.")
        return []
    except Exception:
        logger.exception("Monitor mode capture failed on interface %s", interface)
        return []


def _extract_signal(pkt: object) -> float | None:
    """Extract RSSI from RadioTap layer, or None if unavailable."""
    from scapy.all import RadioTap  # type: ignore[import-untyped]

    if pkt.haslayer(RadioTap):  # type: ignore[union-attr]
        radiotap = pkt.getlayer(RadioTap)  # type: ignore[union-attr,attr-defined]
        if hasattr(radiotap, "dBm_AntSignal"):
            return float(radiotap.dBm_AntSignal)
    return None


def _extract_frame_info(pkt: object) -> tuple[str, str | None]:
    """Return (frame_type, ssid) for a Dot11 packet."""
    from scapy.all import Dot11Beacon, Dot11Elt, Dot11ProbeReq  # type: ignore[import-untyped]

    ssid: str | None = None
    if pkt.haslayer(Dot11Beacon):  # type: ignore[union-attr]
        frame_type = "beacon"
        elt = pkt.getlayer(Dot11Elt)  # type: ignore[union-attr,attr-defined]
        if elt and elt.ID == 0:
            with contextlib.suppress(UnicodeDecodeError, AttributeError):
                ssid = elt.info.decode("utf-8", errors="replace")
    elif pkt.haslayer(Dot11ProbeReq):  # type: ignore[union-attr]
        frame_type = "probe_request"
        elt = pkt.getlayer(Dot11Elt)  # type: ignore[union-attr,attr-defined]
        if elt and elt.ID == 0:
            with contextlib.suppress(UnicodeDecodeError, AttributeError):
                ssid = elt.info.decode("utf-8", errors="replace")
    else:
        frame_type = "data"
    return frame_type, ssid


def _update_device(
    devices: dict[str, MonitorModeDevice],
    src_mac: str,
    signal: float | None,
    frame_type: str,
    ssid: str | None,
    scan_time: datetime,
) -> None:
    """Insert a new device entry or update an existing one in-place."""
    if src_mac not in devices:
        devices[src_mac] = MonitorModeDevice(
            mac_address=src_mac,
            signal_dbm=signal,
            frame_type=frame_type,
            ssid=ssid,
            scan_time=scan_time,
        )
    else:
        existing = devices[src_mac]
        if signal is not None and (existing.signal_dbm is None or signal > existing.signal_dbm):
            existing.signal_dbm = signal
        if frame_type in ("beacon", "probe_request"):
            existing.frame_type = frame_type
        if ssid and not existing.ssid:
            existing.ssid = ssid
    if frame_type == "probe_request":
        ssid_key = ssid if ssid else ""
        if ssid_key not in devices[src_mac].probed_ssids:
            devices[src_mac].probed_ssids.append(ssid_key)


def _process_dot11_packet(
    pkt: object,
    devices: dict[str, MonitorModeDevice],
    scan_time: datetime,
) -> None:
    """Process a single captured 802.11 frame and update the devices map."""
    from scapy.all import Dot11  # type: ignore[import-untyped]

    if not hasattr(pkt, "haslayer"):
        return
    if not pkt.haslayer(Dot11):  # type: ignore[union-attr]
        return
    dot11 = pkt.getlayer(Dot11)  # type: ignore[union-attr,attr-defined]
    if dot11 is None:
        return
    src_mac = dot11.addr2
    if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff":
        return
    src_mac = src_mac.upper()
    signal = _extract_signal(pkt)
    frame_type, ssid = _extract_frame_info(pkt)
    _update_device(devices, src_mac, signal, frame_type, ssid, scan_time)


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
    from scapy.all import sniff  # type: ignore[import-untyped]

    devices: dict[str, MonitorModeDevice] = {}
    scan_time = datetime.now(timezone.utc)

    logger.info(
        "Starting monitor mode capture on %s for %ds (channel_hop=%s)",
        interface,
        duration_seconds,
        channel_hop,
    )

    try:
        sniff(
            iface=interface,
            prn=lambda pkt: _process_dot11_packet(pkt, devices, scan_time),
            timeout=duration_seconds,
            store=False,
        )
    except OSError:
        logger.exception("Cannot open interface %s", interface)
        return []

    logger.info("Monitor mode capture complete: %d unique devices", len(devices))
    return list(devices.values())


def scan_probe_requests(
    interface: str = "wlan0mon",
    duration_seconds: int = 30,
) -> list[ProbeRequest]:
    """Capture 802.11 probe-request frames and return per-frame records.

    Each returned :class:`ProbeRequest` represents one unique
    (mac_address, probed_ssid) pair observed during the capture window.
    This reveals which network names a client device has previously
    connected to.

    Args:
        interface: Monitor mode interface name.
        duration_seconds: How long to capture.

    Returns:
        List of :class:`ProbeRequest` objects (one per unique mac+ssid pair).
        Returns an empty list if scapy is unavailable or permissions are insufficient.
    """
    devices = scan_monitor_mode(interface=interface, duration_seconds=duration_seconds, channel_hop=False)
    probe_records: list[ProbeRequest] = []
    for dev in devices:
        if dev.frame_type == "probe_request":
            for ssid in dev.probed_ssids:
                probe_records.append(
                    ProbeRequest(
                        mac_address=dev.mac_address,
                        probed_ssid=ssid,
                        signal_dbm=dev.signal_dbm,
                        scan_time=dev.scan_time,
                    )
                )
    logger.info("Probe request scan: %d unique (mac, ssid) pairs", len(probe_records))
    return probe_records
