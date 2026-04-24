"""WiFi network and device scanner.

Windows uses `netsh wlan show networks mode=bssid`. Linux prefers
NetworkManager's `nmcli` output and falls back to `iw` when available.

Security: This is purely passive scanning. No connections are established
with discovered networks/devices.
"""

import logging
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class WifiNetwork:
    """A discovered WiFi network / access point."""

    ssid: str
    bssid: str  # MAC address of the access point
    network_type: str
    authentication: str
    encryption: str
    signal_percent: int
    signal_dbm: float | None
    radio_type: str
    channel: int
    vendor: str | None = None
    is_randomized: bool = False
    device_name: str | None = None
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Post-initialization: look up vendor and check for randomization."""
        if self.vendor is None:
            self.vendor = lookup_vendor(self.bssid)
        self.is_randomized = is_randomized_mac(self.bssid)


def signal_percent_to_dbm(percent: int) -> float:
    """Convert signal strength percentage to approximate dBm.

    Several backends report signal as a percentage (0-100). This converts to
    approximate dBm using the common linear mapping:
    dBm = (percent / 2) - 100

    Args:
        percent: Signal strength as percentage (0-100).

    Returns:
        Approximate signal strength in dBm.
    """
    percent = max(0, min(100, percent))
    return (percent / 2) - 100


def signal_dbm_to_percent(signal_dbm: float) -> int:
    """Convert signal strength in dBm to an approximate percentage."""
    return max(0, min(100, int(round((signal_dbm + 100) * 2))))


def scan_wifi_networks() -> list[WifiNetwork]:
    """Scan for nearby WiFi networks on the current platform.

    Returns:
        List of discovered WifiNetwork objects.

    Raises:
        RuntimeError: If the active Windows backend fails.
    """
    logger.info("Starting WiFi network scan...")
    system_name = platform.system().lower()

    if system_name == "windows":
        networks = _scan_windows_wifi_networks()
        logger.info("WiFi scan complete: found %d networks/access points.", len(networks))
        return networks

    if system_name == "linux":
        if _is_wsl():
            logger.info("Skipping WiFi scan: direct WiFi access is not typically available under WSL")
            return []
        networks = _scan_linux_wifi_networks()
        logger.info("WiFi scan complete: found %d networks/access points.", len(networks))
        return networks

    logger.info("Skipping WiFi scan: unsupported platform %s", platform.system())
    return []


def _scan_windows_wifi_networks() -> list[WifiNetwork]:
    """Scan for nearby WiFi networks using netsh on Windows."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        logger.error("netsh command not found. WiFi scanning requires Windows.")
        raise RuntimeError("WiFi scanning requires Windows (netsh not found).") from None
    except subprocess.TimeoutExpired:
        logger.error("WiFi scan timed out after 30 seconds.")
        raise RuntimeError("WiFi scan timed out.") from None

    if result.returncode != 0:
        error_msg = result.stderr.strip() if result.stderr else "Unknown error"
        logger.error("netsh failed (rc=%d): %s", result.returncode, error_msg)
        raise RuntimeError(f"WiFi scan failed: {error_msg}")

    return _parse_netsh_output(result.stdout)


def _scan_linux_wifi_networks() -> list[WifiNetwork]:
    """Scan for nearby WiFi networks on Linux."""
    backend_errors: list[str] = []

    for backend_name, backend in (("nmcli", _scan_linux_nmcli), ("iw", _scan_linux_iw)):
        try:
            networks = backend()
            logger.info("Linux WiFi backend %s found %d networks/access points.", backend_name, len(networks))
            return networks
        except FileNotFoundError:
            backend_errors.append(f"{backend_name}: command not found")
        except RuntimeError as exc:
            backend_errors.append(f"{backend_name}: {exc}")

    if backend_errors:
        logger.info("Skipping WiFi scan: no usable Linux backend (%s)", "; ".join(backend_errors))
    else:
        logger.info("Skipping WiFi scan: no usable Linux backend detected")
    return []


def _scan_linux_nmcli() -> list[WifiNetwork]:
    """Scan for nearby WiFi networks using NetworkManager on Linux."""
    result = subprocess.run(
        [
            "nmcli",
            "--mode",
            "multiline",
            "--fields",
            "SSID,BSSID,MODE,CHAN,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "--rescan",
            "yes",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        error_msg = result.stderr.strip() or result.stdout.strip() or "nmcli failed"
        raise RuntimeError(error_msg)
    return _parse_nmcli_output(result.stdout)


def _scan_linux_iw() -> list[WifiNetwork]:
    """Scan for nearby WiFi networks using iw on Linux."""
    interface_result = subprocess.run(
        ["iw", "dev"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if interface_result.returncode != 0:
        error_msg = interface_result.stderr.strip() or interface_result.stdout.strip() or "iw dev failed"
        raise RuntimeError(error_msg)

    interfaces = _parse_iw_interfaces(interface_result.stdout)
    if not interfaces:
        raise RuntimeError("no WiFi interface found")

    last_error = "iw scan produced no output"
    for interface_name in interfaces:
        scan_result = subprocess.run(
            ["iw", "dev", interface_name, "scan"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if scan_result.returncode != 0:
            last_error = scan_result.stderr.strip() or scan_result.stdout.strip() or last_error
            continue
        networks = _parse_iw_output(scan_result.stdout)
        if networks:
            return networks

    raise RuntimeError(last_error)


def _parse_nmcli_output(output: str) -> list[WifiNetwork]:
    """Parse `nmcli --mode multiline device wifi list` output."""
    networks: list[WifiNetwork] = []
    current: dict[str, str] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                network = _build_nmcli_network(current)
                if network is not None:
                    networks.append(network)
                current = {}
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        current[key.strip().upper()] = value.strip()

    if current:
        network = _build_nmcli_network(current)
        if network is not None:
            networks.append(network)

    return networks


def _build_nmcli_network(values: dict[str, str]) -> WifiNetwork | None:
    """Build a WifiNetwork from parsed nmcli fields."""
    bssid = values.get("BSSID", "")
    if not bssid:
        return None

    try:
        normalized_bssid = normalize_mac(bssid)
    except ValueError:
        logger.debug("Skipping nmcli entry with invalid BSSID: %s", bssid)
        return None

    signal_percent = _safe_int(values.get("SIGNAL", "0"))
    security = values.get("SECURITY", "")
    authentication, encryption = _split_linux_security(security)

    return WifiNetwork(
        ssid=values.get("SSID", "") or "<Hidden>",
        bssid=normalized_bssid,
        network_type=_normalize_linux_network_type(values.get("MODE", "")),
        authentication=authentication,
        encryption=encryption,
        signal_percent=signal_percent,
        signal_dbm=signal_percent_to_dbm(signal_percent),
        radio_type="",
        channel=_safe_int(values.get("CHAN", "0")),
    )


def _parse_iw_interfaces(output: str) -> list[str]:
    """Parse interface names from `iw dev` output."""
    interfaces: list[str] = []
    for raw_line in output.splitlines():
        match = re.search(r"\bInterface\s+(\S+)", raw_line)
        if match:
            interfaces.append(match.group(1))
    return interfaces


def _parse_iw_output(output: str) -> list[WifiNetwork]:
    """Parse `iw dev <iface> scan` output."""
    networks: list[WifiNetwork] = []
    current: dict[str, object] | None = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        bss_match = re.match(r"^BSS\s+([0-9A-Fa-f:]{17})", stripped)
        if bss_match:
            if current:
                network = _build_iw_network(current)
                if network is not None:
                    networks.append(network)
            current = {
                "bssid": bss_match.group(1),
                "ssid": "<Hidden>",
                "signal_dbm": None,
                "channel": 0,
                "frequency": 0,
                "security_markers": set(),
                "privacy": False,
            }
            continue

        if current is None:
            continue

        if stripped.startswith("SSID:"):
            current["ssid"] = stripped.split(":", 1)[1].strip() or "<Hidden>"
            continue

        if stripped.startswith("signal:"):
            signal_match = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", stripped)
            if signal_match:
                current["signal_dbm"] = float(signal_match.group(1))
            continue

        channel_match = re.search(r"channel\s+(\d+)", stripped, flags=re.IGNORECASE)
        if channel_match:
            current["channel"] = int(channel_match.group(1))
            continue

        primary_match = re.match(r"^primary channel:\s*(\d+)", stripped, flags=re.IGNORECASE)
        if primary_match:
            current["channel"] = int(primary_match.group(1))
            continue

        if stripped.startswith("freq:"):
            current["frequency"] = _safe_int(stripped.split(":", 1)[1].strip())
            continue

        if stripped.startswith("RSN:"):
            security_markers = current["security_markers"]
            if isinstance(security_markers, set):
                security_markers.add("WPA2")
            continue

        if stripped.startswith("WPA:"):
            security_markers = current["security_markers"]
            if isinstance(security_markers, set):
                security_markers.add("WPA")
            continue

        if stripped.startswith("capability:") and "privacy" in stripped.lower():
            current["privacy"] = True

    if current:
        network = _build_iw_network(current)
        if network is not None:
            networks.append(network)

    return networks


def _build_iw_network(values: dict[str, object]) -> WifiNetwork | None:
    """Build a WifiNetwork from parsed iw fields."""
    bssid = values.get("bssid", "")
    if not isinstance(bssid, str) or not bssid:
        return None

    try:
        normalized_bssid = normalize_mac(bssid)
    except ValueError:
        logger.debug("Skipping iw entry with invalid BSSID: %s", bssid)
        return None

    signal_dbm = values.get("signal_dbm")
    signal_percent = 0
    if isinstance(signal_dbm, (int, float)):
        signal_percent = signal_dbm_to_percent(float(signal_dbm))

    channel = values.get("channel", 0)
    raw_freq = values.get("frequency")
    if (not isinstance(channel, int) or channel == 0) and isinstance(raw_freq, int):
        channel = _frequency_to_channel(raw_freq)

    security_markers = values.get("security_markers")
    privacy = values.get("privacy", False)
    security = _format_iw_security(security_markers, privacy)
    authentication, encryption = _split_linux_security(security)

    return WifiNetwork(
        ssid=str(values.get("ssid") or "") if isinstance(values.get("ssid"), str) else "<Hidden>",
        bssid=normalized_bssid,
        network_type="Infrastructure",
        authentication=authentication,
        encryption=encryption,
        signal_percent=signal_percent,
        signal_dbm=float(signal_dbm) if isinstance(signal_dbm, (int, float)) else None,
        radio_type="",
        channel=channel if isinstance(channel, int) else 0,
    )


def _format_iw_security(security_markers: object, privacy: object) -> str:
    """Format parsed iw security markers into a readable label."""
    markers = sorted(security_markers) if isinstance(security_markers, set) else []
    if markers:
        return "/".join(markers)
    if privacy:
        return "WEP"
    return ""


def _split_linux_security(security: str) -> tuple[str, str]:
    """Map Linux backend security text to authentication and encryption labels."""
    cleaned = security.strip().replace("--", "")
    if not cleaned:
        return ("Open", "None")
    return (cleaned, cleaned)


def _normalize_linux_network_type(mode: str) -> str:
    """Normalize Linux backend mode labels to the existing network type field."""
    cleaned = mode.strip()
    if cleaned.lower().startswith("infra"):
        return "Infrastructure"
    return cleaned or "Infrastructure"


def _frequency_to_channel(frequency_mhz: int) -> int:
    """Convert WiFi center frequency in MHz to channel number when possible."""
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz <= 5895:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    return 0


def _safe_int(value: str, default: int = 0) -> int:
    """Parse an integer field with a default fallback."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_wsl() -> bool:
    """Return True when running under Windows Subsystem for Linux."""
    if platform.system().lower() != "linux":
        return False
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    for version_path in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            with open(version_path, encoding="utf-8") as version_file:
                if "microsoft" in version_file.read().lower():
                    return True
        except OSError:
            continue
    return False


def _parse_netsh_output(output: str) -> list[WifiNetwork]:
    """Parse the output of `netsh wlan show networks mode=bssid`.

    Handles both English and other locale outputs by looking for
    patterns in the structure rather than exact label matches.

    Args:
        output: Raw stdout from netsh command.

    Returns:
        List of WifiNetwork objects.
    """
    networks: list[WifiNetwork] = []
    current_ssid = ""
    current_network_type = ""
    current_auth = ""
    current_encryption = ""

    lines = output.splitlines()

    for i, line in enumerate(lines):
        line = line.strip()

        field = _match_network_field(line)
        if field:
            key, value = field
            if key == "ssid":
                current_ssid = value
            elif key == "network_type":
                current_network_type = value
            elif key == "auth":
                current_auth = value
            elif key == "encryption":
                current_encryption = value
            continue

        # BSSID line — this starts a new access point entry
        bssid_match = re.match(r"^BSSID\s*\d*\s*:\s*([0-9a-f:]{17})", line, re.IGNORECASE)
        if bssid_match:
            network = _parse_bssid_entry(
                bssid_match.group(1).strip(),
                lines,
                i,
                current_ssid,
                current_network_type,
                current_auth,
                current_encryption,
            )
            if network:
                networks.append(network)

    return networks


# Regex patterns for network field parsing
_FIELD_PATTERNS: list[tuple[str, str]] = [
    ("ssid", r"^SSID\s*\d*\s*:\s*(.*)"),
    ("network_type", r"^(?:Network type|Netzwerktyp|Tipo de red)\s*:\s*(.*)"),
    ("auth", r"^(?:Authentication|Authentifizierung|Autenticaci.n)\s*:\s*(.*)"),
    ("encryption", r"^(?:Encryption|Verschl.sselung|Cifrado)\s*:\s*(.*)"),
]


def _match_network_field(line: str) -> tuple[str, str] | None:
    """Match a netsh output line against known network field patterns.

    Args:
        line: Stripped line from netsh output.

    Returns:
        Tuple of (field_key, value) if matched, None otherwise.
    """
    if line.upper().startswith("BSSID"):
        return None

    for key, pattern in _FIELD_PATTERNS:
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            return (key, match.group(1).strip())
    return None


def _parse_bssid_entry(
    bssid: str,
    lines: list[str],
    line_index: int,
    ssid: str,
    network_type: str,
    auth: str,
    encryption: str,
) -> WifiNetwork | None:
    """Parse a BSSID entry with lookahead for signal/radio/channel.

    Args:
        bssid: Raw BSSID string.
        lines: All output lines.
        line_index: Index of the BSSID line.
        ssid: Current SSID context.
        network_type: Current network type.
        auth: Current authentication mode.
        encryption: Current encryption mode.

    Returns:
        WifiNetwork if valid, None if BSSID is invalid.
    """
    signal_percent, radio_type, channel = _lookahead_bssid_details(lines, line_index)

    try:
        normalized_bssid = normalize_mac(bssid)
    except ValueError:
        logger.warning("Skipping invalid BSSID: %s", bssid)
        return None

    return WifiNetwork(
        ssid=ssid or "<Hidden>",
        bssid=normalized_bssid,
        network_type=network_type,
        authentication=auth,
        encryption=encryption,
        signal_percent=signal_percent,
        signal_dbm=signal_percent_to_dbm(signal_percent),
        radio_type=radio_type,
        channel=channel,
    )


def _lookahead_bssid_details(lines: list[str], bssid_index: int) -> tuple[int, str, int]:
    """Look ahead after a BSSID line to extract signal, radio type, channel.

    Args:
        lines: All output lines.
        bssid_index: Index of the BSSID line.

    Returns:
        Tuple of (signal_percent, radio_type, channel).
    """
    signal_percent = 0
    radio_type = ""
    channel = 0

    for j in range(bssid_index + 1, min(bssid_index + 6, len(lines))):
        ahead = lines[j].strip()

        if re.match(r"^(?:SSID|BSSID)\s", ahead, re.IGNORECASE):
            break

        signal_match = re.match(r"^(?:Signal|Se.al)\s*:\s*(\d+)%", ahead, re.IGNORECASE)
        if signal_match:
            signal_percent = int(signal_match.group(1))
            continue

        radio_match = re.match(r"^(?:Radio type|Funktyp|Tipo de radio)\s*:\s*(.*)", ahead, re.IGNORECASE)
        if radio_match:
            radio_type = radio_match.group(1).strip()
            continue

        channel_match = re.match(r"^(?:Channel|Kanal|Canal)\s*:\s*(\d+)", ahead, re.IGNORECASE)
        if channel_match:
            channel = int(channel_match.group(1))

    return signal_percent, radio_type, channel


def get_wifi_interfaces() -> list[dict[str, str]]:
    """Get information about available WiFi interfaces.

    Returns:
        List of dicts with interface information.
    """
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Could not query WiFi interfaces.")
        return []

    if result.returncode != 0:
        return []

    interfaces: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            if current:
                interfaces.append(current)
                current = {}
            continue

        match = re.match(r"^(.+?)\s*:\s*(.+)$", line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            current[key] = value

    if current:
        interfaces.append(current)

    return interfaces
