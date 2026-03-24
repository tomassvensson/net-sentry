"""IPv6 neighbor discovery scanner.

Uses the system's IPv6 neighbor table to discover devices on the local
network via NDP (Neighbor Discovery Protocol).
"""

import logging
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class Ipv6Neighbor:
    """A discovered IPv6 neighbor."""

    ipv6_address: str
    mac_address: str
    interface: str = ""
    state: str = ""
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        """Return string representation."""
        return f"<Ipv6Neighbor(ip={self.ipv6_address}, mac={self.mac_address}, state={self.state})>"


def scan_ipv6_neighbors() -> list[Ipv6Neighbor]:
    """Scan the IPv6 neighbor table.

    Uses platform-specific commands:
    - Windows: netsh interface ipv6 show neighbors
    - Linux/macOS: ip -6 neigh show

    Returns:
        List of discovered IPv6 neighbors.
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            return _scan_windows()
        return _scan_linux()
    except FileNotFoundError:
        logger.warning("IPv6 neighbor scan command not available on this platform")
        return []
    except subprocess.SubprocessError:
        logger.exception("IPv6 neighbor scan failed")
        return []


def _scan_windows() -> list[Ipv6Neighbor]:
    """Parse Windows 'netsh interface ipv6 show neighbors' output."""
    result = subprocess.run(
        ["netsh", "interface", "ipv6", "show", "neighbors"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        logger.warning("netsh ipv6 neighbors failed: %s", result.stderr.strip())
        return []

    return _parse_windows_output(result.stdout)


def _parse_windows_output(output: str) -> list[Ipv6Neighbor]:
    """Parse Windows netsh IPv6 neighbor output.

    Expected format per interface:
    Interface X: <name>
    Internet Address        Physical Address      Type
    -------             -------              -------
    fe80::1              aa-bb-cc-dd-ee-ff    Reachable

    Args:
        output: Raw netsh output.

    Returns:
        List of Ipv6Neighbor entries.
    """
    neighbors: list[Ipv6Neighbor] = []
    current_interface = ""
    scan_time = datetime.now(timezone.utc)

    # Match "Interface N: <name>"
    iface_pattern = re.compile(r"^Interface\s+\d+:\s+(.+)$", re.IGNORECASE)
    # Match IPv6 + MAC line
    entry_pattern = re.compile(
        r"^\s*([\da-fA-F:%.]+)\s+([\da-fA-F]{2}(?:-[\da-fA-F]{2}){5})\s+(\S+)",
    )

    for line in output.splitlines():
        iface_match = iface_pattern.match(line)
        if iface_match:
            current_interface = iface_match.group(1).strip()
            continue

        entry_match = entry_pattern.match(line)
        if entry_match:
            ipv6 = entry_match.group(1)
            mac_raw = entry_match.group(2)
            state = entry_match.group(3)

            # Convert Windows MAC format (aa-bb-cc-dd-ee-ff) to standard
            mac = mac_raw.replace("-", ":").upper()

            # Skip multicast and incomplete entries
            if mac == "FF:FF:FF:FF:FF:FF" or state.lower() == "unreachable":
                continue

            neighbors.append(
                Ipv6Neighbor(
                    ipv6_address=ipv6,
                    mac_address=mac,
                    interface=current_interface,
                    state=state,
                    scan_time=scan_time,
                )
            )

    logger.info("IPv6 neighbor scan found %d entries", len(neighbors))
    return neighbors


def _scan_linux() -> list[Ipv6Neighbor]:
    """Parse Linux 'ip -6 neigh show' output."""
    result = subprocess.run(
        ["ip", "-6", "neigh", "show"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        logger.warning("ip -6 neigh failed: %s", result.stderr.strip())
        return []

    return _parse_linux_output(result.stdout)


def _parse_linux_output(output: str) -> list[Ipv6Neighbor]:
    """Parse Linux 'ip -6 neigh show' output.

    Expected format:
    fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE

    Args:
        output: Raw ip -6 neigh output.

    Returns:
        List of Ipv6Neighbor entries.
    """
    neighbors: list[Ipv6Neighbor] = []
    scan_time = datetime.now(timezone.utc)

    pattern = re.compile(
        r"^([\da-fA-F:]+)\s+dev\s+(\S+)\s+lladdr\s+([\da-fA-F:]+)\s+(\S+)",
    )

    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            ipv6 = match.group(1)
            interface = match.group(2)
            mac = match.group(3).upper()
            state = match.group(4)

            if state.lower() == "failed":
                continue

            neighbors.append(
                Ipv6Neighbor(
                    ipv6_address=ipv6,
                    mac_address=mac,
                    interface=interface,
                    state=state,
                    scan_time=scan_time,
                )
            )

    logger.info("IPv6 neighbor scan found %d entries", len(neighbors))
    return neighbors
