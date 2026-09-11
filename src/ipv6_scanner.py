"""IPv6 neighbor discovery scanner.

Uses the system's IPv6 neighbor table to discover devices on the local
network via NDP (Neighbor Discovery Protocol).
"""

import logging
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.oui_lookup import is_multicast_mac, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class Ipv6Neighbor:
    """A discovered IPv6 neighbor."""

    ipv6_address: str
    mac_address: str
    interface: str = ""
    state: str = ""
    scan_time: datetime = field(default_factory=lambda: datetime.now(UTC))

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
        neighbors = _scan_windows() if system == "windows" else _scan_linux()
    except FileNotFoundError:
        logger.warning("IPv6 neighbor scan command not available on this platform")
        return []
    except subprocess.SubprocessError:
        logger.exception("IPv6 neighbor scan failed")
        return []
    return deduplicate_privacy_addresses(neighbors)


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
    scan_time = datetime.now(UTC)

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

            try:
                mac = normalize_mac(mac_raw)
            except ValueError:
                continue

            # Skip multicast/protocol groups and incomplete entries.
            if is_multicast_mac(mac) or state.lower() == "unreachable":
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
    scan_time = datetime.now(UTC)

    pattern = re.compile(
        r"^([\da-fA-F:]+)\s+dev\s+(\S+)\s+lladdr\s+([\da-fA-F:]+)\s+(\S+)",
    )

    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            ipv6 = match.group(1)
            interface = match.group(2)
            mac_raw = match.group(3)
            state = match.group(4)

            try:
                mac = normalize_mac(mac_raw)
            except ValueError:
                continue

            if is_multicast_mac(mac) or state.lower() == "failed":
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


def _is_privacy_address(ipv6_address: str) -> bool:
    """Heuristically detect IPv6 privacy extension (RFC 4941) addresses.

    A privacy address:
    - Is a global unicast address (starts with 2 or 3)
    - Has a 64-bit interface identifier that does NOT follow EUI-64 encoding
      (EUI-64 has bit 6 of the first octet set and embeds FF:FE in octets 4-5).

    Link-local (fe80::/10), ULA (fc00::/7) and loopback are excluded from
    this heuristic.

    Args:
        ipv6_address: Full IPv6 address string (compressed or expanded).

    Returns:
        True if the address looks like a temporary privacy address.
    """
    import ipaddress

    try:
        addr = ipaddress.IPv6Address(ipv6_address)
    except ValueError:
        return False

    # Only consider global unicast (2000::/3)
    if not addr.is_global:
        return False

    # Expand to 16 bytes and inspect the interface identifier (last 8 bytes)
    packed = addr.packed
    iid = packed[8:]  # bytes 8-15

    # EUI-64 embeds FF:FE at positions 3-4 of the interface identifier.
    return not (iid[3] == 0xFF and iid[4] == 0xFE)


def deduplicate_privacy_addresses(neighbors: list[Ipv6Neighbor]) -> list[Ipv6Neighbor]:
    """Remove duplicate IPv6 neighbor entries caused by privacy extension addresses.

    When a device has multiple global unicast addresses (one EUI-64 derived and
    one or more privacy temporary addresses), all map to the same MAC.  This
    function keeps only one entry per MAC: the EUI-64 derived address if
    available, otherwise the first encountered address.

    Link-local addresses are kept separately because they are useful for
    diagnostics and uniquely identify the interface on the local segment.

    Args:
        neighbors: Raw list of discovered IPv6 neighbors.

    Returns:
        De-duplicated list with at most one global-unicast entry per MAC.
    """
    # Separate link-local from global/other addresses
    link_locals: list[Ipv6Neighbor] = []
    globals_by_mac: dict[str, list[Ipv6Neighbor]] = {}

    for n in neighbors:
        import ipaddress

        try:
            addr = ipaddress.IPv6Address(n.ipv6_address)
        except ValueError:
            link_locals.append(n)
            continue

        if addr.is_link_local:
            link_locals.append(n)
        else:
            globals_by_mac.setdefault(n.mac_address, []).append(n)

    deduped_globals: list[Ipv6Neighbor] = []
    for mac, entries in globals_by_mac.items():
        # Prefer EUI-64 derived address if any
        eui64 = [e for e in entries if not _is_privacy_address(e.ipv6_address)]
        if eui64:
            deduped_globals.append(eui64[0])
        else:
            # All are privacy addresses — keep the first one
            deduped_globals.append(entries[0])

        privacy_count = len(entries) - 1
        if privacy_count > 0:
            logger.debug(
                "Suppressed %d privacy address(es) for MAC %s",
                privacy_count,
                mac,
            )

    result = link_locals + deduped_globals
    if len(result) < len(neighbors):
        logger.info(
            "IPv6 privacy dedup: %d → %d entries (%d suppressed)",
            len(neighbors),
            len(result),
            len(neighbors) - len(result),
        )
    return result
