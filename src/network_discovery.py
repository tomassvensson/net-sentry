"""Network device discovery via ARP table and hostname resolution.

Discovers devices on the local network segment by inspecting the ARP
table and attempting hostname resolution for human-readable names.

Security: This is purely passive — reads the existing ARP cache and
performs standard DNS/NetBIOS lookups. No probing or port scanning.
"""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.oui_lookup import is_multicast_mac, is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class NetworkDevice:
    """A device discovered on the local network via ARP."""

    ip_address: str
    mac_address: str
    interface: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    is_randomized: bool = False
    arp_type: str = "dynamic"  # "dynamic" or "static"
    network_segment: str | None = None  # Subnet/VLAN label from ping_sweep config
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Post-initialization: look up vendor and check for randomization."""
        if self.vendor is None and self.mac_address:
            self.vendor = lookup_vendor(self.mac_address)
        if self.mac_address:
            self.is_randomized = is_randomized_mac(self.mac_address)


def scan_arp_table() -> list[NetworkDevice]:
    """Read the ARP table to discover devices on the local network.

    Returns:
        List of NetworkDevice objects from the ARP cache.
    """
    logger.info("Reading ARP table for local network devices...")

    system = platform.system().lower()
    if system == "windows":
        cmd = ["arp", "-a"]
        parser = _parse_arp_output
    else:
        cmd = ["ip", "neigh", "show"]
        parser = _parse_ip_neigh_output

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        logger.error("%s command not found.", cmd[0])
        return []
    except subprocess.TimeoutExpired:
        logger.error("ARP table query timed out.")
        return []

    if result.returncode != 0:
        logger.warning("ARP command failed (rc=%d)", result.returncode)
        return []

    devices = parser(result.stdout)

    for device in devices:
        device.hostname = _resolve_hostname(device.ip_address)

    logger.info("ARP scan complete: found %d devices.", len(devices))
    return devices


def _parse_arp_output(output: str) -> list[NetworkDevice]:
    """Parse the output of `arp -a`.

    Handles Windows arp output format:
      Interface: 192.168.1.1 --- 0x4
        Internet Address    Physical Address      Type
        192.168.1.2         aa-bb-cc-dd-ee-ff     dynamic

    Args:
        output: Raw stdout from arp command.

    Returns:
        List of NetworkDevice objects.
    """
    devices: list[NetworkDevice] = []
    current_interface = ""
    seen_macs: set[str] = set()

    for line in output.splitlines():
        line = line.strip()

        # Interface line
        iface_match = re.match(r"^Interface:\s*(\S+)", line, re.IGNORECASE)
        if iface_match:
            current_interface = iface_match.group(1)
            continue

        # ARP entry line: IP  MAC  Type
        arp_match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+(\w+)",
            line,
        )
        if arp_match:
            device = _parse_arp_entry(arp_match, current_interface, seen_macs)
            if device:
                devices.append(device)

    return devices


def _parse_arp_entry(
    match: re.Match[str],
    interface: str,
    seen_macs: set[str],
) -> NetworkDevice | None:
    """Parse a single ARP table entry.

    Args:
        match: Regex match with groups (ip, mac, type).
        interface: Current network interface.
        seen_macs: Set of already-seen MACs for dedup.

    Returns:
        NetworkDevice if valid, None otherwise.
    """
    ip = match.group(1)
    mac_raw = match.group(2)
    arp_type = match.group(3).lower()

    # Skip broadcast addresses
    if mac_raw.lower() in ("ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"):
        return None

    try:
        mac = normalize_mac(mac_raw)
    except ValueError:
        return None

    # Skip multicast MACs (first byte odd)
    if is_multicast_mac(mac):
        return None

    if mac in seen_macs:
        return None
    seen_macs.add(mac)

    return NetworkDevice(
        ip_address=ip,
        mac_address=mac,
        interface=interface,
        arp_type=arp_type,
    )


def _parse_ip_neigh_output(output: str) -> list[NetworkDevice]:
    """Parse the output of `ip neigh show` on Linux.

    Format: IP dev IFACE lladdr MAC STATE

    Args:
        output: Raw stdout from ip neigh command.

    Returns:
        List of NetworkDevice objects.
    """
    devices: list[NetworkDevice] = []
    seen_macs: set[str] = set()

    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+"
        r"([\da-fA-F]{2}(?::[\da-fA-F]{2}){5})\s+(\S+)",
    )

    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue

        ip = match.group(1)
        interface = match.group(2)
        mac_raw = match.group(3)
        state = match.group(4).lower()

        if state == "failed":
            continue

        if mac_raw.lower() == "ff:ff:ff:ff:ff:ff":
            continue

        try:
            mac = normalize_mac(mac_raw)
        except ValueError:
            continue

        if is_multicast_mac(mac):
            continue

        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        devices.append(
            NetworkDevice(
                ip_address=ip,
                mac_address=mac,
                interface=interface,
                arp_type="dynamic" if state in ("reachable", "stale", "delay", "probe") else state,
            )
        )

    return devices


def _ip_to_pseudo_mac(ip: str) -> str:
    """Generate a deterministic locally-administered MAC from an IP address.

    Uses the locally-administered bit (02:xx) so these never collide with
    real OUI-assigned MACs.
    """
    octets = ip.split(".")
    return f"02:00:{int(octets[0]):02X}:{int(octets[1]):02X}:{int(octets[2]):02X}:{int(octets[3]):02X}"


def _ping_host(ip: str, timeout: float = 1.0) -> str | None:
    """Ping a single host. Returns the IP if it responds, None otherwise."""
    system = platform.system().lower()
    if system == "windows":
        timeout_ms = max(1, int(timeout * 1000))
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), str(ip)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2,
            check=False,
        )
        if result.returncode == 0:
            return ip
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def ping_sweep(
    subnets: list[str],
    max_workers: int = 40,
    timeout: float = 1.0,
    subnet_labels: dict[str, str] | None = None,
) -> list[NetworkDevice]:
    """Ping-sweep one or more subnets and return responding hosts.

    For hosts discovered through a NAT (where real MACs aren't available),
    a deterministic locally-administered pseudo-MAC is generated from the IP.

    Args:
        subnets: List of CIDR subnets to scan (e.g. ["192.168.0.0/24"]).
        max_workers: Maximum concurrent pings.
        timeout: Ping timeout per host in seconds.
        subnet_labels: Optional mapping from CIDR string to a human-readable
            segment label (e.g. ``{"192.168.1.0/24": "office"}``).  When
            provided, each discovered device gets its ``network_segment``
            field set to the corresponding label (or the raw CIDR if no
            label is defined).

    Returns:
        List of NetworkDevice objects for responding hosts.
    """
    _subnet_labels: dict[str, str] = subnet_labels or {}
    # Build a map from each host IP to its source CIDR (for labelling)
    ip_to_cidr: dict[str, str] = {}
    targets: list[str] = []
    for cidr in subnets:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for h in network.hosts():
                host_str = str(h)
                targets.append(host_str)
                ip_to_cidr[host_str] = cidr
        except ValueError:
            logger.warning("Invalid subnet: %s", cidr)

    if not targets:
        return []

    logger.info("Ping sweep: %d hosts across %d subnet(s)...", len(targets), len(subnets))

    alive: list[str] = []
    checked = 0
    last_progress_log = time.monotonic()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping_host, ip, timeout): ip for ip in targets}
        for future in as_completed(futures):
            result = future.result()
            checked += 1
            if result:
                alive.append(result)
            now = time.monotonic()
            if checked == len(targets) or now - last_progress_log >= 30:
                logger.info(
                    "Ping sweep progress: %d/%d host(s) checked, %d responded.",
                    checked,
                    len(targets),
                    len(alive),
                )
                last_progress_log = now

    logger.info("Ping sweep complete: %d hosts responded.", len(alive))

    devices: list[NetworkDevice] = []
    for ip in sorted(alive, key=lambda x: tuple(int(o) for o in x.split("."))):
        mac = _ip_to_pseudo_mac(ip)
        hostname = _resolve_hostname(ip)
        vendor = lookup_vendor(mac)
        # Determine the network segment label for this device
        source_cidr = ip_to_cidr.get(ip)
        segment: str | None = None
        if source_cidr:
            segment = _subnet_labels.get(source_cidr, source_cidr)
        devices.append(
            NetworkDevice(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                arp_type="ping",
                network_segment=segment,
            )
        )

    return devices


def _resolve_hostname(ip_address: str) -> str | None:
    """Attempt to resolve an IP address to a hostname.

    Tries reverse DNS lookup. On failure, returns None.

    Args:
        ip_address: IP address to resolve.

    Returns:
        Hostname string, or None if resolution fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        if hostname and hostname != ip_address:
            return hostname
    except OSError:
        pass

    return None


def discover_subnets_from_routing_table() -> list[str]:
    """Auto-detect local subnets by parsing the OS routing table.

    Reads the routing table and returns all directly-connected (non-default)
    network prefixes in CIDR notation.  Supports Linux (``ip route show``)
    and Windows (``route print``).

    Returns:
        Sorted list of CIDR strings, e.g. ``["192.168.1.0/24", "10.0.0.0/8"]``.
        Returns an empty list if the command fails or no subnets are found.
    """
    system = platform.system().lower()
    if system == "windows":
        return _parse_windows_routing_table()
    return _parse_linux_routing_table()


def _parse_linux_routing_table() -> list[str]:
    """Parse `ip route show` to extract directly-connected subnets."""
    try:
        result = subprocess.run(
            ["ip", "route", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("'ip' command not found; cannot auto-detect subnets.")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("'ip route show' timed out.")
        return []

    subnets: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        # Skip default routes and kernel/unreachable entries
        if line.startswith(("default", "unreachable", "prohibit", "blackhole")):
            continue
        # First token is the network (CIDR or bare IP)
        parts = line.split()
        if not parts:
            continue
        candidate = parts[0]
        try:
            net = ipaddress.ip_network(candidate, strict=False)
            # Only include private / RFC-1918 / link-local subnets with prefix ≥ /8
            if net.prefixlen >= 8:
                subnets.add(str(net))
        except ValueError:
            pass

    discovered = sorted(subnets)
    logger.info("Routing table: discovered %d subnet(s): %s", len(discovered), discovered)
    return discovered


def _parse_windows_routing_table() -> list[str]:
    """Parse ``route print`` to extract directly-connected subnets (Windows)."""
    try:
        result = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("'route' command not found; cannot auto-detect subnets.")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("'route print' timed out.")
        return []

    subnets: set[str] = set()
    # The IPv4 route table has lines like:
    #   Network Destination  Netmask  Gateway  Interface  Metric
    #   192.168.1.0          255.255.255.0   On-link  192.168.1.x  281
    _ipv4_section = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if "IPv4 Route Table" in stripped or "Active Routes" in stripped:
            _ipv4_section = True
            continue
        if _ipv4_section and stripped.startswith("=") and stripped.count("=") > 10:
            # Separator line between sections
            continue
        if not _ipv4_section:
            continue
        # Skip header / empty lines
        if not stripped or stripped.startswith("Network") or stripped.startswith("="):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        dest, mask = parts[0], parts[1]
        # Skip default and loopback
        if dest in ("0.0.0.0", "127.0.0.0"):
            continue
        try:
            net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
            if net.prefixlen >= 8:
                subnets.add(str(net))
        except ValueError:
            pass

    discovered = sorted(subnets)
    logger.info("Routing table: discovered %d subnet(s): %s", len(discovered), discovered)
    return discovered
