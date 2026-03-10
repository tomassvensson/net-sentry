"""SSDP / UPnP device discovery.

Discovers devices advertising via SSDP (Simple Service Discovery Protocol)
which is used by UPnP devices like smart TVs, media servers, routers, etc.
"""

import logging
import re
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)

# SSDP multicast address and port
_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_TIMEOUT = 3.0

# SSDP M-SEARCH request
_MSEARCH_MSG = (
    f'M-SEARCH * HTTP/1.1\r\nHOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
)


@dataclass
class SsdpDevice:
    """A device discovered via SSDP/UPnP."""

    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    server: str = ""
    location: str = ""
    usn: str = ""
    device_type: str = ""
    vendor: str | None = None
    is_randomized: bool = False
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def scan_ssdp_devices(timeout: float = _SSDP_TIMEOUT) -> list[SsdpDevice]:
    """Discover devices via SSDP M-SEARCH broadcast.

    Sends M-SEARCH requests and collects responses from UPnP devices
    on the local network.

    Args:
        timeout: How long to wait for responses (seconds).

    Returns:
        List of discovered SsdpDevice objects.
    """
    logger.info("Starting SSDP/UPnP discovery (timeout=%.1fs)...", timeout)
    devices: list[SsdpDevice] = []
    seen_ips: set[str] = set()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # Send M-SEARCH
        sock.sendto(_MSEARCH_MSG.encode("utf-8"), (_SSDP_ADDR, _SSDP_PORT))

        # Collect responses
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]

                if ip in seen_ips:
                    continue
                seen_ips.add(ip)

                response = data.decode("utf-8", errors="replace")
                device = _parse_ssdp_response(ip, response)
                if device:
                    devices.append(device)

            except TimeoutError:
                break
            except OSError:
                break

        sock.close()

    except OSError as exc:
        logger.error("SSDP discovery failed: %s", exc)

    logger.info("SSDP discovery complete: found %d devices.", len(devices))
    return devices


def _parse_ssdp_response(ip: str, response: str) -> SsdpDevice | None:
    """Parse an SSDP response into a device record.

    Args:
        ip: IP address of the responding device.
        response: Raw SSDP response text.

    Returns:
        SsdpDevice if valid, None otherwise.
    """
    headers: dict[str, str] = {}
    for line in response.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().upper()] = value.strip()

    server = headers.get("SERVER", "")
    location = headers.get("LOCATION", "")
    usn = headers.get("USN", "")
    st = headers.get("ST", "")

    # Try to resolve MAC from ARP cache
    mac = _arp_lookup_mac(ip)

    vendor = lookup_vendor(mac) if mac else None
    is_rand = is_randomized_mac(mac) if mac else False

    return SsdpDevice(
        ip_address=ip,
        mac_address=mac,
        server=server,
        location=location,
        usn=usn,
        device_type=st,
        vendor=vendor,
        is_randomized=is_rand,
    )


def _arp_lookup_mac(ip_address: str) -> str:
    """Look up a MAC from the ARP cache for a given IP.

    Args:
        ip_address: IP address to look up.

    Returns:
        Normalized MAC address, or empty string if not found.
    """
    try:
        result = subprocess.run(
            ["arp", "-a", ip_address],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            match = re.search(
                r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
                result.stdout,
            )
            if match:
                return normalize_mac(match.group(1))
    except Exception:
        pass

    return ""
