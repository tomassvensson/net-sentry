"""NetBIOS name resolution for network devices.

Provides NetBIOS Name Service (NBNS) queries to resolve
NetBIOS names for IP addresses on the local network, commonly
used by Windows machines and Samba shares.
"""

import logging
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# NetBIOS Name Service port
_NBNS_PORT = 137
_NBNS_TIMEOUT = 2.0


@dataclass
class NetBiosInfo:
    """NetBIOS information for a network device."""

    ip_address: str
    netbios_name: str = ""
    domain: str = ""
    mac_address: str = ""
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def resolve_netbios_name(ip_address: str, timeout: float = _NBNS_TIMEOUT) -> NetBiosInfo | None:
    """Resolve a NetBIOS name for a given IP address.

    Sends an NBNS status query (NBSTAT) to the target IP and parses
    the response to extract the computer's NetBIOS name.

    Args:
        ip_address: IP address to query.
        timeout: Socket timeout in seconds.

    Returns:
        NetBiosInfo if successful, None otherwise.
    """
    try:
        # Build NBNS status request (NBSTAT query)
        transaction_id = 0x1234
        packet = _build_nbstat_request(transaction_id)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip_address, _NBNS_PORT))
            data, _ = sock.recvfrom(1024)
            return _parse_nbstat_response(ip_address, data)
        finally:
            sock.close()

    except TimeoutError:
        logger.debug("NetBIOS query timed out for %s", ip_address)
    except OSError as exc:
        logger.debug("NetBIOS query failed for %s: %s", ip_address, exc)

    return None


def resolve_netbios_names(ip_addresses: list[str], timeout: float = _NBNS_TIMEOUT) -> list[NetBiosInfo]:
    """Resolve NetBIOS names for multiple IP addresses.

    Args:
        ip_addresses: List of IP addresses to query.
        timeout: Socket timeout per query in seconds.

    Returns:
        List of successfully resolved NetBiosInfo objects.
    """
    logger.info("Resolving NetBIOS names for %d addresses...", len(ip_addresses))
    results: list[NetBiosInfo] = []

    for ip in ip_addresses:
        info = resolve_netbios_name(ip, timeout)
        if info and info.netbios_name:
            results.append(info)

    logger.info("NetBIOS resolution complete: %d/%d resolved.", len(results), len(ip_addresses))
    return results


def _build_nbstat_request(transaction_id: int) -> bytes:
    """Build an NBNS Node Status Request (NBSTAT) packet.

    Args:
        transaction_id: Transaction ID for the request.

    Returns:
        bytes of the NBNS packet.
    """
    # Header: TransID, Flags(0x0000=query), Questions=1, Answers=0, Auth=0, Additional=0
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)

    # Query: encoded NBSTAT name (*\x00 = wildcard), type=NBSTAT(0x0021), class=IN(0x0001)
    # NetBIOS encoded wildcard name: 32 bytes of 'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    encoded_name = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    query = encoded_name + struct.pack(">HH", 0x0021, 0x0001)

    return header + query


def _parse_nbstat_response(ip_address: str, data: bytes) -> NetBiosInfo | None:
    """Parse an NBNS Node Status Response.

    Args:
        ip_address: IP that sent the response.
        data: Raw response bytes.

    Returns:
        NetBiosInfo if valid, None otherwise.
    """
    if len(data) < 57:  # Minimum valid response size
        return None

    try:
        # Skip header (12 bytes) + query echo + answer header
        # Find the number of names
        offset = 56  # Typical offset to the count byte
        if offset >= len(data):
            return None

        name_count = data[offset]
        offset += 1

        netbios_name = ""
        domain = ""

        for _ in range(name_count):
            if offset + 18 > len(data):
                break

            # Each entry: 15-byte name + 1-byte suffix + 2-byte flags
            raw_name = data[offset : offset + 15].decode("ascii", errors="replace").strip()
            suffix = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
            offset += 18

            # Suffix 0x00 = workstation/computer name (unique)
            if suffix == 0x00 and not (flags & 0x8000) and not netbios_name:
                netbios_name = raw_name

            # Suffix 0x00 with group flag = domain/workgroup
            if suffix == 0x00 and (flags & 0x8000) and not domain:
                domain = raw_name

        # MAC address is 6 bytes after all name entries
        mac = ""
        if offset + 6 <= len(data):
            mac_bytes = data[offset : offset + 6]
            mac = ":".join(f"{b:02X}" for b in mac_bytes)
            # Ignore zero/broadcast MACs
            if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                mac = ""

        if netbios_name:
            return NetBiosInfo(
                ip_address=ip_address,
                netbios_name=netbios_name,
                domain=domain,
                mac_address=mac,
            )

    except Exception:
        logger.debug("Failed to parse NBSTAT response from %s", ip_address)

    return None
