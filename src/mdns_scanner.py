"""mDNS / Bonjour / Avahi device discovery using pure Python sockets.

Discovers devices advertising services via mDNS (multicast DNS),
commonly used by printers, IoT devices, Apple devices, etc.

Uses only Python standard library — no external dependencies.
"""

import logging
import select
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.oui_lookup import is_randomized_mac, lookup_vendor

logger = logging.getLogger(__name__)

# mDNS multicast address and port (RFC 6762)
_MDNS_ADDR = "224.0.0.251"
_MDNS_PORT = 5353

# DNS record types
_DNS_TYPE_A = 1
_DNS_TYPE_PTR = 12
_DNS_TYPE_TXT = 16
_DNS_TYPE_AAAA = 28
_DNS_TYPE_SRV = 33

# DNS-SD service enumeration query — returns PTR records naming all service types
_DNS_SD_SERVICES = "_services._dns-sd._udp.local."

# Common mDNS service types to browse
_SERVICE_TYPES: list[str] = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_matter._tcp.local.",
    "_esphomelib._tcp.local.",
    "_spotify-connect._tcp.local.",
]

# Timeout for mDNS browsing in seconds
_BROWSE_TIMEOUT = 5.0


@dataclass
class MdnsDevice:
    """A device discovered via mDNS service browsing."""

    hostname: str
    ip_address: str
    mac_address: str = ""
    service_type: str = ""
    service_name: str = ""
    port: int = 0
    vendor: str | None = None
    is_randomized: bool = False
    txt_records: dict[str, str] = field(default_factory=dict)
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def scan_mdns_services(timeout: float = _BROWSE_TIMEOUT, allowed_types: list[str] | None = None) -> list[MdnsDevice]:
    """Discover devices advertising mDNS services on the local network.

    Sends DNS PTR queries for common service types via multicast UDP
    and parses the responses — no external dependencies required.

    Args:
        timeout: How long to wait for responses per service type (seconds).
        allowed_types: If non-empty, only these service types are scanned.
            When empty or None, all built-in types plus DNS-SD-discovered
            types are scanned.

    Returns:
        List of discovered MdnsDevice objects.
    """
    logger.info("Starting mDNS service discovery (timeout=%.1fs per type)...", timeout)

    sock = _create_mdns_socket()
    if sock is None:
        logger.warning("Cannot start mDNS scanner: failed to create socket")
        return []

    seen_keys: set[str] = set()
    ptr_targets: list[str] = []
    all_records: list[dict] = []

    try:
        # Step 1: DNS-SD service enumeration — discover what service types are present
        dynamic_service_types: list[str] = []
        enum_responses = _query_service_type(sock, _DNS_SD_SERVICES, timeout)
        for raw in enum_responses:
            records = _parse_dns_records(raw)
            for r in records:
                if r["type"] == _DNS_TYPE_PTR and "target" in r:
                    svc = r["target"]
                    # PTR targets from _services._dns-sd are service-type names
                    if svc not in _SERVICE_TYPES and svc not in dynamic_service_types:
                        dynamic_service_types.append(svc)
                        logger.debug("DNS-SD discovered service type: %s", svc)

        if dynamic_service_types:
            logger.info("DNS-SD enumeration found %d additional service types", len(dynamic_service_types))

        # Step 2: Query all service types (static + discovered)
        all_service_types = allowed_types or list(_SERVICE_TYPES) + dynamic_service_types
        logger.info("mDNS querying %d service type(s).", len(all_service_types))
        last_progress_log = time.monotonic()
        for index, stype in enumerate(all_service_types, start=1):
            now = time.monotonic()
            if index == 1 or index == len(all_service_types) or now - last_progress_log >= 30:
                logger.info("mDNS progress: querying service type %d/%d (%s).", index, len(all_service_types), stype)
                last_progress_log = now
            raw_responses = _query_service_type(sock, stype, timeout)
            for raw in raw_responses:
                records = _parse_dns_records(raw)
                all_records.extend(records)
                for r in records:
                    if r["type"] == _DNS_TYPE_PTR and "target" in r:
                        ptr_targets.append(r["target"])
    finally:
        sock.close()

    devices = _build_devices_from_records(all_records, ptr_targets, seen_keys)
    logger.info("mDNS discovery complete: found %d services.", len(devices))
    return devices


# ---------------------------------------------------------------------------
# DNS wire-format helpers
# ---------------------------------------------------------------------------


def _encode_dns_name(name: str) -> bytes:
    """Encode a DNS name in wire format (labels, no compression).

    Args:
        name: Fully-qualified DNS name (e.g., "_http._tcp.local.").

    Returns:
        Wire-format encoded bytes.
    """
    result = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        result += bytes([len(encoded)]) + encoded
    return result + b"\x00"


def _build_ptr_query(service_type: str) -> bytes:
    """Build a DNS PTR query for an mDNS service type.

    Args:
        service_type: e.g. "_http._tcp.local."

    Returns:
        Raw DNS query packet bytes.
    """
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    qname = _encode_dns_name(service_type)
    question = qname + struct.pack(">HH", _DNS_TYPE_PTR, 1)  # type=PTR, class=IN
    return header + question


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format, handling pointer compression.

    Args:
        data: Full DNS message bytes.
        offset: Starting offset of the name.

    Returns:
        Tuple of (decoded name string, offset after the name).
    """
    labels: list[str] = []
    visited: set[int] = set()
    jumped = False
    end_offset = offset

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break
        elif (length & 0xC0) == 0xC0:
            # Pointer compression
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            if pointer in visited or pointer >= len(data):
                break
            visited.add(pointer)
            offset = pointer
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length

    name = ".".join(labels) + "." if labels else "."
    return name, end_offset


def _parse_dns_records(data: bytes) -> list[dict]:
    """Parse DNS resource records from a raw DNS message.

    Args:
        data: Raw DNS message bytes.

    Returns:
        List of record dicts with type-specific fields.
    """
    if len(data) < 12:
        return []

    try:
        _txn_id, _flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", data, 0)
    except struct.error:
        return []

    offset = 12
    for _ in range(qdcount):
        try:
            _, offset = _decode_dns_name(data, offset)
            offset += 4  # QTYPE + QCLASS
        except Exception:
            return []

    records: list[dict] = []
    for _ in range(ancount + nscount + arcount):
        if offset >= len(data):
            break
        try:
            name, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack_from(">HHIH", data, offset)
            offset += 10
            rdata_start = offset
            record: dict = {"name": name, "type": rtype}

            if rtype == _DNS_TYPE_PTR:
                target, _ = _decode_dns_name(data, rdata_start)
                record["target"] = target
            elif rtype == _DNS_TYPE_A and rdlength == 4:
                record["address"] = socket.inet_ntoa(data[rdata_start : rdata_start + 4])
            elif rtype == _DNS_TYPE_AAAA and rdlength == 16:
                record["address"] = socket.inet_ntop(socket.AF_INET6, data[rdata_start : rdata_start + 16])
            elif rtype == _DNS_TYPE_SRV and rdlength >= 6:
                priority, weight, port = struct.unpack_from(">HHH", data, rdata_start)
                target, _ = _decode_dns_name(data, rdata_start + 6)
                record["priority"] = priority
                record["weight"] = weight
                record["port"] = port
                record["target"] = target
            elif rtype == _DNS_TYPE_TXT:
                record["txt"] = _parse_txt_rdata(data[rdata_start : rdata_start + rdlength])

            records.append(record)
            offset = rdata_start + rdlength
        except Exception:
            break

    return records


def _parse_txt_rdata(rdata: bytes) -> dict[str, str]:
    """Parse TXT RDATA (RFC 1035: length-prefixed strings).

    Args:
        rdata: Raw TXT RDATA bytes.

    Returns:
        Key-value dict of TXT records.
    """
    txt: dict[str, str] = {}
    i = 0
    while i < len(rdata):
        str_len = rdata[i]
        i += 1
        if i + str_len > len(rdata):
            break
        item = rdata[i : i + str_len].decode("utf-8", errors="replace")
        i += str_len
        if "=" in item:
            k, _, v = item.partition("=")
            txt[k] = v
        else:
            txt[item] = ""
    return txt


# ---------------------------------------------------------------------------
# mDNS socket + query
# ---------------------------------------------------------------------------


def _create_mdns_socket() -> socket.socket | None:
    """Create a non-blocking UDP socket for mDNS multicast queries.

    Returns:
        Configured socket, or None on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setblocking(False)
        return sock
    except OSError:
        logger.debug("Failed to create mDNS socket")
        return None


def _query_service_type(
    sock: socket.socket,
    service_type: str,
    timeout: float,
) -> list[bytes]:
    """Send a PTR query and collect all responses within the timeout.

    Args:
        sock: UDP socket (non-blocking).
        service_type: mDNS service type to query.
        timeout: How long to wait for responses (seconds).

    Returns:
        List of raw response packets.
    """
    query = _build_ptr_query(service_type)
    responses: list[bytes] = []

    try:
        sock.sendto(query, (_MDNS_ADDR, _MDNS_PORT))
    except OSError:
        logger.debug("Failed to send mDNS query for %s", service_type)
        return responses

    readable, _, _ = select.select([sock], [], [], timeout)
    while readable:
        try:
            raw, _ = sock.recvfrom(4096)
            responses.append(raw)
        except OSError:
            break
        readable, _, _ = select.select([sock], [], [], 0)

    return responses


# ---------------------------------------------------------------------------
# Record aggregation
# ---------------------------------------------------------------------------


def _build_devices_from_records(
    all_records: list[dict],
    ptr_targets: list[str],
    seen_keys: set[str],
) -> list[MdnsDevice]:
    """Build MdnsDevice objects from parsed DNS records.

    Args:
        all_records: All parsed DNS records from responses.
        ptr_targets: Service instance names found in PTR records.
        seen_keys: Deduplication set (modified in place).

    Returns:
        List of resolved MdnsDevice objects.
    """
    srv_by_name: dict[str, dict] = {}
    txt_by_name: dict[str, dict] = {}
    a_by_host: dict[str, str] = {}

    for r in all_records:
        name = r.get("name", "")
        if r["type"] == _DNS_TYPE_SRV:
            srv_by_name[name] = r
        elif r["type"] == _DNS_TYPE_TXT:
            txt_by_name[name] = r
        elif r["type"] == _DNS_TYPE_A and "address" in r:
            a_by_host[name] = r["address"]

    devices: list[MdnsDevice] = []
    for instance_name in ptr_targets:
        device = _resolve_instance(instance_name, srv_by_name, txt_by_name, a_by_host, seen_keys)
        if device is not None:
            devices.append(device)

    return devices


def _resolve_instance(
    instance_name: str,
    srv_by_name: dict[str, dict],
    txt_by_name: dict[str, dict],
    a_by_host: dict[str, str],
    seen_keys: set[str],
) -> MdnsDevice | None:
    """Resolve a single service instance into an MdnsDevice.

    Args:
        instance_name: The service instance name from a PTR record.
        srv_by_name: SRV records indexed by service instance name.
        txt_by_name: TXT records indexed by service instance name.
        a_by_host: A records indexed by hostname.
        seen_keys: Deduplication set (modified in place).

    Returns:
        MdnsDevice if resolved, None if insufficient data.
    """
    srv = srv_by_name.get(instance_name)
    if srv is None:
        return None

    hostname = srv.get("target", "")
    ip = a_by_host.get(hostname, "")
    if not ip:
        return None

    key = f"{ip}:{instance_name}"
    if key in seen_keys:
        return None
    seen_keys.add(key)

    txt_record = txt_by_name.get(instance_name, {})
    txt_data: dict[str, str] = txt_record.get("txt", {})

    mac = _arp_lookup_mac(ip)
    vendor = lookup_vendor(mac) if mac else None
    is_rand = is_randomized_mac(mac) if mac else False

    parts = instance_name.split(".")
    stype = ".".join(parts[1:]) if len(parts) > 1 else ""
    stype_clean = stype.replace("._tcp.local.", "").replace("._udp.local.", "").lstrip("_")

    return MdnsDevice(
        hostname=hostname.rstrip("."),
        ip_address=ip,
        mac_address=mac,
        service_type=stype_clean,
        service_name=instance_name,
        port=srv.get("port", 0),
        vendor=vendor,
        is_randomized=is_rand,
        txt_records=txt_data,
    )


def _arp_lookup_mac(ip_address: str) -> str:
    """Look up a MAC address from the ARP cache for a given IP.

    Args:
        ip_address: IP address to look up.

    Returns:
        MAC address string (normalized), or empty string if not found.
    """
    import re
    import subprocess

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
                from src.oui_lookup import normalize_mac

                return normalize_mac(match.group(1))
    except Exception:
        pass

    return ""
