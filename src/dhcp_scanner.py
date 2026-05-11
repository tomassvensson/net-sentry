"""DHCP lease file parser for Net Sentry.

Reads ISC DHCP server lease files (``/var/lib/dhcp/dhcpd.leases`` or similar)
and converts the lease records into :class:`~src.network_discovery.NetworkDevice`
objects so that the rest of the pipeline can process them identically to
ARP-discovered devices.

The ISC DHCP lease format looks like::

    lease 192.168.1.100 {
        starts 2 2024/01/02 10:00:00;
        ends   2 2024/01/02 22:00:00;
        binding state active;
        hardware ethernet aa:bb:cc:dd:ee:ff;
        client-hostname "mylaptop";
    }

Only ``active`` leases (``binding state active``) are returned by default.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from src.network_discovery import NetworkDevice

logger = logging.getLogger(__name__)

# ISC DHCP lease block regex patterns
_LEASE_START_RE = re.compile(r"^lease\s+([\d.]+)\s*\{")
_BINDING_STATE_RE = re.compile(r"^\s*binding\s+state\s+(\w+)\s*;")
_HARDWARE_RE = re.compile(r"^\s*hardware\s+ethernet\s+([\da-fA-F:]+)\s*;")
_HOSTNAME_RE = re.compile(r"^\s*client-hostname\s+\"([^\"]+)\"\s*;")
_ENDS_RE = re.compile(r"^\s*ends\s+\d+\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s*;")


def parse_dhcp_leases(
    lease_file: str = "/var/lib/dhcp/dhcpd.leases",
    *,
    active_only: bool = True,
) -> list[NetworkDevice]:
    """Parse an ISC DHCP server lease file.

    Reads the lease file and yields one :class:`~src.network_discovery.NetworkDevice`
    per unique MAC address.  When a MAC appears in multiple lease blocks the
    most recently ending lease wins (last-write-wins based on ``ends`` timestamp).

    Args:
        lease_file: Path to the ISC DHCP lease database file.
        active_only: When ``True`` (default) only leases with
            ``binding state active`` are returned.  Set to ``False`` to also
            include expired/freed leases.

    Returns:
        List of :class:`~src.network_discovery.NetworkDevice` records derived
        from DHCP leases, one entry per unique MAC address.
    """
    path = Path(lease_file)
    if not path.exists():
        logger.warning("DHCP lease file not found: %s", lease_file)
        return []

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        logger.exception("Could not read DHCP lease file: %s", lease_file)
        return []

    return _parse_lease_text(raw, active_only=active_only)


def _parse_lease_text(text: str, *, active_only: bool) -> list[NetworkDevice]:
    """Parse the text content of a DHCP lease file.

    Args:
        text: Full text content of the lease file.
        active_only: Filter to active leases only.

    Returns:
        Deduplicated list of NetworkDevice records.
    """
    # Track best (latest-ending) lease per MAC
    best: dict[str, dict] = {}  # mac_address -> parsed record

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        lease_match = _LEASE_START_RE.match(line)
        if not lease_match:
            i += 1
            continue

        ip = lease_match.group(1)
        record: dict = {
            "ip_address": ip,
            "mac_address": None,
            "hostname": None,
            "binding_state": "unknown",
            "ends": None,
        }

        # Collect lines until the closing brace
        i += 1
        while i < len(lines) and "}" not in lines[i]:
            cur = lines[i]
            if m := _BINDING_STATE_RE.match(cur):
                record["binding_state"] = m.group(1).lower()
            elif m := _HARDWARE_RE.match(cur):
                record["mac_address"] = m.group(1).upper()
            elif m := _HOSTNAME_RE.match(cur):
                record["hostname"] = m.group(1)
            elif m := _ENDS_RE.match(cur):
                try:
                    ts_str = m.group(1).replace("/", "-")  # 2024-01-02 10:00:00
                    record["ends"] = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            i += 1
        i += 1  # skip closing brace

        if not record["mac_address"]:
            continue
        if active_only and record["binding_state"] != "active":
            continue

        mac = record["mac_address"]
        existing = best.get(mac)
        if existing is None:
            best[mac] = record
        else:
            # Keep the lease with the later expiry time
            if record["ends"] and (existing["ends"] is None or record["ends"] > existing["ends"]):
                best[mac] = record

    devices = [
        NetworkDevice(
            ip_address=r["ip_address"],
            mac_address=r["mac_address"],
            hostname=r["hostname"],
            arp_type="dhcp",
        )
        for r in best.values()
    ]

    logger.info(
        "DHCP lease import: %d active lease(s) from %d block(s) parsed",
        len(devices),
        len(best),
    )
    return devices
