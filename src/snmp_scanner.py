"""SNMP scanner for Net Sentry.

Uses SNMPv2c to query devices on the local network for system information
(sysDescr, sysName, sysContact, sysLocation) via the SNMPv2-MIB.

The scanner is implemented as a :class:`~src.scanner_plugin.ScannerPlugin`
so it is automatically loaded and run if ``pysnmp-lextudio`` is installed and
SNMP scanning is enabled in config.

Typical workflow
----------------
1. Do an ARP or ping-sweep first to get candidate IPs.
2. For each responding IP, walk/get the standard System group OIDs.
3. Return :class:`~src.scanner_plugin.ScanResult` objects.

Configuration (config.yaml)
----------------------------
Typical keys:
- enabled: true
- community: "public"
- port: 161
- timeout_seconds: 2
- retries: 1
- subnet: "192.168.1.0/24"
- max_hosts: 254
- oids: standard System MIB OIDs (optional override)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Network
from typing import Any

logger = logging.getLogger(__name__)

# Standard SNMP System MIB OIDs
_OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
_OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
_DEFAULT_OIDS = (_OID_SYS_DESCR, _OID_SYS_NAME, _OID_SYS_CONTACT, _OID_SYS_LOCATION)


@dataclass
class SnmpDeviceInfo:
    """Information collected about a device via SNMP.

    Attributes:
        ip_address: IPv4 address of the device.
        sys_descr: SNMP sysDescr (OS and hardware description).
        sys_name: SNMP sysName (hostname).
        sys_contact: SNMP sysContact.
        sys_location: SNMP sysLocation.
        scan_time: When the information was collected.
        raw: Raw OID-value mapping.
    """

    ip_address: str
    sys_descr: str = ""
    sys_name: str = ""
    sys_contact: str = ""
    sys_location: str = ""
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw: dict[str, str] = field(default_factory=dict)


def _resolve_mac_from_ip(ip_address: str) -> str | None:
    """Look up the MAC address for an IPv4 address via the OS ARP cache.

    This is a best-effort lookup; it will only work if the IP has been
    recently contacted (so it is in the local ARP table).

    Args:
        ip_address: IPv4 address string.

    Returns:
        MAC address string (colon-separated lower-case) or ``None``.
    """
    import re  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    try:
        result = subprocess.run(
            ["arp", "-n", ip_address],
            capture_output=True,
            text=True,
            timeout=3,
        )
        # Look for a MAC address pattern in the output
        mac_match = re.search(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", result.stdout)
        if mac_match:
            return mac_match.group(0).replace("-", ":").lower()
    except Exception:
        logger.debug("ARP lookup failed for %s", ip_address)
    return None


def query_snmp_device(
    ip_address: str,
    community: str = "public",
    port: int = 161,
    timeout: int = 2,
    retries: int = 1,
    oids: tuple[str, ...] = _DEFAULT_OIDS,
) -> SnmpDeviceInfo | None:
    """Query a single device via SNMPv2c GET.

    Args:
        ip_address: Target IPv4 address.
        community: SNMP community string.
        port: SNMP UDP port (default 161).
        timeout: Per-request timeout in seconds.
        retries: Number of retries on timeout.
        oids: OID strings to GET.

    Returns:
        :class:`SnmpDeviceInfo` on success, ``None`` if unreachable or
        SNMP not supported.
    """
    try:
        from pysnmp.hlapi import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
        )
    except ImportError:
        logger.warning("pysnmp-lextudio is not installed — SNMP scanning unavailable")
        return None

    var_binds: list[Any] = [ObjectType(ObjectIdentity(oid)) for oid in oids]

    engine = SnmpEngine()
    transport = UdpTransportTarget((ip_address, port), timeout=timeout, retries=retries)
    auth = CommunityData(community, mpModel=1)  # mpModel=1 → SNMPv2c

    error_indication, error_status, error_index, result = next(
        getCmd(engine, auth, transport, ContextData(), *var_binds)
    )

    if error_indication:
        logger.debug("SNMP error for %s: %s", ip_address, error_indication)
        return None
    if error_status:
        idx = int(error_index) - 1 if error_index else None
        faulty_oid = result[idx][0] if idx is not None and 0 <= idx < len(result) else "?"
        logger.debug(
            "SNMP error-status for %s: %s at %s",
            ip_address,
            error_status.prettyPrint(),
            faulty_oid,
        )
        return None

    raw: dict[str, str] = {}
    for var_bind in result:
        oid_str, val = str(var_bind[0]), str(var_bind[1])
        raw[oid_str] = val

    info = SnmpDeviceInfo(ip_address=ip_address, raw=raw)
    info.sys_descr = raw.get(_OID_SYS_DESCR, raw.get(f"{_OID_SYS_DESCR}.0", ""))
    info.sys_name = raw.get(_OID_SYS_NAME, raw.get(f"{_OID_SYS_NAME}.0", ""))
    info.sys_contact = raw.get(_OID_SYS_CONTACT, raw.get(f"{_OID_SYS_CONTACT}.0", ""))
    info.sys_location = raw.get(_OID_SYS_LOCATION, raw.get(f"{_OID_SYS_LOCATION}.0", ""))

    return info


def scan_snmp_devices(
    hosts: list[str],
    community: str = "public",
    port: int = 161,
    timeout: int = 2,
    retries: int = 1,
    max_hosts: int = 254,
    oids: tuple[str, ...] = _DEFAULT_OIDS,
) -> list[SnmpDeviceInfo]:
    """Query a list of hosts via SNMP and return those that respond.

    Args:
        hosts: IPv4 address strings to query.
        community: SNMP community string.
        port: SNMP UDP port.
        timeout: Per-request timeout in seconds.
        retries: Number of retries.
        max_hosts: Maximum number of hosts to scan (protects against large
                   subnets).
        oids: OID strings to GET.

    Returns:
        List of :class:`SnmpDeviceInfo` for responding hosts.
    """
    results: list[SnmpDeviceInfo] = []
    scanned = 0
    for host in hosts:
        if scanned >= max_hosts:
            logger.info("SNMP scan reached max_hosts limit (%d)", max_hosts)
            break
        scanned += 1
        info = query_snmp_device(
            host,
            community=community,
            port=port,
            timeout=timeout,
            retries=retries,
            oids=oids,
        )
        if info is not None:
            results.append(info)

    logger.info("SNMP scan: %d/%d hosts responded", len(results), scanned)
    return results


# ---------------------------------------------------------------------------
# Plugin implementation
# ---------------------------------------------------------------------------


class SnmpScanner:
    """BtWiFi scanner plugin for SNMP device discovery.

    Registered automatically via the ``btwifi.scanners`` entry-point
    group in :file:`pyproject.toml`.
    """

    name = "snmp"
    description = "SNMPv2c system-info query for local network devices"

    def is_available(self) -> bool:
        """Return True when pysnmp-lextudio is installed."""
        try:
            import pysnmp  # noqa: F401

            return True
        except ImportError:
            return False

    def scan(self, config: Any) -> list[Any]:
        """Perform an SNMP scan using config.snmp settings.

        Requires a list of target IPs.  If ``config.snmp`` provides a
        ``subnet`` (e.g. ``"192.168.1.0/24"``), all host addresses in that
        subnet are queried.  Otherwise returns an empty list.

        Args:
            config: :class:`~src.config.AppConfig` instance.

        Returns:
            List of :class:`~src.scanner_plugin.ScanResult` objects.
        """
        from src.scanner_plugin import ScanResult  # noqa: PLC0415

        snmp_cfg: Any = getattr(config, "snmp", None)
        if snmp_cfg is None or not getattr(snmp_cfg, "enabled", False):
            return []

        community = getattr(snmp_cfg, "community", "public")
        port = getattr(snmp_cfg, "port", 161)
        timeout = getattr(snmp_cfg, "timeout_seconds", getattr(snmp_cfg, "timeout", 2))
        retries = getattr(snmp_cfg, "retries", 1)
        max_hosts = getattr(snmp_cfg, "max_hosts", 254)
        subnet = getattr(snmp_cfg, "subnet", None)

        if not subnet:
            logger.info("SNMP scanner: no subnet configured — skipping")
            return []

        try:
            hosts = [str(ip) for ip in IPv4Network(subnet, strict=False).hosts()]
        except ValueError:
            logger.error("SNMP scanner: invalid subnet %r", subnet)
            return []

        infos = scan_snmp_devices(
            hosts,
            community=community,
            port=port,
            timeout=timeout,
            retries=retries,
            max_hosts=max_hosts,
        )

        scan_results: list[ScanResult] = []
        for info in infos:
            mac = _resolve_mac_from_ip(info.ip_address)
            if not mac:
                # Use a synthetic MAC derived from the IP as a fallback identifier
                parts = info.ip_address.split(".")
                mac = "00:00:" + ":".join(f"{int(p):02x}" for p in parts)
                logger.debug("No ARP entry for %s; using synthetic MAC %s", info.ip_address, mac)

            name = info.sys_name or info.ip_address
            scan_results.append(
                ScanResult(
                    mac_address=mac,
                    device_type="snmp",
                    source=self.name,
                    scan_time=info.scan_time,
                    device_name=name,
                    ip_address=info.ip_address,
                    extra={
                        "sys_descr": info.sys_descr,
                        "sys_contact": info.sys_contact,
                        "sys_location": info.sys_location,
                    },
                )
            )

        return scan_results
