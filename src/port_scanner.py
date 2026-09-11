"""TCP port scanner with well-known port name resolution.

Performs a simple TCP connect scan (non-destructive, no packet crafting).
Results are intended to be cached in the Device record; re-scanning is
done only when explicitly requested via the ``--rescan-ports`` CLI flag.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Mapping from well-known TCP port numbers to human-readable service names.
# Deliberately kept as a simple dict (no external deps).
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "ike",
    514: "syslog",
    515: "printer",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    1900: "upnp",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "grafana",
    3306: "mysql",
    3389: "rdp",
    4443: "alt-https",
    5000: "flask",
    5432: "postgres",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    6443: "k8s-api",
    7001: "weblogic",
    8080: "http-alt",
    8443: "https-alt",
    8883: "mqtt-tls",
    9000: "sonar",
    9090: "prometheus",
    9091: "prometheus-push",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    27017: "mongodb",
}

# Default set of ports to scan when none are specified in config.
DEFAULT_PORTS: list[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    443,
    445,
    3389,
    8080,
    8443,
]


@dataclass
class OpenPort:
    """A single open TCP port on a host."""

    port: int
    service: str

    def __str__(self) -> str:
        return f"{self.port}/{self.service}"


def port_to_service(port: int) -> str:
    """Return the human-readable service name for a well-known port.

    Falls back to the string representation of the port number if unknown.

    Args:
        port: TCP port number.

    Returns:
        Service name string (e.g. "ssh", "http") or plain port number string.
    """
    return WELL_KNOWN_PORTS.get(port, str(port))


def scan_host_ports(
    ip_address: str,
    ports: list[int] | None = None,
    timeout: float = 0.5,
    max_workers: int = 20,
) -> list[OpenPort]:
    """TCP connect-scan a host on the given port list.

    Uses non-blocking sockets with a per-port timeout.  This is a
    passive-style scan — it only attempts a full TCP connect, which is
    the least disruptive approach that yields reliable results.

    Args:
        ip_address: Target host IP address.
        ports: TCP ports to probe. Defaults to DEFAULT_PORTS.
        timeout: Per-port connection timeout in seconds.
        max_workers: Maximum concurrent port probes.

    Returns:
        List of OpenPort instances for ports that accepted a connection,
        sorted by port number.
    """
    if not ip_address:
        return []

    target_ports = ports if ports is not None else DEFAULT_PORTS

    open_ports: list[OpenPort] = []

    def _probe(port: int) -> OpenPort | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    return OpenPort(port=port, service=port_to_service(port))
        except OSError:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe, p): p for p in target_ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda op: op.port)
    logger.debug("Port scan of %s: %d/%d ports open.", ip_address, len(open_ports), len(target_ports))
    return open_ports


def encode_open_ports(ports: list[OpenPort]) -> str:
    """Encode a list of OpenPort objects as a compact comma-separated string.

    Format: ``"22/ssh,80/http,443/https"``

    Args:
        ports: List of OpenPort objects.

    Returns:
        Comma-separated string, or empty string if none.
    """
    return ",".join(str(p) for p in ports)


def decode_open_ports(encoded: str | None) -> list[OpenPort]:
    """Decode a compact comma-separated port string back into OpenPort objects.

    Args:
        encoded: String produced by :func:`encode_open_ports`, or None/empty.

    Returns:
        List of OpenPort objects.
    """
    if not encoded:
        return []
    result: list[OpenPort] = []
    for token in encoded.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            port_str, service = token.split("/", 1)
        else:
            port_str = token
            service = token
        try:
            result.append(OpenPort(port=int(port_str), service=service))
        except ValueError:
            logger.warning("Could not parse port token: %r", token)
    return result
