"""Device fingerprinting based on multiple data sources.

Combines information from different scan methods (mDNS TXT records,
SSDP server strings, hostnames, vendor names) to build a richer
device profile.
"""

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DeviceFingerprint:
    """Aggregated fingerprint information for a device."""

    mac_address: str
    os_family: str = ""
    os_version: str = ""
    device_model: str = ""
    manufacturer: str = ""
    services: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0

    def merge(self, other: "DeviceFingerprint") -> None:
        """Merge another fingerprint's data into this one.

        Only fills in empty fields; does not overwrite existing data.

        Args:
            other: Fingerprint to merge from.
        """
        if not self.os_family and other.os_family:
            self.os_family = other.os_family
        if not self.os_version and other.os_version:
            self.os_version = other.os_version
        if not self.device_model and other.device_model:
            self.device_model = other.device_model
        if not self.manufacturer and other.manufacturer:
            self.manufacturer = other.manufacturer
        for svc in other.services:
            if svc not in self.services:
                self.services.append(svc)
        self.confidence = max(self.confidence, other.confidence)


def fingerprint_from_mdns_txt(
    mac_address: str, txt_records: dict[str, str], service_type: str = ""
) -> DeviceFingerprint:
    """Build a fingerprint from mDNS TXT records.

    Common TXT record keys:
    - md: model description (e.g., "Synology DS920+")
    - fn: friendly name
    - am: Apple model
    - os: OS info

    Args:
        mac_address: Device MAC address.
        txt_records: Parsed TXT records from mDNS.
        service_type: The mDNS service type.

    Returns:
        DeviceFingerprint with available information.
    """
    fp = DeviceFingerprint(mac_address=mac_address)

    # Apple model identifier (e.g., "MacBookPro18,1") — check first
    apple_model = txt_records.get("am", "")
    if apple_model:
        fp.device_model = apple_model
        fp.manufacturer = "Apple"
        fp.confidence = max(fp.confidence, 0.8)

    # Model descriptor (e.g., "Synology DS920+")
    model = txt_records.get("md", "")
    if model:
        fp.device_model = model  # md is more descriptive, overrides am
        fp.confidence = max(fp.confidence, 0.7)

    # Friendly name
    if txt_records.get("fn"):
        fp.device_model = fp.device_model or txt_records["fn"]

    # OS
    os_info = txt_records.get("os", "")
    if os_info:
        family, version = _parse_os_string(os_info)
        fp.os_family = family
        fp.os_version = version
        fp.confidence = max(fp.confidence, 0.6)

    if service_type:
        fp.services.append(service_type)

    return fp


def fingerprint_from_ssdp_server(mac_address: str, server_string: str) -> DeviceFingerprint:
    """Build a fingerprint from an SSDP Server header.

    Typical format: "OS/version UPnP/1.0 product/version"
    Example: "Linux/4.14.0 UPnP/1.0 Synology/DSM"

    Args:
        mac_address: Device MAC address.
        server_string: SSDP Server header value.

    Returns:
        DeviceFingerprint with available information.
    """
    fp = DeviceFingerprint(mac_address=mac_address)

    if not server_string:
        return fp

    parts = server_string.split()
    for part in parts:
        if "/" in part:
            name, _, version = part.partition("/")
            name_lower = name.lower()

            # OS detection
            if name_lower in ("linux", "windows", "darwin", "macos", "freebsd"):
                fp.os_family = name
                fp.os_version = version
                fp.confidence = max(fp.confidence, 0.5)
            elif "upnp" not in name_lower:
                # Likely a product identifier
                if not fp.manufacturer:
                    fp.manufacturer = name
                    fp.device_model = f"{name}/{version}"
                    fp.confidence = max(fp.confidence, 0.4)

    return fp


def fingerprint_from_hostname(mac_address: str, hostname: str) -> DeviceFingerprint:
    """Infer device information from hostname patterns.

    Args:
        mac_address: Device MAC address.
        hostname: Resolved hostname.

    Returns:
        DeviceFingerprint with available information.
    """
    fp = DeviceFingerprint(mac_address=mac_address)

    if not hostname:
        return fp

    hostname_lower = hostname.lower()

    # Apple devices
    for pattern, model in [
        (r"(iphone)", "iPhone"),
        (r"(ipad)", "iPad"),
        (r"(macbook)", "MacBook"),
        (r"(imac)", "iMac"),
        (r"(mac-?mini)", "Mac mini"),
        (r"(mac-?pro)", "Mac Pro"),
        (r"(apple-?tv)", "Apple TV"),
        (r"(homepod)", "HomePod"),
    ]:
        if re.search(pattern, hostname_lower):
            fp.manufacturer = "Apple"
            fp.device_model = model
            fp.os_family = "iOS" if model in ("iPhone", "iPad") else "macOS"
            fp.confidence = 0.6
            return fp

    # Windows patterns
    if re.search(r"(desktop|laptop|pc)\b", hostname_lower):
        fp.os_family = "Windows"
        fp.confidence = 0.3

    # Android
    if re.search(r"android", hostname_lower):
        fp.os_family = "Android"
        fp.confidence = 0.5

    # Samsung Galaxy
    match = re.search(r"galaxy[-_\s]?(s\d+|a\d+|note\d+|z\w+)", hostname_lower)
    if match:
        fp.manufacturer = "Samsung"
        fp.device_model = f"Galaxy {match.group(1).upper()}"
        fp.os_family = "Android"
        fp.confidence = 0.7

    # Synology
    if re.search(r"(diskstation|ds\d{3,4}|synology)", hostname_lower):
        fp.manufacturer = "Synology"
        fp.os_family = "DSM"
        fp.confidence = 0.7

    return fp


def _parse_os_string(os_string: str) -> tuple[str, str]:
    """Parse an OS string into family and version.

    Args:
        os_string: Raw OS string (e.g., "macOS 14.2", "Linux 5.15").

    Returns:
        Tuple of (os_family, os_version).
    """
    match = re.match(r"(\w+)\s*([\d.]+)?", os_string)
    if match:
        return match.group(1), match.group(2) or ""
    return os_string, ""
