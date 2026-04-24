"""Device fingerprinting based on multiple data sources.

Combines information from different scan methods (mDNS TXT records,
SSDP server strings, hostnames, vendor names) to build a richer
device profile.

Confidence scoring
------------------
Each piece of evidence carries a *weight* (0.0–1.0) representing how reliable
it is.  The overall ``DeviceFingerprint.confidence`` is derived by combining
all evidence weights via ``compute_confidence()``.  The combination rule is a
Bayesian-style complement product so that independent weak signals can together
produce a higher confidence than any single signal alone, while a single strong
signal can already push it near 1.0:

    confidence = 1 − ∏(1 − wᵢ)
"""

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Evidence tracking
# ---------------------------------------------------------------------------


@dataclass
class FingerprintEvidence:
    """A single piece of evidence contributing to device identification.

    Attributes:
        source: Where the evidence came from (e.g. ``"mdns"``, ``"ssdp"``).
        field: Which fingerprint field it informs (e.g. ``"os_family"``).
        value: The raw observed value.
        weight: Reliability weight in [0.0, 1.0].
    """

    source: str
    field: str
    value: str
    weight: float


def compute_confidence(evidence_list: list[FingerprintEvidence]) -> float:
    """Compute overall confidence from a list of evidence items.

    Uses the complement-product formula so that independent evidence items
    reinforce each other:

        confidence = 1 − ∏(1 − wᵢ)

    Args:
        evidence_list: List of ``FingerprintEvidence`` items.

    Returns:
        Float in [0.0, 1.0].
    """
    if not evidence_list:
        return 0.0
    complement = 1.0
    for ev in evidence_list:
        complement *= 1.0 - max(0.0, min(1.0, ev.weight))
    return round(1.0 - complement, 4)


# ---------------------------------------------------------------------------
# Fingerprint model
# ---------------------------------------------------------------------------


@dataclass
class DeviceFingerprint:
    """Aggregated fingerprint information for a device."""

    mac_address: str
    os_family: str = ""
    os_version: str = ""
    device_model: str = ""
    manufacturer: str = ""
    services: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0 — recomputed via compute_confidence()
    evidence: list[FingerprintEvidence] = field(default_factory=list)

    def add_evidence(self, source: str, fp_field: str, value: str, weight: float) -> None:
        """Record an evidence item and update the confidence score.

        Args:
            source: Evidence source label (e.g. ``"mdns"``).
            fp_field: Fingerprint field this evidence informs.
            value: Observed raw value.
            weight: Reliability weight in [0.0, 1.0].
        """
        self.evidence.append(FingerprintEvidence(source=source, field=fp_field, value=value, weight=weight))
        self.confidence = compute_confidence(self.evidence)

    def merge(self, other: "DeviceFingerprint") -> None:
        """Merge another fingerprint's data into this one.

        Only fills in empty fields; does not overwrite existing data.
        Evidence items from *other* are appended, and confidence is
        recomputed from the combined evidence.

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
        # Merge evidence and recompute confidence
        self.evidence.extend(other.evidence)
        self.confidence = compute_confidence(self.evidence)


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
        fp.add_evidence("mdns", "device_model", apple_model, 0.8)

    # Model descriptor (e.g., "Synology DS920+")
    model = txt_records.get("md", "")
    if model:
        fp.device_model = model  # md is more descriptive, overrides am
        fp.add_evidence("mdns", "device_model", model, 0.7)

    # Friendly name
    if txt_records.get("fn"):
        fp.device_model = fp.device_model or txt_records["fn"]

    # OS
    os_info = txt_records.get("os", "")
    if os_info:
        family, version = _parse_os_string(os_info)
        fp.os_family = family
        fp.os_version = version
        fp.add_evidence("mdns", "os_family", os_info, 0.6)

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
                fp.add_evidence("ssdp", "os_family", part, 0.5)
            elif "upnp" not in name_lower:
                # Likely a product identifier
                if not fp.manufacturer:
                    fp.manufacturer = name
                    fp.device_model = f"{name}/{version}"
                    fp.add_evidence("ssdp", "manufacturer", part, 0.4)

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
            fp.add_evidence("hostname", "manufacturer", hostname, 0.6)
            return fp

    # Windows patterns
    if re.search(r"(desktop|laptop|pc)\b", hostname_lower):
        fp.os_family = "Windows"
        fp.add_evidence("hostname", "os_family", hostname, 0.3)

    # Android
    if re.search(r"android", hostname_lower):
        fp.os_family = "Android"
        fp.add_evidence("hostname", "os_family", hostname, 0.5)

    # Samsung Galaxy
    match = re.search(r"galaxy[-_\s]?(s\d+|a\d+|note\d+|z\w+)", hostname_lower)
    if match:
        fp.manufacturer = "Samsung"
        fp.device_model = f"Galaxy {match.group(1).upper()}"
        fp.os_family = "Android"
        fp.add_evidence("hostname", "device_model", hostname, 0.7)

    # Synology
    if re.search(r"(diskstation|ds\d{3,4}|synology)", hostname_lower):
        fp.manufacturer = "Synology"
        fp.os_family = "DSM"
        fp.add_evidence("hostname", "manufacturer", hostname, 0.7)

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
