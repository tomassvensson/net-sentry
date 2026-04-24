"""Home Assistant REST API client for device name enrichment.

Queries the Home Assistant REST API to resolve device names and areas
(rooms/zones) from MAC-to-IP mappings already discovered by other scanners.

The lookup is cached per scan cycle so the API is hit at most once per
cycle regardless of how many devices are being enriched.

Docs: https://developers.home-assistant.io/docs/api/rest/
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HaDevice:
    """A device entity known to Home Assistant."""

    entity_id: str
    friendly_name: str
    area: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None


def fetch_ha_devices(
    ha_url: str,
    token: str,
    timeout: float = 5.0,
) -> list[HaDevice]:
    """Fetch all entity states from Home Assistant.

    Filters to entities that carry device tracker or network information
    (``device_tracker.*`` and ``sensor.*`` entities with MAC/IP attributes).

    Args:
        ha_url: Base URL of the Home Assistant instance (e.g. "http://ha:8123").
        token: Long-lived access token for the HA REST API.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of HaDevice objects with name/area/IP/MAC info.
    """
    url = ha_url.rstrip("/") + "/api/states"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw_data = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        logger.error("Home Assistant API error: HTTP %d for %s", exc.code, url)
        return []
    except urllib.error.URLError as exc:
        logger.error("Home Assistant connection failed: %s", exc.reason)
        return []
    except TimeoutError:
        logger.error("Home Assistant request timed out after %.1fs", timeout)
        return []

    try:
        states: list[dict] = json.loads(raw_data)
    except json.JSONDecodeError:
        logger.error("Home Assistant returned non-JSON response.")
        return []

    devices: list[HaDevice] = []
    for state in states:
        entity_id: str = state.get("entity_id", "")
        if not entity_id.startswith("device_tracker."):
            continue

        attrs: dict = state.get("attributes", {})
        friendly_name: str = attrs.get("friendly_name", entity_id)
        ip_address: str | None = attrs.get("ip") or attrs.get("ip_address")
        mac_address: str | None = _normalize_ha_mac(attrs.get("mac") or attrs.get("mac_address"))
        # HA may provide the area in attributes under some integrations
        area: str | None = attrs.get("area_id") or attrs.get("area")

        devices.append(
            HaDevice(
                entity_id=entity_id,
                friendly_name=friendly_name,
                area=area,
                ip_address=ip_address,
                mac_address=mac_address,
            )
        )

    logger.debug("Fetched %d device_tracker entities from Home Assistant.", len(devices))
    return devices


def build_ha_lookup(ha_devices: list[HaDevice]) -> dict[str, HaDevice]:
    """Build a MAC-keyed lookup dict from a list of HaDevice objects.

    Both MAC and IP address are used as keys where available to maximise
    match coverage.

    Args:
        ha_devices: List of HaDevice objects returned by :func:`fetch_ha_devices`.

    Returns:
        Dict mapping normalized MAC address (``"AA:BB:CC:DD:EE:FF"``) → HaDevice.
        IP address entries (``"192.168.x.x"``) are also included as keys.
    """
    lookup: dict[str, HaDevice] = {}
    for device in ha_devices:
        if device.mac_address:
            lookup[device.mac_address.upper()] = device
        if device.ip_address:
            lookup[device.ip_address] = device
    return lookup


def enrich_from_ha(
    mac_address: str,
    ip_address: str | None,
    ha_lookup: dict[str, HaDevice],
) -> HaDevice | None:
    """Look up a device in the Home Assistant cache by MAC or IP.

    Args:
        mac_address: Normalized MAC address of the device.
        ip_address: IP address of the device (optional).
        ha_lookup: Dict built by :func:`build_ha_lookup`.

    Returns:
        Matching HaDevice if found, else None.
    """
    if not ha_lookup:
        return None
    if mac_address:
        match = ha_lookup.get(mac_address.upper())
        if match:
            return match
    if ip_address:
        return ha_lookup.get(ip_address)
    return None


def _normalize_ha_mac(raw: str | None) -> str | None:
    """Normalize a MAC address string from HA to ``AA:BB:CC:DD:EE:FF`` format."""
    if not raw:
        return None
    cleaned = raw.upper().replace("-", ":").strip()
    # Validate minimal structure
    if len(cleaned) == 17 and cleaned.count(":") == 5:
        return cleaned
    return None
