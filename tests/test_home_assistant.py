"""Unit tests for src/home_assistant.py."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.home_assistant import (
    HaDevice,
    _normalize_ha_mac,
    build_ha_lookup,
    enrich_from_ha,
    fetch_ha_devices,
)

# ---------------------------------------------------------------------------
# _normalize_ha_mac
# ---------------------------------------------------------------------------


class TestNormalizeHaMac:
    def test_colon_separated_uppercase(self):
        assert _normalize_ha_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_colon_separated_lowercase(self):
        assert _normalize_ha_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_hyphen_separated(self):
        assert _normalize_ha_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator_returns_none(self):
        # _normalize_ha_mac only handles already-delimited MACs (colon or hyphen)
        assert _normalize_ha_mac("aabbccddeeff") is None

    def test_invalid_returns_none(self):
        assert _normalize_ha_mac("not-a-mac") is None
        assert _normalize_ha_mac("") is None
        assert _normalize_ha_mac(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# build_ha_lookup
# ---------------------------------------------------------------------------


class TestBuildHaLookup:
    def _make_device(self, mac, ip=None, area=None):
        return HaDevice(
            entity_id=f"device_tracker.test_{mac.replace(':', '')}",
            friendly_name=f"Device {mac}",
            area=area,
            ip_address=ip,
            mac_address=mac,
        )

    def test_keyed_by_mac(self):
        d = self._make_device("AA:BB:CC:DD:EE:01")
        lookup = build_ha_lookup([d])
        assert "AA:BB:CC:DD:EE:01" in lookup

    def test_keyed_by_ip(self):
        d = self._make_device("AA:BB:CC:DD:EE:01", ip="192.168.1.5")
        lookup = build_ha_lookup([d])
        assert "192.168.1.5" in lookup

    def test_device_without_ip_not_in_ip_index(self):
        d = self._make_device("AA:BB:CC:DD:EE:02")
        lookup = build_ha_lookup([d])
        for key in lookup:
            assert "." not in key  # no IP-style keys

    def test_empty_list(self):
        assert build_ha_lookup([]) == {}


# ---------------------------------------------------------------------------
# enrich_from_ha
# ---------------------------------------------------------------------------


class TestEnrichFromHa:
    def _lookup(self, mac="AA:BB:CC:DD:EE:01", ip="192.168.1.1", area="office"):
        device = HaDevice(
            entity_id="device_tracker.test",
            friendly_name="Test Device",
            area=area,
            ip_address=ip,
            mac_address=mac,
        )
        return build_ha_lookup([device])

    def test_match_by_mac(self):
        lookup = self._lookup(mac="AA:BB:CC:DD:EE:01")
        result = enrich_from_ha("AA:BB:CC:DD:EE:01", None, lookup)
        assert result is not None
        assert result.friendly_name == "Test Device"

    def test_match_by_ip(self):
        lookup = self._lookup(ip="10.0.0.5")
        result = enrich_from_ha(None, "10.0.0.5", lookup)
        assert result is not None

    def test_no_match_returns_none(self):
        lookup = self._lookup(mac="AA:BB:CC:DD:EE:01")
        result = enrich_from_ha("FF:FF:FF:FF:FF:FF", "10.0.0.99", lookup)
        assert result is None

    def test_empty_lookup(self):
        assert enrich_from_ha("AA:BB:CC:DD:EE:01", "192.168.1.1", {}) is None


# ---------------------------------------------------------------------------
# fetch_ha_devices
# ---------------------------------------------------------------------------


class TestFetchHaDevices:
    def _make_ha_response(self, entries):
        """Build a mock response bytes for urllib.request.urlopen."""
        return json.dumps(entries).encode()

    def test_returns_device_trackers(self):
        payload = [
            {
                "entity_id": "device_tracker.my_phone",
                "state": "home",
                "attributes": {
                    "friendly_name": "My Phone",
                    "ip": "192.168.1.50",
                    "mac": "AA:BB:CC:DD:EE:50",
                    "area_id": "office",
                },
            }
        ]
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = fetch_ha_devices("http://ha.local:8123", "token123")

        assert len(result) == 1
        assert result[0].friendly_name == "My Phone"
        assert result[0].mac_address == "AA:BB:CC:DD:EE:50"

    def test_ignores_non_device_tracker_entities(self):
        payload = [
            {
                "entity_id": "light.living_room",
                "state": "on",
                "attributes": {"friendly_name": "Living Room Light"},
            }
        ]
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = fetch_ha_devices("http://ha.local:8123", "token")

        assert result == []

    def test_network_error_returns_empty_list(self):
        from urllib.error import URLError

        with patch("urllib.request.urlopen", side_effect=URLError("timeout")):
            result = fetch_ha_devices("http://ha.local:8123", "token")

        assert result == []

    def test_malformed_json_returns_empty_list(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not valid json"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = fetch_ha_devices("http://ha.local:8123", "token")

        assert result == []
