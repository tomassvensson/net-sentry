"""Contract tests for the ScannerPlugin interface (M).

Every concrete ScannerPlugin subclass must satisfy these invariants:
  1. Has a non-empty ``name`` class attribute.
  2. Has a non-empty ``description`` class attribute.
  3. ``name`` contains only alphanumeric characters, underscores, or hyphens
     (no spaces or special chars that could break logging / identifiers).
  4. ``scan()`` returns a list (not None, not a generator).
  5. Each element in that list is a :class:`~src.scanner_plugin.ScanResult`.
  6. ``ScanResult.mac_address`` is a non-empty string.
  7. ``ScanResult.device_type`` is a non-empty string.
  8. ``ScanResult.source`` equals the plugin's ``name``.
  9. ``is_available()`` returns a bool.
"""

import re
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.scanner_plugin import ScannerPlugin, ScanResult

# ---------------------------------------------------------------------------
# Minimal concrete implementations used by the parametrized tests
# ---------------------------------------------------------------------------


class _MinimalPlugin(ScannerPlugin):
    name = "minimal_plugin"
    description = "A minimal plugin for contract testing."

    def scan(self, config: Any) -> list[ScanResult]:
        return []


class _PluginWithResults(ScannerPlugin):
    name = "plugin-with-results"
    description = "Returns one well-formed ScanResult."

    def scan(self, config: Any) -> list[ScanResult]:
        return [
            ScanResult(
                mac_address="aa:bb:cc:dd:ee:ff",
                device_type="wifi",
                source=self.name,
            )
        ]


class _UnavailablePlugin(ScannerPlugin):
    name = "unavailable_plugin"
    description = "Always reports itself as unavailable."

    def scan(self, config: Any) -> list[ScanResult]:  # pragma: no cover
        return []

    def is_available(self) -> bool:
        return False


# All concrete plugin classes to test
_PLUGIN_CLASSES = [_MinimalPlugin, _PluginWithResults, _UnavailablePlugin]


# ---------------------------------------------------------------------------
# Contract parametrized tests
# ---------------------------------------------------------------------------


@pytest.fixture(params=_PLUGIN_CLASSES, ids=lambda cls: cls.__name__)
def plugin_instance(request):
    return request.param()


@pytest.mark.timeout(30)
def test_name_is_nonempty(plugin_instance: ScannerPlugin) -> None:
    """Contract: name must be a non-empty string."""
    assert isinstance(plugin_instance.name, str), "name must be a str"
    assert plugin_instance.name, "name must not be empty"


@pytest.mark.timeout(30)
def test_name_is_valid_identifier_chars(plugin_instance: ScannerPlugin) -> None:
    """Contract: name must contain only alphanumerics, underscores, or hyphens."""
    assert re.fullmatch(r"[a-z0-9_-]+", plugin_instance.name), (
        f"name '{plugin_instance.name}' contains invalid characters"
    )


@pytest.mark.timeout(30)
def test_description_is_nonempty(plugin_instance: ScannerPlugin) -> None:
    """Contract: description must be a non-empty string."""
    assert isinstance(plugin_instance.description, str), "description must be a str"
    assert plugin_instance.description, "description must not be empty"


@pytest.mark.timeout(30)
def test_scan_returns_list(plugin_instance: ScannerPlugin) -> None:
    """Contract: scan() must return a list."""
    result = plugin_instance.scan(MagicMock())
    assert isinstance(result, list), "scan() must return a list"


@pytest.mark.timeout(30)
def test_scan_result_elements_are_scan_results(plugin_instance: ScannerPlugin) -> None:
    """Contract: each element of scan() output must be a ScanResult."""
    result = plugin_instance.scan(MagicMock())
    for item in result:
        assert isinstance(item, ScanResult), f"Expected ScanResult, got {type(item)}"


@pytest.mark.timeout(30)
def test_scan_result_mac_nonempty(plugin_instance: ScannerPlugin) -> None:
    """Contract: ScanResult.mac_address must be non-empty."""
    for item in plugin_instance.scan(MagicMock()):
        assert item.mac_address, "mac_address must not be empty"


@pytest.mark.timeout(30)
def test_scan_result_device_type_nonempty(plugin_instance: ScannerPlugin) -> None:
    """Contract: ScanResult.device_type must be non-empty."""
    for item in plugin_instance.scan(MagicMock()):
        assert item.device_type, "device_type must not be empty"


@pytest.mark.timeout(30)
def test_scan_result_source_matches_plugin_name(plugin_instance: ScannerPlugin) -> None:
    """Contract: ScanResult.source must equal the plugin's name."""
    for item in plugin_instance.scan(MagicMock()):
        assert item.source == plugin_instance.name, (
            f"source '{item.source}' must equal plugin name '{plugin_instance.name}'"
        )


@pytest.mark.timeout(30)
def test_is_available_returns_bool(plugin_instance: ScannerPlugin) -> None:
    """Contract: is_available() must return a bool."""
    result = plugin_instance.is_available()
    assert isinstance(result, bool), "is_available() must return a bool"


# ---------------------------------------------------------------------------
# Additional unit tests for ScanResult dataclass
# ---------------------------------------------------------------------------


class TestScanResult:
    """Unit tests for ScanResult dataclass."""

    @pytest.mark.timeout(30)
    def test_required_fields(self) -> None:
        sr = ScanResult(mac_address="aa:bb:cc:dd:ee:ff", device_type="ble", source="test")
        assert sr.mac_address == "aa:bb:cc:dd:ee:ff"
        assert sr.device_type == "ble"
        assert sr.source == "test"

    @pytest.mark.timeout(30)
    def test_optional_fields_default_to_none(self) -> None:
        sr = ScanResult(mac_address="aa:bb:cc:dd:ee:ff", device_type="ble", source="test")
        assert sr.signal_dbm is None
        assert sr.vendor is None
        assert sr.device_name is None
        assert sr.ip_address is None

    @pytest.mark.timeout(30)
    def test_extra_defaults_to_empty_dict(self) -> None:
        sr = ScanResult(mac_address="aa:bb:cc:dd:ee:ff", device_type="ble", source="test")
        assert sr.extra == {}

    @pytest.mark.timeout(30)
    def test_scan_time_is_utc_aware(self) -> None:
        from datetime import timezone

        sr = ScanResult(mac_address="aa:bb:cc:dd:ee:ff", device_type="ble", source="test")
        assert sr.scan_time.tzinfo is not None
        assert sr.scan_time.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# ScannerPlugin ABC enforcement
# ---------------------------------------------------------------------------


class TestScannerPluginABC:
    """Verify that ScannerPlugin cannot be instantiated without implementing scan()."""

    @pytest.mark.timeout(30)
    def test_cannot_instantiate_abstract_plugin(self) -> None:
        with pytest.raises(TypeError):
            ScannerPlugin()  # type: ignore[abstract]

    @pytest.mark.timeout(30)
    def test_is_available_default_is_true(self) -> None:
        """Default is_available() must return True."""
        plugin = _MinimalPlugin()
        assert plugin.is_available() is True
