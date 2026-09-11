"""Tests for whitelist management."""

import pytest

from src.config import AppConfig, WhitelistEntry
from src.whitelist import WhitelistManager


def _make_config(*entries: WhitelistEntry) -> AppConfig:
    """Create an AppConfig with given whitelist entries."""
    config = AppConfig()
    config.whitelist = list(entries)
    return config


class TestWhitelistManager:
    """Tests for WhitelistManager."""

    @pytest.mark.timeout(30)
    def test_empty_whitelist(self) -> None:
        wl = WhitelistManager(_make_config())
        assert len(wl) == 0
        assert wl.entries == []

    @pytest.mark.timeout(30)
    def test_load_entries(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="Phone", trusted=True),
            WhitelistEntry(mac_address="11:22:33:44:55:66", name="Server"),
        )
        wl = WhitelistManager(config)
        assert len(wl) == 2

    @pytest.mark.timeout(30)
    def test_is_known(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="Phone"),
        )
        wl = WhitelistManager(config)
        assert wl.is_known("AA:BB:CC:DD:EE:FF") is True
        assert wl.is_known("aa:bb:cc:dd:ee:ff") is True
        assert wl.is_known("11:22:33:44:55:66") is False

    @pytest.mark.timeout(30)
    def test_is_known_invalid_mac(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.is_known("not-a-mac") is False

    @pytest.mark.timeout(30)
    def test_is_trusted(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", trusted=True),
            WhitelistEntry(mac_address="11:22:33:44:55:66", trusted=False),
        )
        wl = WhitelistManager(config)
        assert wl.is_trusted("AA:BB:CC:DD:EE:FF") is True
        assert wl.is_trusted("11:22:33:44:55:66") is False
        assert wl.is_trusted("99:99:99:99:99:99") is False

    @pytest.mark.timeout(30)
    def test_is_trusted_invalid_mac(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.is_trusted("garbage") is False

    @pytest.mark.timeout(30)
    def test_get_entry(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="Phone", category="mobile"),
        )
        wl = WhitelistManager(config)
        entry = wl.get_entry("AA:BB:CC:DD:EE:FF")
        assert entry is not None
        assert entry.name == "Phone"
        assert entry.category == "mobile"

    @pytest.mark.timeout(30)
    def test_get_entry_not_found(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.get_entry("AA:BB:CC:DD:EE:FF") is None

    @pytest.mark.timeout(30)
    def test_get_entry_invalid_mac(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.get_entry("invalid") is None

    @pytest.mark.timeout(30)
    def test_get_custom_name(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="My Phone"),
        )
        wl = WhitelistManager(config)
        assert wl.get_custom_name("AA:BB:CC:DD:EE:FF") == "My Phone"

    @pytest.mark.timeout(30)
    def test_get_custom_name_none_when_no_name(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name=""),
        )
        wl = WhitelistManager(config)
        assert wl.get_custom_name("AA:BB:CC:DD:EE:FF") is None

    @pytest.mark.timeout(30)
    def test_get_custom_name_not_found(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.get_custom_name("AA:BB:CC:DD:EE:FF") is None

    @pytest.mark.timeout(30)
    def test_add_device(self) -> None:
        wl = WhitelistManager(_make_config())
        wl.add_device("AA:BB:CC:DD:EE:FF", name="New Device", category="iot")
        assert wl.is_known("AA:BB:CC:DD:EE:FF") is True
        assert wl.get_custom_name("AA:BB:CC:DD:EE:FF") == "New Device"

    @pytest.mark.timeout(30)
    def test_remove_device(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="Phone"),
        )
        wl = WhitelistManager(config)
        assert wl.remove_device("AA:BB:CC:DD:EE:FF") is True
        assert wl.is_known("AA:BB:CC:DD:EE:FF") is False

    @pytest.mark.timeout(30)
    def test_remove_device_not_found(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.remove_device("AA:BB:CC:DD:EE:FF") is False

    @pytest.mark.timeout(30)
    def test_remove_device_invalid_mac(self) -> None:
        wl = WhitelistManager(_make_config())
        assert wl.remove_device("invalid") is False

    @pytest.mark.timeout(30)
    def test_invalid_mac_in_config_skipped(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="not-valid", name="Bad"),
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="Good"),
        )
        wl = WhitelistManager(config)
        assert len(wl) == 1
        assert wl.is_known("AA:BB:CC:DD:EE:FF") is True

    @pytest.mark.timeout(30)
    def test_entries_property(self) -> None:
        config = _make_config(
            WhitelistEntry(mac_address="AA:BB:CC:DD:EE:FF", name="A"),
            WhitelistEntry(mac_address="11:22:33:44:55:66", name="B"),
        )
        wl = WhitelistManager(config)
        entries = wl.entries
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert names == {"A", "B"}

    @pytest.mark.timeout(30)
    def test_whitelist_logs_redact_mac_addresses(self, caplog) -> None:
        with caplog.at_level("INFO"):
            wl = WhitelistManager(_make_config(WhitelistEntry(mac_address="not-valid", name="Bad")))
            wl.add_device("AA:BB:CC:DD:EE:FF", name="New Device")
            assert wl.remove_device("AA:BB:CC:DD:EE:FF") is True

        assert "not-valid" not in caplog.text
        assert "AA:BB:CC:DD:EE:FF" not in caplog.text
        assert "New Device" not in caplog.text
