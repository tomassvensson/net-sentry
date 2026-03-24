"""Tests for configuration module."""

import os
from unittest.mock import mock_open, patch

import pytest

from src.config import (
    AlertConfig,
    AppConfig,
    ArpConfig,
    DatabaseConfig,
    MonitorModeConfig,
    OuiConfig,
    ScanConfig,
    SnmpConfig,
    _apply_env_overrides,
    _parse_raw_config,
    load_config,
)


class TestScanConfigDefaults:
    """Tests for ScanConfig default values."""

    def test_defaults(self) -> None:
        config = ScanConfig()
        assert config.continuous is False
        assert config.interval_seconds == 60
        assert config.gap_seconds == 300
        assert config.wifi_enabled is True
        assert config.bluetooth_enabled is True
        assert config.arp_enabled is True
        assert config.mdns_enabled is True
        assert config.ssdp_enabled is True
        assert config.netbios_enabled is True
        assert config.snmp_enabled is False
        assert config.monitor_mode_enabled is False


class TestAppConfigDefaults:
    """Tests for AppConfig default values."""

    def test_defaults(self) -> None:
        config = AppConfig()
        assert isinstance(config.scan, ScanConfig)
        assert isinstance(config.arp, ArpConfig)
        assert isinstance(config.snmp, SnmpConfig)
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.alert, AlertConfig)
        assert config.whitelist == []
        assert isinstance(config.oui, OuiConfig)
        assert isinstance(config.monitor_mode, MonitorModeConfig)
        assert config.database.url == "sqlite:///btwifi.db"


class TestParseRawConfig:
    """Tests for parsing raw YAML config dictionaries."""

    def test_empty_dict(self) -> None:
        config = _parse_raw_config({})
        assert config.scan.continuous is False
        assert config.database.url == "sqlite:///btwifi.db"

    def test_scan_section(self) -> None:
        raw = {"scan": {"continuous": True, "interval_seconds": 30}}
        config = _parse_raw_config(raw)
        assert config.scan.continuous is True
        assert config.scan.interval_seconds == 30
        assert config.scan.gap_seconds == 300  # default

    def test_database_section(self) -> None:
        raw = {"database": {"url": "sqlite:///test.db"}}
        config = _parse_raw_config(raw)
        assert config.database.url == "sqlite:///test.db"

    def test_alert_section(self) -> None:
        raw = {"alert": {"enabled": False, "log_file": "/tmp/alerts.log"}}
        config = _parse_raw_config(raw)
        assert config.alert.enabled is False
        assert config.alert.log_file == "/tmp/alerts.log"

    def test_whitelist_section(self) -> None:
        raw = {
            "whitelist": [
                {"mac_address": "AA:BB:CC:DD:EE:FF", "name": "My Phone", "trusted": True},
                {"mac_address": "11:22:33:44:55:66", "name": "Server"},
            ]
        }
        config = _parse_raw_config(raw)
        assert len(config.whitelist) == 2
        assert config.whitelist[0].mac_address == "AA:BB:CC:DD:EE:FF"
        assert config.whitelist[0].name == "My Phone"
        assert config.whitelist[1].name == "Server"

    def test_whitelist_skips_invalid(self) -> None:
        raw = {
            "whitelist": [
                {"name": "No MAC"},
                "not a dict",
                {"mac_address": "AA:BB:CC:DD:EE:FF", "name": "Valid"},
            ]
        }
        config = _parse_raw_config(raw)
        assert len(config.whitelist) == 1
        assert config.whitelist[0].name == "Valid"

    def test_arp_section(self) -> None:
        raw = {"arp": {"resolve_hostnames": False, "timeout_seconds": 5.0}}
        config = _parse_raw_config(raw)
        assert config.arp.resolve_hostnames is False
        assert config.arp.timeout_seconds == pytest.approx(5.0)

    def test_snmp_section(self) -> None:
        raw = {"snmp": {"community": "private", "version": 3}}
        config = _parse_raw_config(raw)
        assert config.snmp.community == "private"
        assert config.snmp.version == 3

    def test_oui_section(self) -> None:
        raw = {"oui": {"auto_update": False, "update_interval_hours": 48}}
        config = _parse_raw_config(raw)
        assert config.oui.auto_update is False
        assert config.oui.update_interval_hours == 48

    def test_monitor_mode_section(self) -> None:
        raw = {"monitor_mode": {"interface": "wlan1", "use_docker": False}}
        config = _parse_raw_config(raw)
        assert config.monitor_mode.interface == "wlan1"
        assert config.monitor_mode.use_docker is False


class TestApplyEnvOverrides:
    """Tests for environment variable overrides."""

    def test_database_url_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///env.db"}):
            result = _apply_env_overrides(config)
        assert result.database.url == "sqlite:///env.db"

    def test_scan_interval_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_SCAN_INTERVAL": "120"}):
            result = _apply_env_overrides(config)
        assert result.scan.interval_seconds == 120

    def test_invalid_scan_interval(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_SCAN_INTERVAL": "not_a_number"}):
            result = _apply_env_overrides(config)
        assert result.scan.interval_seconds == 60  # unchanged

    def test_continuous_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_CONTINUOUS": "true"}):
            result = _apply_env_overrides(config)
        assert result.scan.continuous is True

    def test_gap_seconds_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_GAP_SECONDS": "600"}):
            result = _apply_env_overrides(config)
        assert result.scan.gap_seconds == 600

    def test_invalid_gap_seconds(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_GAP_SECONDS": "bad"}):
            result = _apply_env_overrides(config)
        assert result.scan.gap_seconds == 300


class TestLoadConfig:
    """Tests for full config loading."""

    def test_load_defaults_when_no_file(self) -> None:
        with patch("src.config.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            config = load_config("/nonexistent/config.yaml")
        assert isinstance(config, AppConfig)

    def test_load_from_yaml(self) -> None:
        yaml_content = "scan:\n  continuous: true\n  interval_seconds: 15\n"
        with (
            patch("src.config.Path") as mock_path,
            patch("builtins.open", mock_open(read_data=yaml_content)),
        ):
            mock_path.return_value.exists.return_value = True
            config = load_config("/some/config.yaml")
        assert config.scan.continuous is True
        assert config.scan.interval_seconds == 15

    def test_load_with_bad_yaml(self) -> None:
        with (
            patch("src.config.Path") as mock_path,
            patch("builtins.open", side_effect=OSError("Cannot read")),
        ):
            mock_path.return_value.exists.return_value = True
            config = load_config("/bad/config.yaml")
        assert isinstance(config, AppConfig)  # Should use defaults
