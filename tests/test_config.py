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
    validate_config,
)


class TestScanConfigDefaults:
    """Tests for ScanConfig default values."""

    @pytest.mark.timeout(30)
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

    @pytest.mark.timeout(30)
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
        assert config.database.url == "sqlite:///net-sentry.db"
        assert config.snmp.timeout_seconds == pytest.approx(2.0)
        assert config.snmp.retries == 1
        assert config.snmp.max_hosts == 254
        assert config.snmp.subnet == ""
        assert config.api.proxy_headers is False
        assert config.api.forwarded_allow_ips == "127.0.0.1"


class TestParseRawConfig:
    """Tests for parsing raw YAML config dictionaries."""

    @pytest.mark.timeout(30)
    def test_empty_dict(self) -> None:
        config = _parse_raw_config({})
        assert config.scan.continuous is False
        assert config.database.url == "sqlite:///net-sentry.db"

    @pytest.mark.timeout(30)
    def test_scan_section(self) -> None:
        raw = {"scan": {"continuous": True, "interval_seconds": 30}}
        config = _parse_raw_config(raw)
        assert config.scan.continuous is True
        assert config.scan.interval_seconds == 30
        assert config.scan.gap_seconds == 300  # default

    @pytest.mark.timeout(30)
    def test_database_section(self) -> None:
        raw = {"database": {"url": "sqlite:///test.db"}}
        config = _parse_raw_config(raw)
        assert config.database.url == "sqlite:///test.db"

    @pytest.mark.timeout(30)
    def test_alert_section(self) -> None:
        raw = {"alert": {"enabled": False, "log_file": "/tmp/alerts.log"}}
        config = _parse_raw_config(raw)
        assert config.alert.enabled is False
        assert config.alert.log_file == "/tmp/alerts.log"

    @pytest.mark.timeout(30)
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

    @pytest.mark.timeout(30)
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

    @pytest.mark.timeout(30)
    def test_arp_section(self) -> None:
        raw = {"arp": {"resolve_hostnames": False, "timeout_seconds": 5.0}}
        config = _parse_raw_config(raw)
        assert config.arp.resolve_hostnames is False
        assert config.arp.timeout_seconds == pytest.approx(5.0)

    @pytest.mark.timeout(30)
    def test_snmp_section(self) -> None:
        raw = {"snmp": {"community": "private", "version": 3}}
        config = _parse_raw_config(raw)
        assert config.snmp.community == "private"
        assert config.snmp.version == 3

    @pytest.mark.timeout(30)
    def test_snmp_section_with_extended_fields(self) -> None:
        raw = {
            "snmp": {
                "enabled": True,
                "community": "private",
                "version": 2,
                "port": 1161,
                "timeout": 5,
                "retries": 3,
                "max_hosts": 32,
                "subnet": "192.168.1.0/24",
                "target_hosts": ["192.168.1.1"],
            }
        }
        config = _parse_raw_config(raw)
        assert config.snmp.enabled is True
        assert config.snmp.community == "private"
        assert config.snmp.port == 1161
        assert config.snmp.timeout_seconds == pytest.approx(5)
        assert config.snmp.retries == 3
        assert config.snmp.max_hosts == 32
        assert config.snmp.subnet == "192.168.1.0/24"
        assert config.snmp.target_hosts == ["192.168.1.1"]

    @pytest.mark.timeout(30)
    def test_oui_section(self) -> None:
        raw = {"oui": {"auto_update": False, "update_interval_hours": 48}}
        config = _parse_raw_config(raw)
        assert config.oui.auto_update is False
        assert config.oui.update_interval_hours == 48

    @pytest.mark.timeout(30)
    def test_monitor_mode_section(self) -> None:
        raw = {"monitor_mode": {"interface": "wlan1", "use_docker": False}}
        config = _parse_raw_config(raw)
        assert config.monitor_mode.interface == "wlan1"
        assert config.monitor_mode.use_docker is False


class TestApplyEnvOverrides:
    """Tests for environment variable overrides."""

    @pytest.mark.timeout(30)
    def test_database_url_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///env.db"}):
            result = _apply_env_overrides(config)
        assert result.database.url == "sqlite:///env.db"

    @pytest.mark.timeout(30)
    def test_scan_interval_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_SCAN_INTERVAL": "120"}):
            result = _apply_env_overrides(config)
        assert result.scan.interval_seconds == 120

    @pytest.mark.timeout(30)
    def test_invalid_scan_interval(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_SCAN_INTERVAL": "not_a_number"}):
            result = _apply_env_overrides(config)
        assert result.scan.interval_seconds == 60  # unchanged

    @pytest.mark.timeout(30)
    def test_continuous_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_CONTINUOUS": "true"}):
            result = _apply_env_overrides(config)
        assert result.scan.continuous is True

    @pytest.mark.timeout(30)
    def test_scanner_env_overrides(self) -> None:
        config = AppConfig()
        with patch.dict(
            os.environ,
            {
                "NET_SENTRY_SCAN_BLUETOOTH": "false",
                "NET_SENTRY_SCAN_BLE": "false",
            },
        ):
            result = _apply_env_overrides(config)
        assert result.scan.bluetooth_enabled is False
        assert result.scan.ble_enabled is False

    @pytest.mark.timeout(30)
    def test_gap_seconds_override(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_GAP_SECONDS": "600"}):
            result = _apply_env_overrides(config)
        assert result.scan.gap_seconds == 600

    @pytest.mark.timeout(30)
    def test_file_backed_auth_secrets(self, tmp_path) -> None:
        jwt_file = tmp_path / "jwt-secret"
        users_file = tmp_path / "api-users.json"
        jwt_file.write_text("x" * 48 + "\n", encoding="utf-8")
        users_file.write_text('{"admin":"$2b$12$' + "x" * 53 + '"}', encoding="utf-8")

        config = AppConfig()
        with patch.dict(
            os.environ,
            {
                "NET_SENTRY_JWT_SECRET_FILE": str(jwt_file),
                "NET_SENTRY_API_USERS_JSON_FILE": str(users_file),
            },
            clear=True,
        ):
            result = _apply_env_overrides(config)

        assert result.api.jwt_secret == "x" * 48
        assert result.api.api_users == {"admin": "$2b$12$" + "x" * 53}

    @pytest.mark.timeout(30)
    def test_direct_and_file_secret_are_mutually_exclusive(self, tmp_path) -> None:
        jwt_file = tmp_path / "jwt-secret"
        jwt_file.write_text("x" * 48, encoding="utf-8")

        with (
            patch.dict(
                os.environ,
                {
                    "NET_SENTRY_JWT_SECRET": "y" * 48,
                    "NET_SENTRY_JWT_SECRET_FILE": str(jwt_file),
                },
                clear=True,
            ),
            pytest.raises(ValueError, match="Set only one"),
        ):
            _apply_env_overrides(AppConfig())

    @pytest.mark.timeout(30)
    def test_proxy_header_env_overrides(self) -> None:
        config = AppConfig()
        with patch.dict(
            os.environ,
            {
                "NET_SENTRY_PROXY_HEADERS": "true",
                "NET_SENTRY_FORWARDED_ALLOW_IPS": "172.20.0.0/16",
            },
            clear=True,
        ):
            result = _apply_env_overrides(config)

        assert result.api.proxy_headers is True
        assert result.api.forwarded_allow_ips == "172.20.0.0/16"

    @pytest.mark.timeout(30)
    def test_invalid_gap_seconds(self) -> None:
        config = AppConfig()
        with patch.dict(os.environ, {"BTWIFI_GAP_SECONDS": "bad"}):
            result = _apply_env_overrides(config)
        assert result.scan.gap_seconds == 300


class TestLoadConfig:
    """Tests for full config loading."""

    @pytest.mark.timeout(30)
    def test_load_defaults_when_no_file(self) -> None:
        with patch("src.config.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            config = load_config("/nonexistent/config.yaml")
        assert isinstance(config, AppConfig)

    @pytest.mark.timeout(30)
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

    @pytest.mark.timeout(30)
    def test_load_with_bad_yaml(self) -> None:
        with (
            patch("src.config.Path") as mock_path,
            patch("builtins.open", side_effect=OSError("Cannot read")),
        ):
            mock_path.return_value.exists.return_value = True
            config = load_config("/bad/config.yaml")
        assert isinstance(config, AppConfig)  # Should use defaults


class TestValidateConfig:
    """Tests for fail-fast security and resource-bound validation."""

    def test_auth_requires_users(self) -> None:
        config = AppConfig()
        config.api.auth_enabled = True
        config.api.jwt_secret = "x" * 32
        with pytest.raises(ValueError, match="at least one"):
            validate_config(config)

    def test_auth_rejects_short_secret(self) -> None:
        config = AppConfig()
        config.api.auth_enabled = True
        config.api.jwt_secret = "too-short"
        config.api.api_users = {"admin": "$2b$12$" + "x" * 53}
        with pytest.raises(ValueError, match="at least 32 bytes"):
            validate_config(config)

    def test_auth_rejects_wildcard_cors(self) -> None:
        config = AppConfig()
        config.api.auth_enabled = True
        config.api.jwt_secret = "x" * 32
        config.api.api_users = {"admin": "$2b$12$" + "x" * 53}
        config.api.cors_origins = ["*"]
        with pytest.raises(ValueError, match="Wildcard CORS"):
            validate_config(config)

    def test_auth_rejects_wildcard_allowed_hosts(self) -> None:
        config = AppConfig()
        config.api.auth_enabled = True
        config.api.jwt_secret = "x" * 32
        config.api.api_users = {"admin": "$2b$12$" + "x" * 53}
        config.api.allowed_hosts = ["*"]
        with pytest.raises(ValueError, match="Wildcard allowed_hosts"):
            validate_config(config)

    def test_outbound_urls_must_be_http(self) -> None:
        config = AppConfig()
        config.alert.webhook_url = "file:///etc/passwd"
        with pytest.raises(ValueError, match=r"HTTP\(S\)"):
            validate_config(config)

    def test_ping_target_limit_is_bounded(self) -> None:
        config = AppConfig()
        config.ping_sweep.max_targets = 100_000
        with pytest.raises(ValueError, match="max_targets"):
            validate_config(config)

    def test_wildcard_forwarded_peers_require_hardened_auth(self) -> None:
        config = AppConfig()
        config.api.proxy_headers = True
        config.api.forwarded_allow_ips = "*"
        with pytest.raises(ValueError, match="authentication and secure cookies"):
            validate_config(config)

    def test_forwarded_peers_must_be_ip_addresses_or_networks(self) -> None:
        config = AppConfig()
        config.api.proxy_headers = True
        config.api.forwarded_allow_ips = "caddy"
        with pytest.raises(ValueError, match="IP address or CIDR"):
            validate_config(config)
