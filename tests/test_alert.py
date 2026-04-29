"""Tests for alert management system."""

import logging

import pytest

from src.alert import AlertManager
from src.config import AlertConfig


class TestAlertManager:
    """Tests for AlertManager."""

    @pytest.mark.timeout(30)
    def test_alert_disabled(self) -> None:
        config = AlertConfig(enabled=False)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
        )
        assert mgr.alert_count == 0

    @pytest.mark.timeout(30)
    def test_alert_enabled_increments_count(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=False)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            vendor="TestVendor",
            device_name="TestDevice",
        )
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_alert_whitelisted_device(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            vendor="Known",
            device_name="MyServer",
            is_whitelisted=True,
        )
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_alert_unknown_device(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="bluetooth",
            is_whitelisted=False,
        )
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_multiple_alerts(self) -> None:
        config = AlertConfig(enabled=True)
        mgr = AlertManager(config)
        for i in range(5):
            mgr.on_new_device(
                mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
                device_type="wifi_ap",
            )
        assert mgr.alert_count == 5

    @pytest.mark.timeout(30)
    def test_alert_with_log_file(self, tmp_path) -> None:
        log_file = str(tmp_path / "alerts.log")
        config = AlertConfig(enabled=True, log_file=log_file, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            vendor="Test",
            device_name="TestDev",
        )
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_alert_log_file_failure(self, tmp_path) -> None:
        """Test that AlertManager handles log file creation failure gracefully."""
        config = AlertConfig(enabled=True, log_file="/nonexistent/dir/alerts.log")
        # Should not raise — just logs a warning
        mgr = AlertManager(config)
        assert mgr.alert_count == 0

    @pytest.mark.timeout(30)
    def test_no_vendor_no_name(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
        )
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_alert_logs_redact_device_identifiers(self, caplog, tmp_path) -> None:
        log_file = tmp_path / "alerts.log"
        config = AlertConfig(enabled=True, log_file=str(log_file), log_new_devices=True)
        mgr = AlertManager(config)

        caplog.set_level(logging.INFO)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            vendor="Acme Corp",
            device_name="Office Sensor",
            is_whitelisted=False,
        )

        for handler in logging.getLogger("net_sentry.alerts").handlers:
            handler.flush()

        assert "AA:BB:CC:DD:EE:FF" not in caplog.text
        assert "Office Sensor" not in caplog.text
        assert "Acme Corp" not in caplog.text

        alert_log = log_file.read_text(encoding="utf-8")
        assert "AA:BB:CC:DD:EE:FF" not in alert_log
        assert "Office Sensor" not in alert_log
        assert "Acme Corp" not in alert_log

    @pytest.mark.timeout(30)
    def test_cooldown_suppresses_repeated_alerts(self) -> None:
        """The same MAC should not trigger a second alert within the cooldown window."""
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=300)
        mgr = AlertManager(config)
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        assert mgr.alert_count == 1, "Duplicate alert within cooldown window should be suppressed"

    @pytest.mark.timeout(30)
    def test_cooldown_zero_allows_every_alert(self) -> None:
        """With cooldown_seconds=0 every call must fire an alert."""
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=0)
        mgr = AlertManager(config)
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        assert mgr.alert_count == 2

    @pytest.mark.timeout(30)
    def test_cooldown_different_macs_are_independent(self) -> None:
        """Cooldown is per-MAC; different MACs should each get their own alert."""
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=300)
        mgr = AlertManager(config)
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:01", device_type="wifi_ap")
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:02", device_type="wifi_ap")
        mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:01", device_type="wifi_ap")  # duplicate
        assert mgr.alert_count == 2
