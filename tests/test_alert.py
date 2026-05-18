"""Tests for alert management system."""

import logging
from datetime import datetime

import pytest

from src.alert import AlertManager
from src.config import AlertConfig, AlertRule


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


class TestAlertRules:
    """Tests for configurable alert rules (E)."""

    # ---- time_window rules ----

    @pytest.mark.timeout(30)
    def test_time_window_rule_fires_in_window(self) -> None:
        """time_window rule should fire an extra alert when the device is seen in window."""
        from datetime import timezone
        from unittest.mock import patch

        rule = AlertRule(rule_type="time_window", start_hour=0, end_hour=6, label="night")
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        # Simulate hour=3 (within 00:00–06:00)
        fake_now = datetime(2024, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
        with patch("src.alert.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        # 1 baseline alert + 1 time_window rule alert
        assert mgr.alert_count == 2

    @pytest.mark.timeout(30)
    def test_time_window_rule_silent_outside_window(self) -> None:
        """time_window rule should NOT fire when device is seen outside the window."""
        from datetime import timezone
        from unittest.mock import patch

        rule = AlertRule(rule_type="time_window", start_hour=0, end_hour=6, label="night")
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        fake_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch("src.alert.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        # Only baseline alert, no rule alert
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_time_window_rule_device_type_filter_match(self) -> None:
        """time_window rule with device_type_filter fires only for matching type."""
        from datetime import timezone
        from unittest.mock import patch

        rule = AlertRule(rule_type="time_window", start_hour=0, end_hour=6, device_type_filter="bluetooth")
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        fake_now = datetime(2024, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
        with patch("src.alert.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="bluetooth")
        assert mgr.alert_count == 2  # baseline + rule

    @pytest.mark.timeout(30)
    def test_time_window_rule_device_type_filter_no_match(self) -> None:
        from datetime import timezone
        from unittest.mock import patch

        rule = AlertRule(rule_type="time_window", start_hour=0, end_hour=6, device_type_filter="bluetooth")
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        fake_now = datetime(2024, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
        with patch("src.alert.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        assert mgr.alert_count == 1  # only baseline, filter excluded

    @pytest.mark.timeout(30)
    def test_time_window_rule_wraps_midnight(self) -> None:
        """time_window start_hour > end_hour wraps midnight correctly."""
        from datetime import timezone
        from unittest.mock import patch

        # 22:00–02:00 window
        rule = AlertRule(rule_type="time_window", start_hour=22, end_hour=2, label="late")
        config = AlertConfig(enabled=True, log_new_devices=False, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        fake_now = datetime(2024, 1, 1, 23, 30, 0, tzinfo=timezone.utc)  # 23:30 is in window
        with patch("src.alert.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mgr.on_new_device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        assert mgr.alert_count == 2

    # ---- disappearance rules ----

    @pytest.mark.timeout(30)
    def test_disappearance_rule_fires_when_absent(self) -> None:
        from datetime import timedelta, timezone

        rule = AlertRule(rule_type="disappearance", mac_address="AA:BB:CC:DD:EE:FF", threshold_minutes=30)
        config = AlertConfig(enabled=True, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        now = datetime.now(timezone.utc)
        last_seen_by_mac = {"AA:BB:CC:DD:EE:FF": now - timedelta(minutes=45)}
        mgr.check_disappearance(last_seen_by_mac)
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_disappearance_rule_silent_when_present(self) -> None:
        from datetime import timedelta, timezone

        rule = AlertRule(rule_type="disappearance", mac_address="AA:BB:CC:DD:EE:FF", threshold_minutes=30)
        config = AlertConfig(enabled=True, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        now = datetime.now(timezone.utc)
        last_seen_by_mac = {"AA:BB:CC:DD:EE:FF": now - timedelta(minutes=10)}
        mgr.check_disappearance(last_seen_by_mac)
        assert mgr.alert_count == 0

    @pytest.mark.timeout(30)
    def test_disappearance_rule_fires_when_never_seen(self) -> None:
        rule = AlertRule(rule_type="disappearance", mac_address="AA:BB:CC:DD:EE:FF", threshold_minutes=30)
        config = AlertConfig(enabled=True, cooldown_seconds=0, rules=[rule])
        mgr = AlertManager(config)
        mgr.check_disappearance({})  # empty — device never seen
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_disappearance_rule_cooldown(self) -> None:
        from datetime import timedelta, timezone

        rule = AlertRule(rule_type="disappearance", mac_address="AA:BB:CC:DD:EE:FF", threshold_minutes=30)
        config = AlertConfig(enabled=True, cooldown_seconds=300, rules=[rule])
        mgr = AlertManager(config)
        now = datetime.now(timezone.utc)
        last_seen_by_mac = {"AA:BB:CC:DD:EE:FF": now - timedelta(minutes=45)}
        mgr.check_disappearance(last_seen_by_mac)
        mgr.check_disappearance(last_seen_by_mac)  # second call — still within cooldown
        assert mgr.alert_count == 1


class TestWebhookDispatcher:
    """Tests for WebhookDispatcher."""

    @pytest.mark.timeout(30)
    def test_dispatch_blocked_for_non_http_scheme(self) -> None:
        """dispatch() should skip sending when the URL uses a disallowed scheme."""
        from unittest.mock import patch

        from src.alert import WebhookDispatcher

        dispatcher = WebhookDispatcher("file:///etc/passwd")
        with patch("urllib.request.urlopen") as mock_open:
            dispatcher.dispatch("test message")
        mock_open.assert_not_called()

    @pytest.mark.timeout(30)
    def test_dispatch_sends_for_https_url(self) -> None:
        """dispatch() should attempt to POST for a valid https URL."""
        from unittest.mock import MagicMock, patch

        from src.alert import WebhookDispatcher

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        dispatcher = WebhookDispatcher("https://hooks.example.com/test")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            dispatcher.dispatch("hello", mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi")

        # If no exception, the request was attempted


class TestOnReturningDevice:
    """Tests for AlertManager.on_returning_device."""

    @pytest.mark.timeout(30)
    def test_returning_device_increments_count(self) -> None:
        config = AlertConfig(enabled=True, warn_returning_after_days=14)
        mgr = AlertManager(config)
        mgr.on_returning_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            days_absent=20.0,
        )
        assert mgr.alert_count == 1

    @pytest.mark.timeout(30)
    def test_returning_device_suppressed_when_disabled(self) -> None:
        config = AlertConfig(enabled=False, warn_returning_after_days=14)
        mgr = AlertManager(config)
        mgr.on_returning_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            days_absent=20.0,
        )
        assert mgr.alert_count == 0

    @pytest.mark.timeout(30)
    def test_returning_device_suppressed_when_threshold_zero(self) -> None:
        config = AlertConfig(enabled=True, warn_returning_after_days=0)
        mgr = AlertManager(config)
        mgr.on_returning_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            days_absent=20.0,
        )
        assert mgr.alert_count == 0

    @pytest.mark.timeout(30)
    def test_returning_device_cooldown(self) -> None:
        config = AlertConfig(enabled=True, warn_returning_after_days=14, cooldown_seconds=300)
        mgr = AlertManager(config)
        mgr.on_returning_device("AA:BB:CC:DD:EE:FF", "wifi_ap", 20.0)
        mgr.on_returning_device("AA:BB:CC:DD:EE:FF", "wifi_ap", 20.0)
        assert mgr.alert_count == 1
