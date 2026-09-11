"""Tests for Prometheus metrics module."""

import pytest


class TestMetricDefinitions:
    """Tests for metric objects and labels."""

    @pytest.mark.timeout(30)
    def test_scan_total_exists(self) -> None:
        from src.metrics import SCAN_TOTAL

        # Counter should be callable
        before = SCAN_TOTAL._value.get()
        SCAN_TOTAL.inc()
        after = SCAN_TOTAL._value.get()
        assert after == pytest.approx(before + 1)

    @pytest.mark.timeout(30)
    def test_scan_duration_histogram(self) -> None:
        from src.metrics import SCAN_DURATION

        SCAN_DURATION.observe(2.5)
        # Should not raise

    @pytest.mark.timeout(30)
    def test_device_gauges(self) -> None:
        from src.metrics import DEVICES_CURRENTLY_VISIBLE, DEVICES_TOTAL

        DEVICES_TOTAL.labels(device_type="wifi_ap").set(5)
        DEVICES_CURRENTLY_VISIBLE.labels(device_type="wifi_ap").set(3)
        assert DEVICES_TOTAL.labels(device_type="wifi_ap")._value.get() == pytest.approx(5.0)
        assert DEVICES_CURRENTLY_VISIBLE.labels(device_type="wifi_ap")._value.get() == pytest.approx(3.0)

    @pytest.mark.timeout(30)
    def test_alert_counter(self) -> None:
        from src.metrics import ALERTS_TOTAL

        ALERTS_TOTAL.labels(severity="warning").inc()
        # Should not raise

    @pytest.mark.timeout(30)
    def test_mqtt_metrics(self) -> None:
        from src.metrics import MQTT_ERRORS, MQTT_MESSAGES_SENT

        MQTT_MESSAGES_SENT.inc()
        MQTT_ERRORS.inc()
        # Should not raise

    @pytest.mark.timeout(30)
    def test_scan_error_counter(self) -> None:
        from src.metrics import SCAN_ERRORS

        SCAN_ERRORS.labels(scanner_type="wifi").inc()

    @pytest.mark.timeout(30)
    def test_new_devices_counter(self) -> None:
        from src.metrics import NEW_DEVICES_TOTAL

        NEW_DEVICES_TOTAL.labels(device_type="bluetooth").inc()

    @pytest.mark.timeout(30)
    def test_active_windows_gauge(self) -> None:
        from src.metrics import ACTIVE_WINDOWS

        ACTIVE_WINDOWS.set(10)
        assert ACTIVE_WINDOWS._value.get() == pytest.approx(10.0)

    @pytest.mark.timeout(30)
    def test_app_info(self) -> None:
        from src.metrics import APP_INFO

        # Info metric should exist
        assert APP_INFO is not None


class TestRecordScanResults:
    """Tests for the record_scan_results helper."""

    @pytest.mark.timeout(30)
    def test_sets_gauges(self) -> None:
        from src.metrics import (
            ARP_HOSTS_FOUND,
            BLUETOOTH_DEVICES_FOUND,
            WIFI_NETWORKS_FOUND,
            record_scan_results,
        )

        record_scan_results(wifi_count=5, bluetooth_count=3, arp_count=10)
        assert WIFI_NETWORKS_FOUND._value.get() == pytest.approx(5.0)
        assert BLUETOOTH_DEVICES_FOUND._value.get() == pytest.approx(3.0)
        assert ARP_HOSTS_FOUND._value.get() == pytest.approx(10.0)

    @pytest.mark.timeout(30)
    def test_defaults_to_zero(self) -> None:
        from src.metrics import (
            ARP_HOSTS_FOUND,
            BLUETOOTH_DEVICES_FOUND,
            WIFI_NETWORKS_FOUND,
            record_scan_results,
        )

        record_scan_results()
        assert WIFI_NETWORKS_FOUND._value.get() == pytest.approx(0.0)
        assert BLUETOOTH_DEVICES_FOUND._value.get() == pytest.approx(0.0)
        assert ARP_HOSTS_FOUND._value.get() == pytest.approx(0.0)
