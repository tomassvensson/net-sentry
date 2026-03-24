"""Prometheus metrics for BtWiFi device scanner."""

import logging

from prometheus_client import Counter, Gauge, Histogram, Info

logger = logging.getLogger(__name__)

# Application info
APP_INFO = Info("btwifi", "BtWiFi Device Visibility Tracker")
APP_INFO.info({"version": "0.1.0"})

# Scan metrics
SCAN_TOTAL = Counter("btwifi_scans_total", "Total number of scan cycles completed")
SCAN_DURATION = Histogram(
    "btwifi_scan_duration_seconds",
    "Duration of a scan cycle in seconds",
    buckets=(1, 5, 10, 30, 60, 120, 300),
)
SCAN_ERRORS = Counter("btwifi_scan_errors_total", "Total scan errors", ["scanner_type"])

# Device metrics
DEVICES_TOTAL = Gauge("btwifi_devices_total", "Total known devices", ["device_type"])
DEVICES_CURRENTLY_VISIBLE = Gauge(
    "btwifi_devices_visible",
    "Devices currently visible (seen in last scan)",
    ["device_type"],
)
NEW_DEVICES_TOTAL = Counter("btwifi_new_devices_total", "Total new devices discovered", ["device_type"])

# Visibility window metrics
ACTIVE_WINDOWS = Gauge("btwifi_active_visibility_windows", "Number of active visibility windows")

# Alert metrics
ALERTS_TOTAL = Counter("btwifi_alerts_total", "Total alerts raised", ["severity"])

# MQTT metrics
MQTT_MESSAGES_SENT = Counter("btwifi_mqtt_messages_sent_total", "Total MQTT messages sent")
MQTT_ERRORS = Counter("btwifi_mqtt_errors_total", "Total MQTT publish errors")

# Scanner-specific metrics
WIFI_NETWORKS_FOUND = Gauge("btwifi_wifi_networks_found", "WiFi networks found in last scan")
BLUETOOTH_DEVICES_FOUND = Gauge("btwifi_bluetooth_devices_found", "Bluetooth devices found in last scan")
ARP_HOSTS_FOUND = Gauge("btwifi_arp_hosts_found", "ARP hosts found in last scan")


def record_scan_results(
    wifi_count: int = 0,
    bluetooth_count: int = 0,
    arp_count: int = 0,
) -> None:
    """Record scan result counts in Prometheus metrics.

    Args:
        wifi_count: Number of WiFi networks found.
        bluetooth_count: Number of Bluetooth devices found.
        arp_count: Number of ARP hosts found.
    """
    WIFI_NETWORKS_FOUND.set(wifi_count)
    BLUETOOTH_DEVICES_FOUND.set(bluetooth_count)
    ARP_HOSTS_FOUND.set(arp_count)
