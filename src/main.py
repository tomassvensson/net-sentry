"""Net Sentry — Main entry point for the device visibility tracker.

Scans for WiFi networks, Bluetooth devices, and local network devices,
then stores results in the database and displays a human-readable table.
"""

import csv
import json
import logging
import platform
import re
import signal
import sys
import time
from collections.abc import Callable
from datetime import datetime
from typing import TypeVar

from sqlalchemy import Engine
from sqlalchemy.orm import Session as DbSession
from tabulate import tabulate

from src.alert import AlertManager
from src.bluetooth_scanner import BluetoothDevice, scan_ble_devices, scan_bluetooth_devices
from src.categorizer import categorize_device, get_category_label
from src.config import AppConfig, load_config
from src.database import get_session, init_database
from src.device_tracker import (
    get_all_devices_with_latest_window,
    track_bluetooth_scan,
    track_wifi_scan,
    update_visibility,
)
from src.home_assistant import HaDevice, build_ha_lookup, enrich_from_ha, fetch_ha_devices
from src.ipv6_scanner import Ipv6Neighbor, scan_ipv6_neighbors
from src.mdns_scanner import MdnsDevice
from src.models import Device, VisibilityWindow
from src.network_discovery import NetworkDevice, ping_sweep, scan_arp_table
from src.oui_lookup import is_randomized_mac
from src.port_scanner import decode_open_ports, encode_open_ports, scan_host_ports
from src.ssdp_scanner import SsdpDevice
from src.whitelist import WhitelistManager
from src.wifi_scanner import WifiNetwork, scan_wifi_networks

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# Flag for graceful shutdown in continuous mode
_shutdown_requested = False


def _handle_shutdown(signum: int, frame: object) -> None:
    """Handle shutdown signals for graceful exit."""
    global _shutdown_requested  # noqa: PLW0603
    _shutdown_requested = True
    logger.info("Shutdown requested (signal %d). Finishing current scan...", signum)


def _friendly_vendor(vendor: str | None, mac: str) -> str:
    """Return a human-friendly vendor name, shortening common verbose names.

    Instead of using a hardcoded lookup table, this uses regex-based
    shortening rules to normalize verbose vendor strings automatically.

    Args:
        vendor: Raw vendor string from OUI database.
        mac: MAC address of the device.

    Returns:
        Friendly vendor string for display.
    """
    if vendor:
        return _shorten_vendor_name(vendor)

    try:
        if is_randomized_mac(mac):
            return "(Randomized MAC)"
    except ValueError:
        pass

    return "(Unknown vendor)"


# Regex rules for shortening verbose vendor names automatically
_VENDOR_SHORTEN_RULES: list[tuple[str, str]] = [
    # Remove common suffixes
    (
        r"\s*,?\s*(?:Inc\.?|Incorporated|Corp(?:oration)?\.?|Co\.\s*,?\s*Ltd\.?"
        r"|Ltd\.?|LLC|GmbH|SA|AB|AG|SE|BV|NV|PLC|SRL|SpA|Pty|OY|AS|Aps)\s*$",
        "",
    ),
    # Remove "Technologies" / "Technology" at end
    (r"\s+Technolog(?:y|ies)\s*$", ""),
    # Remove " Electronics" at end if preceded by brand
    (r"\s+Electronics?\s*$", ""),
    # Remove trailing parenthetical details
    (r"\s*\(.*\)\s*$", ""),
    # Strip trailing commas and whitespace
    (r",\s*$", ""),
]


def _shorten_vendor_name(vendor: str) -> str:
    """Shorten a verbose vendor name to a concise brand name.

    Applies regex rules to strip common legal suffixes and verbose
    qualifiers from vendor strings returned by the OUI database.

    Args:
        vendor: Raw vendor name.

    Returns:
        Shortened/cleaned vendor name.
    """
    result = vendor
    # Apply two passes to handle nested patterns
    for _ in range(2):
        for pattern, replacement in _VENDOR_SHORTEN_RULES:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    return result.strip() or vendor


def _best_name(
    device: Device,
    whitelist: WhitelistManager | None = None,
) -> str:
    """Get the best human-readable name for a device.

    Priority: whitelist name > device_name > hostname > ssid > vendor > mac.

    Args:
        device: Device record.
        whitelist: Optional whitelist manager for custom names.

    Returns:
        Best available name.
    """
    # Check whitelist for custom name
    if whitelist:
        custom = whitelist.get_custom_name(device.mac_address)
        if custom:
            return custom

    if device.device_name:
        return device.device_name
    if device.hostname:
        return device.hostname
    if device.ssid and device.ssid != "<Hidden>":
        return device.ssid
    if device.vendor:
        return f"{_shorten_vendor_name(device.vendor)} device"
    return device.mac_address


def _format_signal(signal_dbm: float | None) -> str:
    """Format signal strength for display.

    Args:
        signal_dbm: Signal in dBm, or None.

    Returns:
        Human-readable signal string.
    """
    if signal_dbm is None:
        return "N/A"
    if signal_dbm >= -50:
        quality = "Excellent"
    elif signal_dbm >= -60:
        quality = "Good"
    elif signal_dbm >= -70:
        quality = "Fair"
    elif signal_dbm >= -80:
        quality = "Weak"
    else:
        quality = "Very Weak"
    return f"{signal_dbm:.0f} dBm ({quality})"


def _format_time(dt: datetime | None) -> str:
    """Format a datetime for display.

    Args:
        dt: Datetime to format.

    Returns:
        Formatted string.
    """
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def run_scan(config: AppConfig | None = None, rescan_ports: bool = False) -> None:
    """Run a complete scan cycle: WiFi, Bluetooth, ARP, mDNS, SSDP.

    When continuous mode is enabled, repeats scans at the configured
    interval until interrupted.

    Args:
        config: Application configuration. If None, loads from file/defaults.
        rescan_ports: Force port re-scan even if cached data exists.
    """
    if config is None:
        config = load_config()

    logger.info("=" * 60)
    logger.info("Net Sentry Device Visibility Tracker \u2014 Starting scan")
    logger.info("=" * 60)

    engine = init_database(config.database.url)

    whitelist = WhitelistManager(config)
    alert_mgr = AlertManager(config.alert)

    # Initialize MQTT if enabled
    mqtt_pub = None
    if config.mqtt.enabled:
        from src.mqtt_publisher import MqttPublisher

        mqtt_pub = MqttPublisher(
            broker_host=config.mqtt.broker_host,
            broker_port=config.mqtt.broker_port,
            topic_prefix=config.mqtt.topic_prefix,
            username=config.mqtt.username,
            password=config.mqtt.password,
            client_id=config.mqtt.client_id,
        )
        mqtt_pub.connect()

    if config.scan.continuous:
        logger.info(
            "Continuous mode enabled. Scan interval: %ds. Press Ctrl+C to stop.",
            config.scan.interval_seconds,
        )
        signal.signal(signal.SIGINT, _handle_shutdown)
        signal.signal(signal.SIGTERM, _handle_shutdown)

        scan_number = 0
        while not _shutdown_requested:
            scan_number += 1
            logger.info("--- Scan cycle #%d ---", scan_number)
            _run_single_scan(engine, config, whitelist, alert_mgr, mqtt_pub, rescan_ports=rescan_ports)
            # After the first cycle, only rescan ports if explicitly requested
            rescan_ports = False

            if _shutdown_requested:
                break

            logger.info(
                "Next scan in %d seconds...",
                config.scan.interval_seconds,
            )
            # Sleep in small increments to allow interruption
            for _ in range(config.scan.interval_seconds * 10):
                if _shutdown_requested:
                    break
                time.sleep(0.1)

        logger.info("Continuous scanning stopped after %d cycles.", scan_number)
    else:
        _run_single_scan(engine, config, whitelist, alert_mgr, mqtt_pub, rescan_ports=rescan_ports)

    # Cleanup MQTT
    if mqtt_pub is not None:
        mqtt_pub.disconnect()


def _run_single_scan(
    engine: Engine,
    config: AppConfig,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    mqtt_publisher: object | None = None,
    rescan_ports: bool = False,
) -> None:
    """Execute one scan cycle across all enabled scanners.

    Args:
        engine: SQLAlchemy engine.
        config: Application configuration.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        mqtt_publisher: Optional MQTT publisher.
        rescan_ports: When True, force port re-scan even if cached data exists.
    """
    scan_start = time.time()
    scan_data = _execute_all_scanners(config)
    gap = config.scan.gap_seconds

    # Fetch Home Assistant device names once per cycle (not per device)
    ha_lookup: dict[str, HaDevice] = {}
    if config.home_assistant.enabled and config.home_assistant.url:
        ha_devices = fetch_ha_devices(
            ha_url=config.home_assistant.url,
            token=config.home_assistant.token,
            timeout=config.home_assistant.timeout_seconds,
        )
        ha_lookup = build_ha_lookup(ha_devices)
        logger.info("Home Assistant: enriched lookup with %d entities.", len(ha_lookup))

    with get_session(engine) as session:
        wifi_results, bt_results = _store_scan_results(
            session, scan_data, whitelist, alert_mgr, gap, config, ha_lookup, rescan_ports
        )
        _categorize_all_devices(session, whitelist)
        _alert_new_tracked_devices(wifi_results + bt_results, whitelist, alert_mgr)
        session.flush()
        _display_results(session, whitelist)

    scan_duration = time.time() - scan_start

    # Record metrics
    if config.metrics.enabled:
        from src.metrics import SCAN_DURATION, SCAN_TOTAL, record_scan_results

        SCAN_TOTAL.inc()
        SCAN_DURATION.observe(scan_duration)
        record_scan_results(
            wifi_count=len(scan_data.wifi_networks),
            bluetooth_count=len(scan_data.bt_devices),
            arp_count=len(scan_data.arp_devices),
        )

    # Publish to MQTT
    if mqtt_publisher is not None:
        from src.mqtt_publisher import MqttPublisher

        if isinstance(mqtt_publisher, MqttPublisher) and mqtt_publisher.is_connected:
            mqtt_publisher.publish_scan_summary(
                wifi_count=len(scan_data.wifi_networks),
                bluetooth_count=len(scan_data.bt_devices),
                arp_count=len(scan_data.arp_devices),
            )


class _ScanData:
    """Container for results from all scanner types."""

    __slots__ = (
        "wifi_networks",
        "bt_devices",
        "arp_devices",
        "ping_sweep_devices",
        "mdns_devices",
        "ssdp_devices",
        "netbios_names",
        "ipv6_neighbors",
        "monitor_devices",
    )

    def __init__(self) -> None:
        self.wifi_networks: list[WifiNetwork] = []
        self.bt_devices: list[BluetoothDevice] = []
        self.arp_devices: list[NetworkDevice] = []
        self.ping_sweep_devices: list[NetworkDevice] = []
        self.mdns_devices: list[MdnsDevice] = []
        self.ssdp_devices: list[SsdpDevice] = []
        self.netbios_names: dict[str, str] = {}
        self.ipv6_neighbors: list[Ipv6Neighbor] = []
        self.monitor_devices: list[object] = []  # MonitorModeDevice when scapy available


def _execute_all_scanners(config: AppConfig) -> _ScanData:
    """Run all enabled scanners and return collected data.

    Args:
        config: Application configuration.

    Returns:
        _ScanData with results from each scanner.
    """
    data = _ScanData()

    if config.scan.wifi_enabled:
        data.wifi_networks = _run_scanner("WiFi", scan_wifi_networks)

    if config.scan.bluetooth_enabled:
        data.bt_devices = _run_scanner("Bluetooth", scan_bluetooth_devices)

    if config.scan.ble_enabled and platform.system().lower() == "linux":
        ble_devices = _run_scanner("BLE", scan_ble_devices)
        data.bt_devices = _merge_bluetooth_devices(data.bt_devices, ble_devices)

    if config.scan.arp_enabled:
        data.arp_devices = _run_scanner("ARP", scan_arp_table)

    if config.ping_sweep.enabled and config.ping_sweep.subnets:
        data.ping_sweep_devices = _run_scanner(
            "Ping Sweep",
            lambda: ping_sweep(
                config.ping_sweep.subnets,
                max_workers=config.ping_sweep.max_workers,
                timeout=config.ping_sweep.timeout_seconds,
                subnet_labels=config.ping_sweep.subnet_labels or None,
            ),
        )

    if config.scan.mdns_enabled:
        data.mdns_devices = _run_scanner("mDNS", _import_and_scan_mdns)

    if config.scan.ssdp_enabled:
        data.ssdp_devices = _run_scanner("SSDP", _import_and_scan_ssdp)

    if config.scan.netbios_enabled and data.arp_devices:
        data.netbios_names = _resolve_netbios(data.arp_devices)

    if config.scan.ipv6_enabled:
        data.ipv6_neighbors = _run_scanner("IPv6", scan_ipv6_neighbors)

    if config.scan.monitor_mode_enabled:
        data.monitor_devices = _run_scanner("Monitor", _import_and_scan_monitor)

    return data


_T = TypeVar("_T")


def _run_scanner(name: str, scanner_fn: Callable[[], list[_T]]) -> list[_T]:
    """Execute a scanner function with error handling.

    Args:
        name: Human-readable scanner name for logging.
        scanner_fn: Callable that returns a list of results.

    Returns:
        Scanner results, or empty list on failure.
    """
    try:
        return scanner_fn()
    except Exception as exc:
        logger.error("%s scan failed: %s", name, exc)
        return []


def _merge_bluetooth_devices(
    existing_devices: list[BluetoothDevice],
    additional_devices: list[BluetoothDevice],
) -> list[BluetoothDevice]:
    """Merge Bluetooth device lists without double-counting the same MAC."""
    merged_devices: dict[str, BluetoothDevice] = {
        device.mac_address: device for device in existing_devices if device.mac_address
    }
    ordered_devices = [device for device in existing_devices if device.mac_address]

    for device in additional_devices:
        if not device.mac_address:
            continue
        existing = merged_devices.get(device.mac_address)
        if existing is None:
            merged_devices[device.mac_address] = device
            ordered_devices.append(device)
            continue
        if not existing.device_name and device.device_name:
            existing.device_name = device.device_name
        if not existing.vendor and device.vendor:
            existing.vendor = device.vendor
        existing.is_connected = existing.is_connected or device.is_connected
        existing.is_paired = existing.is_paired or device.is_paired
        existing.device_class = existing.device_class or device.device_class

    return ordered_devices


def _import_and_scan_mdns() -> list[MdnsDevice]:
    """Import and run the mDNS scanner."""
    from src.mdns_scanner import scan_mdns_services

    return scan_mdns_services()


def _import_and_scan_ssdp() -> list[SsdpDevice]:
    """Import and run the SSDP scanner."""
    from src.ssdp_scanner import scan_ssdp_devices

    return scan_ssdp_devices()


def _import_and_scan_monitor() -> list[object]:
    """Import and run the monitor mode scanner."""
    from src.monitor_scanner import scan_monitor_mode

    return scan_monitor_mode()  # type: ignore[return-value]


def _resolve_netbios(arp_devices: list[NetworkDevice]) -> dict[str, str]:
    """Resolve NetBIOS names for discovered ARP devices.

    Args:
        arp_devices: List of ARP-discovered devices.

    Returns:
        Map of IP address to NetBIOS name.
    """
    try:
        from src.netbios_scanner import resolve_netbios_names

        ips = [d.ip_address for d in arp_devices]
        nb_infos = resolve_netbios_names(ips)
        return {nb.ip_address: nb.netbios_name for nb in nb_infos}
    except Exception as exc:
        logger.error("NetBIOS resolution failed: %s", exc)
        return {}


def _store_scan_results(
    session: DbSession,
    data: _ScanData,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    gap: int,
    config: AppConfig | None = None,
    ha_lookup: dict[str, HaDevice] | None = None,
    rescan_ports: bool = False,
) -> tuple[
    list[tuple[Device, VisibilityWindow]],
    list[tuple[Device, VisibilityWindow]],
]:
    """Store all scan results in the database.

    Args:
        session: Database session.
        data: Collected scan data.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        gap: Visibility gap threshold in seconds.
        config: Application configuration (for port scan settings).
        ha_lookup: Pre-fetched Home Assistant entity lookup dict.
        rescan_ports: Force port re-scan even if cached data exists.

    Returns:
        Tuple of (wifi_results, bt_results) for alerting.
    """
    wifi_results = track_wifi_scan(session, data.wifi_networks, gap_seconds=gap)
    logger.info("Tracked %d WiFi networks.", len(wifi_results))

    bt_results = track_bluetooth_scan(session, data.bt_devices, gap_seconds=gap)
    logger.info("Tracked %d Bluetooth devices.", len(bt_results))

    all_network_devices = data.arp_devices + data.ping_sweep_devices
    for arp_dev in all_network_devices:
        _upsert_network_device(
            session,
            arp_dev,
            whitelist,
            alert_mgr,
            data.netbios_names,
            gap,
            config=config,
            ha_lookup=ha_lookup or {},
            rescan_ports=rescan_ports,
        )

    for mdns_dev in data.mdns_devices:
        _upsert_mdns_device(session, mdns_dev, whitelist, alert_mgr, gap)

    for ssdp_dev in data.ssdp_devices:
        _upsert_ssdp_device(session, ssdp_dev, whitelist, alert_mgr, gap)

    for ipv6_dev in data.ipv6_neighbors:
        _upsert_ipv6_device(session, ipv6_dev, whitelist, alert_mgr, gap)

    return wifi_results, bt_results


def _alert_new_tracked_devices(
    tracked_results: list[tuple[Device, VisibilityWindow]],
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
) -> None:
    """Send alerts for newly discovered tracked devices.

    Args:
        tracked_results: List of (device, window) tuples from tracking.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
    """
    for device, _window in tracked_results:
        if device.created_at == device.updated_at:
            alert_mgr.on_new_device(
                mac_address=device.mac_address,
                device_type=device.device_type,
                vendor=device.vendor,
                device_name=device.device_name,
                is_whitelisted=whitelist.is_known(device.mac_address),
            )


def _upsert_network_device(
    session: DbSession,
    arp_dev: NetworkDevice,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    netbios_names: dict[str, str],
    gap_seconds: int,
    config: AppConfig | None = None,
    ha_lookup: dict[str, HaDevice] | None = None,
    rescan_ports: bool = False,
) -> None:
    """Insert/update a network device from ARP scan.

    Args:
        session: Database session.
        arp_dev: NetworkDevice from ARP scan.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        netbios_names: Map of IP to NetBIOS name.
        gap_seconds: Visibility gap threshold.
        config: Application config (for port scan settings).
        ha_lookup: Pre-fetched Home Assistant entity lookup.
        rescan_ports: Force port re-scan even if cached data exists.
    """
    existing = session.query(Device).filter_by(mac_address=arp_dev.mac_address).first()

    # Resolve NetBIOS name
    nb_name = netbios_names.get(arp_dev.ip_address, "")
    hostname = arp_dev.hostname or nb_name or None

    # Check Home Assistant for a friendly name / area
    ha_match = enrich_from_ha(arp_dev.mac_address, arp_dev.ip_address, ha_lookup or {})
    ha_name: str | None = ha_match.friendly_name if ha_match else None
    ha_area: str | None = ha_match.area if ha_match else None

    # Determine extra_info string
    extra_parts: list[str] = [f"IP: {arp_dev.ip_address}"]
    if ha_area:
        extra_parts.append(f"Area: {ha_area}")
    extra_info = " | ".join(extra_parts)

    if existing is None:
        device = Device(
            mac_address=arp_dev.mac_address,
            device_type="network",
            vendor=arp_dev.vendor,
            device_name=ha_name or hostname,
            hostname=hostname,
            ip_address=arp_dev.ip_address,
            extra_info=extra_info,
            network_segment=arp_dev.network_segment,
        )
        session.add(device)
        session.flush()  # populate device.id so we can update open_ports below

        alert_mgr.on_new_device(
            mac_address=arp_dev.mac_address,
            device_type="network",
            vendor=arp_dev.vendor,
            device_name=ha_name or hostname,
            is_whitelisted=whitelist.is_known(arp_dev.mac_address),
        )
    else:
        existing.device_name = ha_name or hostname or existing.device_name
        existing.hostname = hostname or existing.hostname
        existing.vendor = arp_dev.vendor or existing.vendor
        existing.ip_address = arp_dev.ip_address
        existing.extra_info = extra_info
        if arp_dev.network_segment:
            existing.network_segment = arp_dev.network_segment
        device = existing

    # Port scanning: run only if enabled and (no cached data or rescan requested)
    if (
        config is not None
        and config.port_scan.enabled
        and arp_dev.ip_address
        and (rescan_ports or not device.open_ports)
    ):
        _mac = arp_dev.mac_address or ""
        _masked = "**:**:**:**:" + ":".join(_mac.split(":")[-2:]) if _mac else "(unknown)"
        logger.info("Port scanning %s (%s)…", arp_dev.ip_address, _masked)
        open_ports = scan_host_ports(
            arp_dev.ip_address,
            ports=config.port_scan.ports,
            timeout=config.port_scan.timeout_seconds,
            max_workers=config.port_scan.max_workers,
        )
        device.open_ports = encode_open_ports(open_ports) if open_ports else ""
        logger.info(
            "Port scan %s → %d open port(s): %s",
            arp_dev.ip_address,
            len(open_ports),
            device.open_ports or "(none)",
        )

    update_visibility(
        session,
        mac_address=arp_dev.mac_address,
        scan_time=arp_dev.scan_time,
        gap_seconds=gap_seconds,
    )


def _upsert_mdns_device(
    session: DbSession,
    mdns_dev: MdnsDevice,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    gap_seconds: int,
) -> None:
    """Insert/update a device from mDNS discovery.

    Args:
        session: Database session.
        mdns_dev: MdnsDevice from mDNS scan.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        gap_seconds: Visibility gap threshold.
    """
    if not mdns_dev.mac_address:
        return

    existing = session.query(Device).filter_by(mac_address=mdns_dev.mac_address).first()

    if existing is None:
        device = Device(
            mac_address=mdns_dev.mac_address,
            device_type="network",
            vendor=mdns_dev.vendor,
            device_name=mdns_dev.hostname,
            hostname=mdns_dev.hostname,
            ip_address=mdns_dev.ip_address,
            extra_info=f"mDNS: {mdns_dev.service_type} | IP: {mdns_dev.ip_address}",
        )
        session.add(device)

        alert_mgr.on_new_device(
            mac_address=mdns_dev.mac_address,
            device_type="network",
            vendor=mdns_dev.vendor,
            device_name=mdns_dev.hostname,
            is_whitelisted=whitelist.is_known(mdns_dev.mac_address),
        )
    else:
        existing.hostname = mdns_dev.hostname or existing.hostname
        existing.vendor = mdns_dev.vendor or existing.vendor
        existing.ip_address = mdns_dev.ip_address or existing.ip_address
        if mdns_dev.service_type:
            svc = f"mDNS: {mdns_dev.service_type}"
            if existing.extra_info and svc not in existing.extra_info:
                existing.extra_info = f"{existing.extra_info} | {svc}"
            elif not existing.extra_info:
                existing.extra_info = svc

    update_visibility(
        session,
        mac_address=mdns_dev.mac_address,
        scan_time=mdns_dev.scan_time,
        gap_seconds=gap_seconds,
    )


def _upsert_ssdp_device(
    session: DbSession,
    ssdp_dev: SsdpDevice,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    gap_seconds: int,
) -> None:
    """Insert/update a device from SSDP discovery.

    Args:
        session: Database session.
        ssdp_dev: SsdpDevice from SSDP scan.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        gap_seconds: Visibility gap threshold.
    """
    if not ssdp_dev.mac_address:
        return

    existing = session.query(Device).filter_by(mac_address=ssdp_dev.mac_address).first()

    if existing is None:
        device = Device(
            mac_address=ssdp_dev.mac_address,
            device_type="network",
            vendor=ssdp_dev.vendor,
            device_name=ssdp_dev.server or None,
            ip_address=ssdp_dev.ip_address,
            extra_info=f"SSDP: {ssdp_dev.server} | IP: {ssdp_dev.ip_address}",
        )
        session.add(device)

        alert_mgr.on_new_device(
            mac_address=ssdp_dev.mac_address,
            device_type="network",
            vendor=ssdp_dev.vendor,
            device_name=ssdp_dev.server,
            is_whitelisted=whitelist.is_known(ssdp_dev.mac_address),
        )
    else:
        existing.vendor = ssdp_dev.vendor or existing.vendor
        existing.ip_address = ssdp_dev.ip_address or existing.ip_address
        if ssdp_dev.server:
            svc = f"SSDP: {ssdp_dev.server}"
            if existing.extra_info and svc not in existing.extra_info:
                existing.extra_info = f"{existing.extra_info} | {svc}"
            elif not existing.extra_info:
                existing.extra_info = svc

    update_visibility(
        session,
        mac_address=ssdp_dev.mac_address,
        scan_time=ssdp_dev.scan_time,
        gap_seconds=gap_seconds,
    )


def _upsert_ipv6_device(
    session: DbSession,
    ipv6_dev: Ipv6Neighbor,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    gap_seconds: int,
) -> None:
    """Insert/update a device from IPv6 neighbor discovery.

    Args:
        session: Database session.
        ipv6_dev: Ipv6Neighbor from IPv6 scan.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        gap_seconds: Visibility gap threshold.
    """
    existing = session.query(Device).filter_by(mac_address=ipv6_dev.mac_address).first()

    if existing is None:
        device = Device(
            mac_address=ipv6_dev.mac_address,
            device_type="network",
            ip_address=ipv6_dev.ipv6_address,
            extra_info=f"IPv6: {ipv6_dev.ipv6_address} ({ipv6_dev.state})",
        )
        session.add(device)

        alert_mgr.on_new_device(
            mac_address=ipv6_dev.mac_address,
            device_type="network",
            device_name=None,
            is_whitelisted=whitelist.is_known(ipv6_dev.mac_address),
        )
    else:
        # Enrich with IPv6 info if not already present
        ipv6_info = f"IPv6: {ipv6_dev.ipv6_address}"
        if existing.extra_info and ipv6_info not in existing.extra_info:
            existing.extra_info = f"{existing.extra_info} | {ipv6_info}"
        elif not existing.extra_info:
            existing.extra_info = ipv6_info
        # Update IP if not already set (prefer IPv4)
        if not existing.ip_address:
            existing.ip_address = ipv6_dev.ipv6_address

    update_visibility(
        session,
        mac_address=ipv6_dev.mac_address,
        scan_time=ipv6_dev.scan_time,
        gap_seconds=gap_seconds,
    )


def _categorize_all_devices(session: DbSession, whitelist: WhitelistManager) -> None:
    """Categorize all devices that don't have a category yet.

    Args:
        session: Database session.
        whitelist: Whitelist manager for custom categories.
    """
    devices = session.query(Device).filter(Device.category.is_(None)).all()
    for device in devices:
        entry = whitelist.get_entry(device.mac_address)
        if entry and entry.category:
            device.category = entry.category
            device.is_whitelisted = True
        else:
            device.category = categorize_device(
                vendor=device.vendor,
                hostname=device.hostname or device.device_name,
                device_name=device.device_name,
                ssid=device.ssid,
                mac_address=device.mac_address,
                device_type=device.device_type,
            )
            device.is_whitelisted = whitelist.is_known(device.mac_address)


_DEVICE_TYPE_LABELS: dict[str, str] = {
    "wifi_ap": "WiFi AP",
    "wifi_client": "WiFi Client",
    "bluetooth": "Bluetooth",
    "network": "Network",
}


_CATEGORY_RELEVANCE: dict[str, int] = {
    "router": 0,
    "access_point": 1,
    "computer": 2,
    "mobile": 3,
    "tablet": 4,
    "nas": 5,
    "printer": 6,
    "tv": 7,
    "speaker": 8,
    "gaming": 9,
    "camera": 10,
    "iot": 11,
    "wearable": 12,
    "appliance": 13,
    "network": 14,
    "virtual": 15,
    "unknown": 16,
}


def _device_sort_key(
    item: tuple[Device, VisibilityWindow | None],
    whitelist: WhitelistManager | None,
) -> tuple[int, int, int, str]:
    """Sort key: whitelisted first, then category relevance, then named, then MAC."""
    device, _window = item
    is_wl = 0 if device.is_whitelisted else 1
    cat_rank = _CATEGORY_RELEVANCE.get(device.category or "unknown", 16)
    has_name = 0 if (device.device_name or device.hostname) else 1
    return (is_wl, cat_rank, has_name, device.mac_address)


def _display_results(session: DbSession, whitelist: WhitelistManager | None = None) -> None:
    """Display all tracked devices in a human-readable table.

    Args:
        session: Active database session.
        whitelist: Optional whitelist manager for custom names.
    """
    results = get_all_devices_with_latest_window(session)

    if not results:
        print("\nNo devices found.")
        return

    results.sort(key=lambda item: _device_sort_key(item, whitelist))

    headers = [
        "Type",
        "Category",
        "Name / SSID",
        "Vendor",
        "MAC Address",
        "Signal",
        "Segment",
        "Open Ports",
        "First Seen",
        "Last Seen",
        "Details",
    ]

    rows = [_build_device_row(device, window, whitelist) for device, window in results]

    _print_device_table(rows, headers)


def _build_device_row(
    device: Device,
    window: VisibilityWindow | None,
    whitelist: WhitelistManager | None,
) -> list[str]:
    """Build a single table row for a device.

    Args:
        device: Device record.
        window: Visibility window (may be None).
        whitelist: Optional whitelist manager.

    Returns:
        List of column values for the table row.
    """
    type_label = _DEVICE_TYPE_LABELS.get(device.device_type, device.device_type)
    category = get_category_label(device.category) if device.category else ""
    name = _best_name(device, whitelist)
    vendor = _friendly_vendor(device.vendor, device.mac_address)

    if device.is_whitelisted:
        name = f"✓ {name}"

    signal_str = _format_signal(window.signal_strength_dbm if window else None)
    first_seen = _format_time(window.first_seen if window else None)
    last_seen = _format_time(window.last_seen if window else None)
    details = _format_details(device)
    segment = device.network_segment or ""
    open_ports = _format_open_ports(device.open_ports)

    return [
        type_label,
        category,
        name,
        vendor,
        device.mac_address,
        signal_str,
        segment,
        open_ports,
        first_seen,
        last_seen,
        details,
    ]


def _format_open_ports(encoded: str | None) -> str:
    """Format the open_ports column for display.

    Args:
        encoded: Comma-separated ``port/service`` string from the database,
            or None if not yet scanned.

    Returns:
        Human-readable port list (e.g. ``"22/ssh 80/http"``) or empty string.
    """
    if not encoded:
        return ""
    ports = decode_open_ports(encoded)
    return " ".join(str(p) for p in ports)


def _format_details(device: Device) -> str:
    """Format the details column for a device row.

    Args:
        device: Device record.

    Returns:
        Pipe-separated detail string.
    """
    parts: list[str] = []
    if device.authentication and device.authentication != "Open":
        parts.append(f"Auth: {device.authentication}")
    if device.encryption and device.encryption != "None":
        parts.append(f"Enc: {device.encryption}")
    if device.radio_type:
        parts.append(device.radio_type)
    if device.channel:
        parts.append(f"Ch {device.channel}")
    if device.extra_info:
        parts.append(device.extra_info)
    return " | ".join(parts)


def _print_device_table(rows: list[list[str]], headers: list[str]) -> None:
    """Print the device table and summary statistics.

    Args:
        rows: Table rows.
        headers: Column headers.
    """
    print("\n" + "=" * 140)
    print("  DISCOVERED DEVICES")
    print("=" * 140)
    print(tabulate(rows, headers=headers, tablefmt="grid"))
    print(f"\nTotal devices: {len(rows)}")
    print(f"  WiFi APs:         {sum(1 for r in rows if r[0] == 'WiFi AP')}")
    print(f"  Bluetooth:        {sum(1 for r in rows if r[0] == 'Bluetooth')}")
    print(f"  Network devices:  {sum(1 for r in rows if r[0] == 'Network')}")
    print()


def main() -> None:
    """Main entry point.

    Supports the following optional CLI flags:

    - ``--once``: Run a single scan cycle regardless of config.
    - ``--continuous``: Run in continuous loop regardless of config.
    - ``--rescan-ports``: Force a fresh port scan for all devices this cycle.
    - ``--export <csv|json>``: Dump all devices to stdout and exit.
    - ``--output <path>``: Write export to file instead of stdout.
    """
    # Pre-parse scan-control flags (ignore unknown so --export still works below)
    import argparse as _ap

    _scan_parser = _ap.ArgumentParser(add_help=False)
    _scan_parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan cycle and exit (overrides config.scan.continuous).",
    )
    _scan_parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run in continuous loop (overrides config.scan.continuous).",
    )
    _scan_parser.add_argument(
        "--rescan-ports",
        action="store_true",
        dest="rescan_ports",
        help="Force a fresh TCP port scan for all network devices this cycle.",
    )
    _scan_args, _ = _scan_parser.parse_known_args()

    # --- Export sub-command (handled by its own parser) ---
    if "--export" in sys.argv:
        _run_cli_export()
        return

    try:
        config = load_config()

        # Apply CLI overrides
        if _scan_args.once and _scan_args.continuous:
            logger.warning("Both --once and --continuous given; --continuous takes precedence.")
        if _scan_args.continuous:
            config.scan.continuous = True
        elif _scan_args.once:
            config.scan.continuous = False

        # --rescan-ports implies port scanning is enabled for this run
        if _scan_args.rescan_ports and not config.port_scan.enabled:
            logger.info("--rescan-ports given: enabling port scan for this run.")
            config.port_scan.enabled = True

        # Start API server in background thread if enabled
        if config.api.enabled:
            import threading

            from src.api import app, set_engine

            engine = init_database(config.database.url)
            set_engine(engine)

            def _run_api() -> None:
                import uvicorn

                uvicorn.run(
                    app,
                    host=config.api.host,
                    port=config.api.port,
                    log_level="warning",
                )

            api_thread = threading.Thread(target=_run_api, daemon=True, name="api-server")
            api_thread.start()
            logger.info("API server started on http://%s:%d", config.api.host, config.api.port)

        run_scan(config, rescan_ports=_scan_args.rescan_ports)
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(0)
    except Exception:
        logger.exception("Fatal error during scan.")
        sys.exit(1)


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# CLI export helpers
# ---------------------------------------------------------------------------

_EXPORT_CSV_FIELDS = [
    "mac_address",
    "device_type",
    "device_name",
    "ssid",
    "vendor",
    "hostname",
    "ip_address",
    "category",
    "is_whitelisted",
    "reconnect_count",
    "channel",
    "authentication",
    "encryption",
    "radio_type",
    "extra_info",
    "created_at",
    "updated_at",
]


def _run_cli_export() -> None:  # noqa: PLR0912
    """Handle the ``--export`` CLI sub-command."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="btwifi --export",
        description="Export device data to CSV or JSON.",
    )
    parser.add_argument(
        "--export",
        choices=["csv", "json"],
        required=True,
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output file path. Use '-' for stdout (default).",
    )
    args = parser.parse_args()

    config = load_config()
    engine = init_database(config.database.url)

    with get_session(engine) as session:
        from src.models import Device

        devices = session.query(Device).order_by(Device.mac_address).all()

        import contextlib
        import io

        with contextlib.ExitStack() as stack:
            if args.output == "-":
                buf: io.StringIO | io.TextIOWrapper = io.StringIO()
            else:
                buf = stack.enter_context(
                    open(args.output, "w", newline="", encoding="utf-8")  # noqa: SIM115
                )

            if args.export == "csv":
                writer = csv.DictWriter(buf, fieldnames=_EXPORT_CSV_FIELDS, extrasaction="ignore")
                writer.writeheader()
                for dev in devices:
                    writer.writerow({f: (getattr(dev, f, None) or "") for f in _EXPORT_CSV_FIELDS})
            else:
                rows = [{f: str(getattr(dev, f, None) or "") for f in _EXPORT_CSV_FIELDS} for dev in devices]
                json.dump(rows, buf, indent=2, default=str)
                buf.write("\n")

            if args.output == "-":
                print(buf.getvalue())  # type: ignore[union-attr]
            else:
                logger.info("Exported %d devices to %s", len(devices), args.output)
