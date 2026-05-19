"""Net Sentry — Main entry point for the device visibility tracker.

Scans for WiFi networks, Bluetooth devices, and local network devices,
then stores results in the database and displays a human-readable table.
"""

import csv
import ipaddress
import json
import logging
import platform
import re
import signal
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Engine, func
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
from src.logging_setup import setup_logging
from src.mdns_scanner import MdnsDevice
from src.models import Device, VisibilityWindow
from src.network_discovery import NetworkDevice, discover_subnets_from_routing_table, ping_sweep, scan_arp_table
from src.oui_lookup import is_multicast_mac, is_randomized_mac
from src.port_scanner import OpenPort, decode_open_ports, encode_open_ports, scan_host_ports
from src.ssdp_scanner import SsdpDevice
from src.tracing import setup_tracing
from src.whitelist import WhitelistManager
from src.wifi_scanner import WifiNetwork, scan_wifi_networks

# Configure logging — can be overridden by run_scan() or config at startup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

_FULL_TCP_PORTS = list(range(1, 65536))


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
        _run_continuous_scan(engine, config, whitelist, alert_mgr, mqtt_pub, rescan_ports=rescan_ports)
    else:
        _run_single_scan(engine, config, whitelist, alert_mgr, mqtt_pub, rescan_ports=rescan_ports)

    # Cleanup MQTT
    if mqtt_pub is not None:
        mqtt_pub.disconnect()


def _run_continuous_scan(
    engine: Engine,
    config: AppConfig,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    mqtt_publisher: object | None,
    rescan_ports: bool = False,
) -> None:
    """Run scan cycles repeatedly until shutdown is requested."""
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
        _run_single_scan(engine, config, whitelist, alert_mgr, mqtt_publisher, rescan_ports=rescan_ports)
        rescan_ports = False  # Only force-rescan ports on the first cycle

        if _shutdown_requested:
            break

        logger.info("Next scan in %d seconds...", config.scan.interval_seconds)
        _interruptible_sleep(config.scan.interval_seconds)

    logger.info("Continuous scanning stopped after %d cycles.", scan_number)


def _interruptible_sleep(seconds: int) -> None:
    """Sleep in 0.1 s increments so shutdown signals are honoured promptly."""
    for _ in range(seconds * 10):
        if _shutdown_requested:
            break
        time.sleep(0.1)


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
    scan_data = _execute_all_scanners(config, force_host_discovery=rescan_ports)
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

    # Check disappearance rules (E: configurable alert rules)
    disappearance_macs = [r.mac_address for r in config.alert.rules if r.rule_type == "disappearance" and r.mac_address]
    if disappearance_macs:
        with get_session(engine) as session:
            rows = (
                session.query(VisibilityWindow.mac_address, func.max(VisibilityWindow.last_seen))
                .filter(VisibilityWindow.mac_address.in_(disappearance_macs))
                .group_by(VisibilityWindow.mac_address)
                .all()
            )
        last_seen_by_mac = {mac: last for mac, last in rows if last is not None}
        alert_mgr.check_disappearance(last_seen_by_mac)

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


@dataclass
class _PortScanSummary:
    """Counters for one scan cycle's TCP port scanning."""

    scanned_hosts: int = 0
    cached_hosts: int = 0
    skipped_hosts: int = 0
    total_open_ports: int = 0


@dataclass(frozen=True)
class _PortScanTarget:
    """A host queued for TCP port scanning."""

    mac_address: str
    ip_address: str


@dataclass
class _PortScanResult:
    """TCP port scan result for one host."""

    mac_address: str
    ip_address: str
    open_ports: list[OpenPort]
    elapsed_seconds: float


def _build_scanner_tasks(
    config: AppConfig,
    ping_sweep_subnets: list[str],
) -> dict[str, Callable[[], list]]:
    """Build the set of enabled scanner tasks to run in parallel."""
    tasks: dict[str, Callable[[], list]] = {}

    if config.scan.wifi_enabled:
        tasks["WiFi"] = scan_wifi_networks
    if config.scan.bluetooth_enabled:
        tasks["Bluetooth"] = scan_bluetooth_devices
    if config.scan.ble_enabled and platform.system().lower() == "linux":
        tasks["BLE"] = lambda: scan_ble_devices(scanning_mode=config.scan.ble_scanning_mode)
    if config.scan.arp_enabled:
        tasks["ARP"] = scan_arp_table
    if ping_sweep_subnets:
        tasks["Ping Sweep"] = lambda: ping_sweep(
            ping_sweep_subnets,
            max_workers=config.ping_sweep.max_workers,
            timeout=config.ping_sweep.timeout_seconds,
            subnet_labels=config.ping_sweep.subnet_labels or None,
        )
    if config.scan.mdns_enabled:
        allowed = config.mdns.service_types or None
        tasks["mDNS"] = lambda: _import_and_scan_mdns(allowed_types=allowed)
    if config.scan.ssdp_enabled:
        tasks["SSDP"] = _import_and_scan_ssdp
    if config.scan.ipv6_enabled:
        tasks["IPv6"] = scan_ipv6_neighbors
    if config.scan.monitor_mode_enabled:
        tasks["Monitor"] = _import_and_scan_monitor
    if config.scan.dhcp_enabled:
        tasks["DHCP"] = lambda: _import_and_scan_dhcp(config.scan.dhcp_lease_file)
    return tasks


def _dispatch_scanner_result(name: str, result: list, data: "_ScanData") -> None:
    """Populate *data* with the result returned by a named scanner."""
    if name == "WiFi":
        data.wifi_networks = result
    elif name in ("Bluetooth", "BLE"):
        data.bt_devices = _merge_bluetooth_devices(data.bt_devices, result)
    elif name == "ARP":
        data.arp_devices = result
    elif name == "Ping Sweep":
        data.ping_sweep_devices = result
    elif name == "mDNS":
        data.mdns_devices = result
    elif name == "SSDP":
        data.ssdp_devices = result
    elif name == "IPv6":
        data.ipv6_neighbors = result
    elif name == "Monitor":
        data.monitor_devices = result


def _execute_all_scanners(config: AppConfig, force_host_discovery: bool = False) -> _ScanData:
    """Run all enabled scanners and return collected data.

    Independent scanners (WiFi, Bluetooth, ARP, mDNS, SSDP, IPv6, Monitor,
    Ping Sweep) run in parallel via a ThreadPoolExecutor.  NetBIOS resolution
    runs afterwards because it depends on the ARP results.

    Args:
        config: Application configuration.
        force_host_discovery: When True, run a ping sweep over detected local
            subnets even if ping_sweep is not explicitly configured.

    Returns:
        _ScanData with results from each scanner.
    """
    data = _ScanData()

    ping_sweep_subnets: list[str] = []
    if config.ping_sweep.enabled:
        ping_sweep_subnets = list(config.ping_sweep.subnets)
    if force_host_discovery and not ping_sweep_subnets:
        ping_sweep_subnets = _subnets_safe_for_forced_host_discovery(
            discover_subnets_from_routing_table(),
        )

    tasks = _build_scanner_tasks(config, ping_sweep_subnets)
    logger.info("Scanner phase started: %s.", ", ".join(tasks) if tasks else "no scanners enabled")

    with ThreadPoolExecutor(max_workers=len(tasks) or 1, thread_name_prefix="scanner") as executor:
        future_to_name = {
            executor.submit(_run_scanner_with_trace_context, name, fn): name for name, fn in tasks.items()
        }
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            result = future.result()
            logger.info("%s scanner finished: %d result(s).", name, len(result))
            _dispatch_scanner_result(name, result, data)

    # A sweep populates the OS ARP cache; refresh it afterwards so LAN hosts
    # are stored and port-scanned under their real MAC instead of pseudo-MACs.
    if data.ping_sweep_devices and config.scan.arp_enabled:
        logger.info("ARP refresh started after ping sweep.")
        refreshed_arp = _run_scanner("ARP refresh", scan_arp_table)
        data.arp_devices = _merge_network_devices_by_mac(data.arp_devices, refreshed_arp)
        logger.info("ARP refresh finished: %d total ARP device(s).", len(data.arp_devices))

    data.ping_sweep_devices = _drop_ping_sweep_devices_with_arp_match(
        data.arp_devices,
        data.ping_sweep_devices,
    )

    # NetBIOS depends on ARP results — must run after
    if config.scan.netbios_enabled and data.arp_devices:
        data.netbios_names = _resolve_netbios(data.arp_devices)

    return data


def _merge_network_devices_by_mac(
    existing_devices: list[NetworkDevice],
    additional_devices: list[NetworkDevice],
) -> list[NetworkDevice]:
    """Merge network device lists, preferring later details for same MAC."""
    merged: dict[str, NetworkDevice] = {}
    ordered: list[NetworkDevice] = []

    for device in existing_devices + additional_devices:
        current = merged.get(device.mac_address)
        if current is None:
            merged[device.mac_address] = device
            ordered.append(device)
            continue
        current.ip_address = device.ip_address or current.ip_address
        current.interface = device.interface or current.interface
        current.hostname = device.hostname or current.hostname
        current.vendor = device.vendor or current.vendor
        current.arp_type = device.arp_type or current.arp_type
        current.network_segment = device.network_segment or current.network_segment

    return ordered


def _drop_ping_sweep_devices_with_arp_match(
    arp_devices: list[NetworkDevice],
    ping_sweep_devices: list[NetworkDevice],
) -> list[NetworkDevice]:
    """Drop pseudo-MAC ping sweep rows when ARP has the same IP."""
    arp_ips = {device.ip_address for device in arp_devices if device.ip_address}
    return [device for device in ping_sweep_devices if device.ip_address not in arp_ips]


def _subnets_safe_for_forced_host_discovery(subnets: list[str], max_hosts: int = 1024) -> list[str]:
    """Return auto-detected subnets that are small enough to sweep implicitly."""
    safe_subnets: list[str] = []
    for cidr in subnets:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not isinstance(network, ipaddress.IPv4Network):
            continue
        if not network.is_private or network.is_loopback or network.is_multicast:
            continue
        if network.num_addresses < 4:
            continue
        if network.num_addresses > max_hosts + 2:
            logger.warning(
                "Skipping auto-discovered subnet %s for --rescan-ports: too large for implicit sweep.",
                cidr,
            )
            continue
        safe_subnets.append(str(network))
    return safe_subnets


def _run_scanner_with_trace_context[T](name: str, scanner_fn: Callable[[], list[T]]) -> list[T]:
    """Run a scanner in a thread pool while preserving the parent trace context.

    Captures the OpenTelemetry context from the calling thread and attaches
    it inside the worker thread so that spans created by the scanner are
    correctly parented.  Falls back transparently when opentelemetry is not
    installed.

    Args:
        name: Scanner name (forwarded to :func:`_run_scanner`).
        scanner_fn: Scanner callable.

    Returns:
        Scanner results.
    """
    try:
        from opentelemetry import context as otel_context
        from opentelemetry import trace

        ctx = otel_context.get_current()
        tracer = trace.get_tracer("net_sentry.scanner")
        with tracer.start_as_current_span(f"scanner.{name}", context=ctx):
            return _run_scanner(name, scanner_fn)
    except ImportError:
        return _run_scanner(name, scanner_fn)


def _run_scanner[T](name: str, scanner_fn: Callable[[], list[T]]) -> list[T]:
    """Execute a scanner function with error handling and per-scanner metrics.

    Args:
        name: Human-readable scanner name for logging.
        scanner_fn: Callable that returns a list of results.

    Returns:
        Scanner results, or empty list on failure.
    """
    import time as _time

    start = _time.time()
    try:
        results = scanner_fn()
        return results
    except Exception:
        logger.exception("%s scan failed", name)
        try:
            from src.metrics import SCAN_ERRORS

            SCAN_ERRORS.labels(scanner_type=name).inc()
        except Exception:  # pragma: no cover
            pass
        return []
    finally:
        elapsed = _time.time() - start
        try:
            from src.metrics import SCAN_DURATION_BY_SCANNER

            SCAN_DURATION_BY_SCANNER.labels(scanner=name).observe(elapsed)
        except Exception:  # pragma: no cover
            pass


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


def _import_and_scan_mdns(allowed_types: list[str] | None = None) -> list[MdnsDevice]:
    """Import and run the mDNS scanner."""
    from src.mdns_scanner import scan_mdns_services

    return scan_mdns_services(allowed_types=allowed_types)


def _import_and_scan_ssdp() -> list[SsdpDevice]:
    """Import and run the SSDP scanner."""
    from src.ssdp_scanner import scan_ssdp_devices

    return scan_ssdp_devices()


def _import_and_scan_monitor() -> list[object]:
    """Import and run the monitor mode scanner."""
    from src.monitor_scanner import scan_monitor_mode

    return scan_monitor_mode()  # type: ignore[return-value]


def _import_and_scan_dhcp(lease_file: str) -> list[NetworkDevice]:
    """Import and run the DHCP lease scanner.

    Args:
        lease_file: Path to the ISC DHCP lease database file.

    Returns:
        List of NetworkDevice records derived from DHCP leases.
    """
    from src.dhcp_scanner import parse_dhcp_leases

    return parse_dhcp_leases(lease_file)


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
    except Exception:
        logger.exception("NetBIOS resolution failed")
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
    list[tuple[Device, VisibilityWindow, datetime | None]],
    list[tuple[Device, VisibilityWindow, datetime | None]],
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
    port_targets, port_summary = _process_network_devices(
        session, all_network_devices, whitelist, alert_mgr, data, gap, config, ha_lookup, rescan_ports
    )
    if port_targets:
        _run_port_scan_phase(session, config, port_targets, port_summary)
    if config is not None and config.port_scan.enabled:
        logger.info(
            "Port scan phase finished: scanned %d host(s), reused cached results for %d, "
            "skipped %d, found %d open port(s).",
            port_summary.scanned_hosts,
            port_summary.cached_hosts,
            port_summary.skipped_hosts,
            port_summary.total_open_ports,
        )

    for mdns_dev in data.mdns_devices:
        _upsert_mdns_device(session, mdns_dev, whitelist, alert_mgr, gap)

    for ssdp_dev in data.ssdp_devices:
        _upsert_ssdp_device(session, ssdp_dev, whitelist, alert_mgr, gap)

    for ipv6_dev in data.ipv6_neighbors:
        _upsert_ipv6_device(session, ipv6_dev, whitelist, alert_mgr, gap)

    return wifi_results, bt_results


def _process_network_devices(
    session: DbSession,
    network_devices: list,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    data: "_ScanData",
    gap: int,
    config: AppConfig | None,
    ha_lookup: dict | None,
    rescan_ports: bool,
) -> tuple[list["_PortScanTarget"], "_PortScanSummary"]:
    """Upsert each network device and collect port scan targets."""
    port_summary = _PortScanSummary()
    port_targets: list[_PortScanTarget] = []
    port_scan_enabled = config is not None and config.port_scan.enabled
    if port_scan_enabled:
        mode = "full" if config.port_scan.ports == _FULL_TCP_PORTS else "configured"  # type: ignore[union-attr]
        logger.info(
            "Port scan phase started: %d network device(s), %d TCP port(s) per device, mode=%s, host_workers=%d.",
            sum(1 for d in network_devices if d.ip_address),
            len(config.port_scan.ports),  # type: ignore[union-attr]
            mode,
            config.port_scan.host_workers,  # type: ignore[union-attr]
        )
    for arp_dev in network_devices:
        device = _upsert_network_device(
            session,
            arp_dev,
            whitelist,
            alert_mgr,
            data.netbios_names,
            gap,
            config=config,
            ha_lookup=ha_lookup or {},
        )
        if port_scan_enabled:
            _classify_port_scan_target(arp_dev, device, rescan_ports, port_targets, port_summary)
    return port_targets, port_summary


def _classify_port_scan_target(
    arp_dev: object,
    device: Device,
    rescan_ports: bool,
    port_targets: list["_PortScanTarget"],
    port_summary: "_PortScanSummary",
) -> None:
    """Classify a network device as a port-scan target, cached, or skipped."""
    if not arp_dev.ip_address:  # type: ignore[attr-defined]
        port_summary.skipped_hosts += 1
    elif not rescan_ports and device.open_ports:
        port_summary.cached_hosts += 1
    else:
        port_targets.append(_PortScanTarget(mac_address=device.mac_address, ip_address=arp_dev.ip_address))  # type: ignore[attr-defined]


def _run_port_scan_phase(
    session: DbSession,
    config: AppConfig | None,
    port_targets: list["_PortScanTarget"],
    port_summary: "_PortScanSummary",
) -> None:
    """Run port scans for all collected targets and persist results."""
    if config is None or not config.port_scan.enabled:
        return
    session.flush()
    scan_results = _scan_port_targets_parallel(port_targets, config)
    for scan_result in scan_results:
        port_device = session.query(Device).filter_by(mac_address=scan_result.mac_address).first()
        if port_device is None:
            continue
        port_device.open_ports = encode_open_ports(scan_result.open_ports) if scan_result.open_ports else ""
        port_summary.scanned_hosts += 1
        port_summary.total_open_ports += len(scan_result.open_ports)


def _alert_new_tracked_devices(
    tracked_results: list[tuple[Device, VisibilityWindow, datetime | None]],
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
) -> None:
    """Send alerts for newly discovered tracked devices and returning devices.

    Args:
        tracked_results: List of (device, window, previous_last_seen) tuples from tracking.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
    """
    warn_after_days = alert_mgr._config.warn_returning_after_days
    now = datetime.now(UTC)
    for device, _window, previous_last_seen in tracked_results:
        is_new_device = device.created_at == device.updated_at
        if is_new_device:
            alert_mgr.on_new_device(
                mac_address=device.mac_address,
                device_type=device.device_type,
                vendor=device.vendor,
                device_name=device.device_name,
                is_whitelisted=whitelist.is_known(device.mac_address),
            )
        elif previous_last_seen is not None and warn_after_days > 0:
            # Device already known — check if it was absent for more than warn_after_days
            last_seen_aware = previous_last_seen
            if last_seen_aware.tzinfo is None:
                last_seen_aware = last_seen_aware.replace(tzinfo=UTC)
            days_absent = (now - last_seen_aware).total_seconds() / 86400.0
            if days_absent >= warn_after_days:
                alert_mgr.on_returning_device(
                    mac_address=device.mac_address,
                    device_type=device.device_type,
                    days_absent=days_absent,
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
) -> Device:
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

    Returns:
        The inserted or updated Device row.
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

    update_visibility(
        session,
        mac_address=arp_dev.mac_address,
        scan_time=arp_dev.scan_time,
        gap_seconds=gap_seconds,
    )
    return device


def _scan_port_targets_parallel(
    targets: list[_PortScanTarget],
    config: AppConfig,
) -> list[_PortScanResult]:
    """Scan TCP ports for multiple hosts concurrently."""
    if not targets:
        return []

    host_workers = max(1, min(config.port_scan.host_workers, len(targets)))
    logger.info("Scanning ports on %d host(s) with %d host worker(s).", len(targets), host_workers)
    results: list[_PortScanResult] = []

    with ThreadPoolExecutor(max_workers=host_workers, thread_name_prefix="port-scan") as pool:
        futures = {pool.submit(_scan_port_target, target, config): target for target in targets}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result.open_ports:
                logger.info(
                    "Port scan found %d open port(s) on one host in %.1fs.",
                    len(result.open_ports),
                    result.elapsed_seconds,
                )
                logger.debug(
                    "Open ports found on one host: %s",
                    " ".join(str(port) for port in result.open_ports),
                )
            else:
                logger.debug("Port scan found no open ports on one host in %.1fs.", result.elapsed_seconds)

    return results


def _scan_port_target(target: _PortScanTarget, config: AppConfig) -> _PortScanResult:
    """Scan TCP ports for one host."""
    logger.debug(
        "Port scan started for one host across %d TCP port(s).",
        len(config.port_scan.ports),
    )
    scan_start = time.time()
    open_ports = scan_host_ports(
        target.ip_address,
        ports=config.port_scan.ports,
        timeout=config.port_scan.timeout_seconds,
        max_workers=config.port_scan.max_workers,
    )
    return _PortScanResult(
        mac_address=target.mac_address,
        ip_address=target.ip_address,
        open_ports=open_ports,
        elapsed_seconds=time.time() - scan_start,
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
    results = [(device, window) for device, window in results if not is_multicast_mac(device.mac_address)]

    if not results:
        print("\nNo devices found.")
        return

    results.sort(key=_device_sort_key)

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
    - ``--full-port-scan``: Scan all TCP ports (1-65535) instead of the configured shortlist.
    - ``--export <csv|json>``: Dump all devices to stdout and exit.
    - ``--output <path>``: Write export to file instead of stdout.
    """
    # Pre-parse scan-control flags (ignore unknown so --export still works below)
    import argparse as _ap

    # Top-level parser for --help (add_help=True so -h/--help exits cleanly)
    _top_parser = _ap.ArgumentParser(
        prog="net-sentry",
        description="Net Sentry — Network Device Visibility Tracker",
        formatter_class=_ap.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  net-sentry --once              Run a single scan and exit\n"
            "  net-sentry --continuous        Scan in a loop\n"
            "  net-sentry --export csv        Dump all known devices as CSV\n"
        ),
    )
    _top_parser.add_argument("--once", action="store_true", help="Run a single scan cycle and exit.")
    _top_parser.add_argument("--continuous", action="store_true", help="Run in continuous loop.")
    _top_parser.add_argument(
        "--rescan-ports",
        action="store_true",
        dest="rescan_ports",
        help="Force a fresh TCP port scan for all network devices this cycle.",
    )
    _top_parser.add_argument(
        "--full-port-scan",
        action="store_true",
        dest="full_port_scan",
        help="Scan all TCP ports (1-65535); implies --rescan-ports and can take much longer.",
    )
    _top_parser.add_argument("--export", choices=["csv", "json"], help="Dump all devices and exit.")
    _top_parser.add_argument("--output", default="-", help="Write --export output to file (default: stdout).")
    _top_parser.parse_known_args()  # exits with 0 if --help / -h was passed

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
    _scan_parser.add_argument(
        "--full-port-scan",
        action="store_true",
        dest="full_port_scan",
        help="Scan all TCP ports (1-65535); implies --rescan-ports and can take much longer.",
    )
    _scan_args, _ = _scan_parser.parse_known_args()

    # --- Export sub-command (handled by its own parser) ---
    if "--export" in sys.argv:
        _run_cli_export()
        return

    try:
        config = load_config()
        setup_logging(json_enabled=config.json_logging)
        setup_tracing(
            enabled=config.tracing.enabled,
            service_name=config.tracing.service_name,
            exporter=config.tracing.exporter,
        )
        if _scan_args.once and _scan_args.continuous:
            logger.warning("Both --once and --continuous given; --continuous takes precedence.")
        if _scan_args.continuous:
            config.scan.continuous = True
        elif _scan_args.once:
            config.scan.continuous = False

        rescan_ports = _scan_args.rescan_ports or _scan_args.full_port_scan

        # --rescan-ports implies port scanning is enabled for this run
        if rescan_ports and not config.port_scan.enabled:
            logger.info("Port rescan requested: enabling port scan for this run.")
            config.port_scan.enabled = True
        if _scan_args.full_port_scan:
            logger.info("--full-port-scan given: scanning all TCP ports 1-65535.")
            config.port_scan.enabled = True
            config.port_scan.ports = _FULL_TCP_PORTS
            config.port_scan.max_workers = max(config.port_scan.max_workers, 200)
            config.port_scan.host_workers = max(config.port_scan.host_workers, 4)

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

        run_scan(config, rescan_ports=rescan_ports)
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
