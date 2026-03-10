"""BtWiFi — Main entry point for the device visibility tracker.

Scans for WiFi networks, Bluetooth devices, and local network devices,
then stores results in the database and displays a human-readable table.
"""

import logging
import re
import signal
import sys
import time
from datetime import datetime

from sqlalchemy import Engine
from sqlalchemy.orm import Session as DbSession
from tabulate import tabulate

from src.alert import AlertManager
from src.bluetooth_scanner import scan_bluetooth_devices
from src.categorizer import categorize_device, get_category_label
from src.config import AppConfig, load_config
from src.database import get_session, init_database
from src.device_tracker import (
    get_all_devices_with_latest_window,
    track_bluetooth_scan,
    track_wifi_scan,
    update_visibility,
)
from src.mdns_scanner import MdnsDevice
from src.models import Device
from src.network_discovery import NetworkDevice, scan_arp_table
from src.oui_lookup import is_randomized_mac
from src.ssdp_scanner import SsdpDevice
from src.whitelist import WhitelistManager
from src.wifi_scanner import scan_wifi_networks

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


def run_scan(config: AppConfig | None = None) -> None:
    """Run a complete scan cycle: WiFi, Bluetooth, ARP, mDNS, SSDP.

    When continuous mode is enabled, repeats scans at the configured
    interval until interrupted.

    Args:
        config: Application configuration. If None, loads from file/defaults.
    """
    if config is None:
        config = load_config()

    logger.info("=" * 60)
    logger.info("BtWiFi Device Visibility Tracker — Starting scan")
    logger.info("=" * 60)

    engine = init_database(config.database.url)

    whitelist = WhitelistManager(config)
    alert_mgr = AlertManager(config.alert)

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
            _run_single_scan(engine, config, whitelist, alert_mgr)

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
        _run_single_scan(engine, config, whitelist, alert_mgr)


def _run_single_scan(
    engine: Engine,
    config: AppConfig,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
) -> None:
    """Execute one scan cycle across all enabled scanners.

    Args:
        engine: SQLAlchemy engine.
        config: Application configuration.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
    """
    gap = config.scan.gap_seconds

    # ---- WiFi Scan ----
    wifi_networks = []
    if config.scan.wifi_enabled:
        try:
            wifi_networks = scan_wifi_networks()
        except RuntimeError as exc:
            logger.error("WiFi scan failed: %s", exc)

    # ---- Bluetooth Scan ----
    bt_devices = []
    if config.scan.bluetooth_enabled:
        try:
            bt_devices = scan_bluetooth_devices()
        except RuntimeError as exc:
            logger.error("Bluetooth scan failed: %s", exc)

    # ---- ARP / Network Discovery ----
    arp_devices = []
    if config.scan.arp_enabled:
        try:
            arp_devices = scan_arp_table()
        except Exception as exc:
            logger.error("ARP scan failed: %s", exc)

    # ---- mDNS Discovery ----
    mdns_devices = []
    if config.scan.mdns_enabled:
        try:
            from src.mdns_scanner import scan_mdns_services

            mdns_devices = scan_mdns_services()
        except Exception as exc:
            logger.error("mDNS discovery failed: %s", exc)

    # ---- SSDP Discovery ----
    ssdp_devices = []
    if config.scan.ssdp_enabled:
        try:
            from src.ssdp_scanner import scan_ssdp_devices

            ssdp_devices = scan_ssdp_devices()
        except Exception as exc:
            logger.error("SSDP discovery failed: %s", exc)

    # ---- NetBIOS ----
    netbios_names: dict[str, str] = {}
    if config.scan.netbios_enabled and arp_devices:
        try:
            from src.netbios_scanner import resolve_netbios_names

            ips = [d.ip_address for d in arp_devices]
            nb_infos = resolve_netbios_names(ips)
            for nb in nb_infos:
                netbios_names[nb.ip_address] = nb.netbios_name
        except Exception as exc:
            logger.error("NetBIOS resolution failed: %s", exc)

    # ---- Store results ----
    with get_session(engine) as session:
        # Track WiFi
        wifi_results = track_wifi_scan(session, wifi_networks, gap_seconds=gap)
        logger.info("Tracked %d WiFi networks.", len(wifi_results))

        # Track Bluetooth
        bt_results = track_bluetooth_scan(session, bt_devices, gap_seconds=gap)
        logger.info("Tracked %d Bluetooth devices.", len(bt_results))

        # Track ARP devices
        for arp_dev in arp_devices:
            _upsert_network_device(session, arp_dev, whitelist, alert_mgr, netbios_names, gap)

        # Track mDNS devices (enrich or create)
        for mdns_dev in mdns_devices:
            _upsert_mdns_device(session, mdns_dev, whitelist, alert_mgr, gap)

        # Track SSDP devices (enrich or create)
        for ssdp_dev in ssdp_devices:
            _upsert_ssdp_device(session, ssdp_dev, whitelist, alert_mgr, gap)

        # Categorize and tag all devices
        _categorize_all_devices(session, whitelist)

        # Alert for new WiFi devices
        for device, _window in wifi_results:
            if device.created_at == device.updated_at:
                alert_mgr.on_new_device(
                    mac_address=device.mac_address,
                    device_type=device.device_type,
                    vendor=device.vendor,
                    device_name=device.device_name,
                    is_whitelisted=whitelist.is_known(device.mac_address),
                )

        # Alert for new BT devices
        for device, _window in bt_results:
            if device.created_at == device.updated_at:
                alert_mgr.on_new_device(
                    mac_address=device.mac_address,
                    device_type=device.device_type,
                    vendor=device.vendor,
                    device_name=device.device_name,
                    is_whitelisted=whitelist.is_known(device.mac_address),
                )

        session.flush()
        _display_results(session, whitelist)


def _upsert_network_device(
    session: DbSession,
    arp_dev: NetworkDevice,
    whitelist: WhitelistManager,
    alert_mgr: AlertManager,
    netbios_names: dict[str, str],
    gap_seconds: int,
) -> None:
    """Insert/update a network device from ARP scan.

    Args:
        session: Database session.
        arp_dev: NetworkDevice from ARP scan.
        whitelist: Whitelist manager.
        alert_mgr: Alert manager.
        netbios_names: Map of IP to NetBIOS name.
        gap_seconds: Visibility gap threshold.
    """
    existing = session.query(Device).filter_by(mac_address=arp_dev.mac_address).first()

    # Resolve NetBIOS name
    nb_name = netbios_names.get(arp_dev.ip_address, "")
    hostname = arp_dev.hostname or nb_name or None

    if existing is None:
        device = Device(
            mac_address=arp_dev.mac_address,
            device_type="network",
            vendor=arp_dev.vendor,
            device_name=hostname,
            hostname=hostname,
            ip_address=arp_dev.ip_address,
            extra_info=f"IP: {arp_dev.ip_address}",
        )
        session.add(device)

        alert_mgr.on_new_device(
            mac_address=arp_dev.mac_address,
            device_type="network",
            vendor=arp_dev.vendor,
            device_name=hostname,
            is_whitelisted=whitelist.is_known(arp_dev.mac_address),
        )
    else:
        existing.device_name = hostname or existing.device_name
        existing.hostname = hostname or existing.hostname
        existing.vendor = arp_dev.vendor or existing.vendor
        existing.ip_address = arp_dev.ip_address
        if arp_dev.ip_address:
            existing.extra_info = f"IP: {arp_dev.ip_address}"

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

    headers = [
        "Type",
        "Category",
        "Name / SSID",
        "Vendor",
        "MAC Address",
        "Signal",
        "First Seen",
        "Last Seen",
        "Details",
    ]

    rows = []
    for device, window in results:
        type_label = {
            "wifi_ap": "WiFi AP",
            "wifi_client": "WiFi Client",
            "bluetooth": "Bluetooth",
            "network": "Network",
        }.get(device.device_type, device.device_type)

        category = get_category_label(device.category) if device.category else ""
        name = _best_name(device, whitelist)
        vendor = _friendly_vendor(device.vendor, device.mac_address)
        mac = device.mac_address

        if device.is_whitelisted:
            name = f"✓ {name}"

        signal_str = _format_signal(window.signal_strength_dbm if window else None)
        first_seen = _format_time(window.first_seen if window else None)
        last_seen = _format_time(window.last_seen if window else None)

        details_parts = []
        if device.authentication and device.authentication != "Open":
            details_parts.append(f"Auth: {device.authentication}")
        if device.encryption and device.encryption != "None":
            details_parts.append(f"Enc: {device.encryption}")
        if device.radio_type:
            details_parts.append(device.radio_type)
        if device.channel:
            details_parts.append(f"Ch {device.channel}")
        if device.extra_info:
            details_parts.append(device.extra_info)

        details = " | ".join(details_parts) if details_parts else ""

        rows.append([type_label, category, name, vendor, mac, signal_str, first_seen, last_seen, details])

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
    """Main entry point."""
    try:
        config = load_config()
        run_scan(config)
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(0)
    except Exception:
        logger.exception("Fatal error during scan.")
        sys.exit(1)


if __name__ == "__main__":
    main()
