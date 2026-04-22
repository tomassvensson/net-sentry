"""Device visibility tracking logic.

Manages the lifecycle of visibility windows — when a device is seen,
the current window is extended; when it disappears for longer than
the configured gap, a new window is created.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from src.bluetooth_scanner import BluetoothDevice
from src.models import Device, VisibilityWindow
from src.wifi_scanner import WifiNetwork

logger = logging.getLogger(__name__)

# If a device is not seen for this many seconds, a new visibility window starts
DEFAULT_GAP_SECONDS = 300  # 5 minutes


def upsert_wifi_device(session: Session, network: WifiNetwork) -> Device:
    """Insert or update a WiFi device record.

    Args:
        session: Active database session.
        network: Scanned WiFi network data.

    Returns:
        The Device record (new or updated).
    """
    device = session.query(Device).filter_by(mac_address=network.bssid).first()

    if device is None:
        device = Device(
            mac_address=network.bssid,
            device_type="wifi_ap",
            vendor=network.vendor,
            device_name=network.device_name,
            ssid=network.ssid,
            network_type=network.network_type,
            authentication=network.authentication,
            encryption=network.encryption,
            radio_type=network.radio_type,
            channel=network.channel,
        )
        session.add(device)
        logger.info("New WiFi device: %s (%s) — %s", network.bssid, network.vendor or "Unknown", network.ssid)
    else:
        # Update mutable fields
        device.ssid = network.ssid or device.ssid
        device.vendor = network.vendor or device.vendor
        device.device_name = network.device_name or device.device_name
        device.network_type = network.network_type or device.network_type
        device.authentication = network.authentication or device.authentication
        device.encryption = network.encryption or device.encryption
        device.radio_type = network.radio_type or device.radio_type
        device.channel = network.channel or device.channel

    return device


def upsert_bluetooth_device(session: Session, bt_device: BluetoothDevice) -> Device | None:
    """Insert or update a Bluetooth device record.

    Args:
        session: Active database session.
        bt_device: Scanned Bluetooth device data.

    Returns:
        The Device record (new or updated), or None if MAC is missing.
    """
    if not bt_device.mac_address:
        logger.debug("Skipping Bluetooth device without MAC: %s", bt_device.device_name)
        return None

    device = session.query(Device).filter_by(mac_address=bt_device.mac_address).first()

    if device is None:
        device = Device(
            mac_address=bt_device.mac_address,
            device_type="bluetooth",
            vendor=bt_device.vendor,
            device_name=bt_device.device_name,
        )
        session.add(device)
        logger.info(
            "New Bluetooth device: %s (%s) — %s",
            bt_device.mac_address,
            bt_device.vendor or "Unknown",
            bt_device.device_name or "N/A",
        )
    else:
        device.vendor = bt_device.vendor or device.vendor
        device.device_name = bt_device.device_name or device.device_name

    return device


def update_visibility(
    session: Session,
    mac_address: str,
    scan_time: datetime,
    signal_dbm: float | None = None,
    gap_seconds: int = DEFAULT_GAP_SECONDS,
) -> tuple[VisibilityWindow, bool]:
    """Update or create a visibility window for a device.

    If the device was last seen within `gap_seconds`, extend the current
    window. Otherwise, create a new window.

    Args:
        session: Active database session.
        mac_address: Device MAC address.
        scan_time: Time of the current scan.
        signal_dbm: Signal strength in dBm (if available).
        gap_seconds: Max gap in seconds before starting a new window.

    Returns:
        Tuple of (VisibilityWindow, is_new_window) where is_new_window is True
        when a new window was created (i.e. the device reconnected).
    """
    cutoff = scan_time - timedelta(seconds=gap_seconds)

    # Find the most recent open window for this device
    window = (
        session.query(VisibilityWindow)
        .filter(
            VisibilityWindow.mac_address == mac_address,
            VisibilityWindow.last_seen >= cutoff,
        )
        .order_by(VisibilityWindow.last_seen.desc())
        .first()
    )

    if window is not None:
        # Extend existing window
        window.last_seen = scan_time
        window.scan_count += 1
        if signal_dbm is not None:
            window.signal_strength_dbm = signal_dbm
            if window.min_signal_dbm is None or signal_dbm < window.min_signal_dbm:
                window.min_signal_dbm = signal_dbm
            if window.max_signal_dbm is None or signal_dbm > window.max_signal_dbm:
                window.max_signal_dbm = signal_dbm
        return window, False
    else:
        # Create new visibility window
        window = VisibilityWindow(
            mac_address=mac_address,
            first_seen=scan_time,
            last_seen=scan_time,
            signal_strength_dbm=signal_dbm,
            min_signal_dbm=signal_dbm,
            max_signal_dbm=signal_dbm,
            scan_count=1,
        )
        session.add(window)
        return window, True


def track_wifi_scan(
    session: Session,
    networks: list[WifiNetwork],
    gap_seconds: int = DEFAULT_GAP_SECONDS,
) -> list[tuple[Device, VisibilityWindow]]:
    """Process a WiFi scan result: update devices and visibility windows.

    Args:
        session: Active database session.
        networks: List of scanned WiFi networks.
        gap_seconds: Max gap seconds for visibility windows.

    Returns:
        List of (Device, VisibilityWindow) tuples for each network.
    """
    results: list[tuple[Device, VisibilityWindow]] = []
    for network in networks:
        device = upsert_wifi_device(session, network)
        window, is_new = update_visibility(
            session,
            mac_address=network.bssid,
            scan_time=network.scan_time,
            signal_dbm=network.signal_dbm,
            gap_seconds=gap_seconds,
        )
        if is_new and device.reconnect_count is not None:
            device.reconnect_count += 1
        results.append((device, window))
    return results


def track_bluetooth_scan(
    session: Session,
    bt_devices: list[BluetoothDevice],
    gap_seconds: int = DEFAULT_GAP_SECONDS,
) -> list[tuple[Device, VisibilityWindow]]:
    """Process a Bluetooth scan result: update devices and visibility windows.

    Args:
        session: Active database session.
        bt_devices: List of scanned Bluetooth devices.
        gap_seconds: Max gap seconds for visibility windows.

    Returns:
        List of (Device, VisibilityWindow) tuples for each device.
    """
    results: list[tuple[Device, VisibilityWindow]] = []
    for bt_device in bt_devices:
        device = upsert_bluetooth_device(session, bt_device)
        if device is None:
            continue
        window, is_new = update_visibility(
            session,
            mac_address=bt_device.mac_address,
            scan_time=bt_device.scan_time,
            signal_dbm=None,  # Bluetooth signal not available from PnP scan
            gap_seconds=gap_seconds,
        )
        if is_new and device.reconnect_count is not None:
            device.reconnect_count += 1
        results.append((device, window))
    return results


def get_all_devices_with_latest_window(
    session: Session,
) -> list[tuple[Device, VisibilityWindow | None]]:
    """Get all devices with their most recent visibility window.

    Args:
        session: Active database session.

    Returns:
        List of (Device, VisibilityWindow or None) tuples.
    """
    devices = session.query(Device).order_by(Device.device_type, Device.mac_address).all()
    results: list[tuple[Device, VisibilityWindow | None]] = []

    for device in devices:
        window = (
            session.query(VisibilityWindow)
            .filter_by(mac_address=device.mac_address)
            .order_by(VisibilityWindow.last_seen.desc())
            .first()
        )
        results.append((device, window))

    return results
