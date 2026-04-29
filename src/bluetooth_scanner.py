"""Bluetooth and BLE device scanner.

Classic Bluetooth scanning uses Windows PowerShell APIs. Linux BLE scanning
uses bleak when `ble_enabled` is set in the application config.

Security: This is purely passive scanning — no pairing or connections
are established with discovered devices.
"""

import asyncio
import json
import logging
import os
import platform
import re
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class BluetoothDevice:
    """A discovered Bluetooth device."""

    mac_address: str
    device_name: str | None = None
    is_connected: bool = False
    is_paired: bool = False
    device_class: str | None = None
    vendor: str | None = None
    is_randomized: bool = False
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Post-initialization: look up vendor and check for randomization."""
        if self.vendor is None and self.mac_address:
            self.vendor = lookup_vendor(self.mac_address)
        if self.mac_address:
            self.is_randomized = is_randomized_mac(self.mac_address)


# PowerShell script to discover Bluetooth devices via PnP / WMI
_BT_DISCOVERY_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$devices = @()

# Method 1: Get-PnpDevice for Bluetooth devices
$btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -and $_.InstanceId -match 'BTHENUM|BTH' }

foreach ($dev in $btDevices) {
    $instanceId = $dev.InstanceId
    $mac = ''

    # Extract MAC from InstanceId (format: BTHENUM\...\XX:XX:XX:XX:XX:XX or similar)
    if ($instanceId -match '([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}') {
        $mac = $matches[0]
    } elseif ($instanceId -match '([0-9A-Fa-f]{12})') {
        $raw = $matches[1]
        $mac = ($raw -replace '(.{2})', '$1:').TrimEnd(':')
    }

    $devices += @{
        Name = $dev.FriendlyName
        MAC = $mac
        Status = $dev.Status
        Class = $dev.Class
        InstanceId = $instanceId
    }
}

# Method 2: WMI Bluetooth devices
$wmiDevices = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
    Where-Object { $_.PNPClass -eq 'Bluetooth' -or $_.Name -match 'Bluetooth' }

foreach ($dev in $wmiDevices) {
    $instanceId = $dev.DeviceID
    $mac = ''

    if ($instanceId -match '([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}') {
        $mac = $matches[0]
    } elseif ($instanceId -match '_([0-9A-Fa-f]{12})') {
        $raw = $matches[1]
        $mac = ($raw -replace '(.{2})', '$1:').TrimEnd(':')
    }

    # Avoid duplicates
    $existing = $devices | Where-Object { $_.MAC -eq $mac -and $mac -ne '' }
    if (-not $existing -and $mac) {
        $devices += @{
            Name = $dev.Name
            MAC = $mac
            Status = $dev.Status
            Class = 'Bluetooth'
            InstanceId = $instanceId
        }
    }
}

$devices | ConvertTo-Json -Depth 3
"""


def scan_bluetooth_devices() -> list[BluetoothDevice]:
    """Scan for nearby/known classic Bluetooth devices on the current platform.

    Returns:
        List of discovered BluetoothDevice objects.

    Raises:
        RuntimeError: If the Windows scan fails completely.
    """
    system_name = platform.system().lower()
    if system_name == "windows":
        return _scan_windows_bluetooth_devices()

    if system_name == "linux":
        if _is_wsl():
            logger.info("Skipping classic Bluetooth scan: direct Bluetooth access is not typically available under WSL")
            return []
        logger.info("Skipping classic Bluetooth scan on Linux; use ble_enabled for BLE discovery")
        return []

    logger.info("Skipping Bluetooth scan: unsupported platform %s", platform.system())
    return []


def _scan_windows_bluetooth_devices() -> list[BluetoothDevice]:
    """Scan for nearby/known Bluetooth devices using Windows APIs."""
    logger.info("Starting Bluetooth device scan...")

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _BT_DISCOVERY_SCRIPT],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        logger.error("PowerShell not found. Bluetooth scanning requires Windows.")
        raise RuntimeError("Bluetooth scanning requires Windows PowerShell.") from None
    except subprocess.TimeoutExpired:
        logger.error("Bluetooth scan timed out after 30 seconds.")
        raise RuntimeError("Bluetooth scan timed out.") from None

    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else ""
        logger.warning("Bluetooth scan had warnings: %s", stderr)

    return _parse_bt_output(result.stdout)


def scan_ble_devices(timeout_seconds: float = 10.0) -> list[BluetoothDevice]:
    """Scan for BLE devices on Linux using bleak.

    Returns:
        List of discovered BluetoothDevice objects.
    """
    if platform.system().lower() != "linux":
        return []
    if _is_wsl():
        logger.info("Skipping BLE scan: direct Bluetooth access is not typically available under WSL")
        return []

    logger.info("Starting BLE device scan...")
    try:
        discovered_devices = _run_ble_discovery(timeout_seconds)
    except ImportError:
        logger.info("Skipping BLE scan: bleak is not installed")
        return []
    except Exception as exc:
        logger.info("Skipping BLE scan: %s", exc)
        return []

    devices = _parse_ble_discovery_results(discovered_devices)
    logger.info("BLE scan complete: found %d devices.", len(devices))
    return devices


async def _discover_ble_devices(timeout_seconds: float) -> list[Any]:
    """Run a bleak discovery round and return the raw device list."""
    from bleak import BleakScanner

    return list(await BleakScanner.discover(timeout=timeout_seconds))


def _run_ble_discovery(timeout_seconds: float) -> list[Any]:
    """Run BLE discovery even when the current thread already has an event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_discover_ble_devices(timeout_seconds))

    result: list[Any] = []
    error: list[BaseException] = []

    def _runner() -> None:
        try:
            result.extend(asyncio.run(_discover_ble_devices(timeout_seconds)))
        except BaseException as exc:  # pragma: no cover - bubbled immediately below
            error.append(exc)

    worker = threading.Thread(target=_runner, daemon=True)
    worker.start()
    worker.join()

    if error:
        raise error[0]

    return result


def _parse_ble_discovery_results(discovered_devices: object) -> list[BluetoothDevice]:
    """Convert bleak discovery output into BluetoothDevice objects."""
    parsed_items: list[tuple[object, object | None]] = []
    if isinstance(discovered_devices, dict):
        for value in discovered_devices.values():
            if isinstance(value, tuple) and value:
                ble_device = value[0]
                advertisement = value[1] if len(value) > 1 else None
                parsed_items.append((ble_device, advertisement))
            else:
                parsed_items.append((value, None))
    elif isinstance(discovered_devices, list):
        parsed_items = [(device, None) for device in discovered_devices]
    else:
        return []

    devices: list[BluetoothDevice] = []
    seen_macs: set[str] = set()

    for ble_device, advertisement in parsed_items:
        mac_address = getattr(ble_device, "address", "")
        if not mac_address:
            continue
        try:
            normalized_mac = normalize_mac(mac_address)
        except ValueError:
            continue
        if normalized_mac in seen_macs:
            continue
        seen_macs.add(normalized_mac)

        device_name = getattr(ble_device, "name", None) or getattr(advertisement, "local_name", None)
        devices.append(
            BluetoothDevice(
                mac_address=normalized_mac,
                device_name=device_name,
                is_connected=False,
                is_paired=False,
                device_class="BLE",
            )
        )

    return devices


def _parse_bt_output(output: str) -> list[BluetoothDevice]:
    """Parse the JSON output from the PowerShell Bluetooth scan.

    Args:
        output: JSON string from PowerShell script.

    Returns:
        List of BluetoothDevice objects.
    """
    output = output.strip()
    if not output:
        logger.info("No Bluetooth devices found.")
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Bluetooth scan output as JSON.")
        logger.debug("Raw output: %s", output[:500])
        return []

    # Ensure we have a list
    if isinstance(data, dict):
        data = [data]

    devices: list[BluetoothDevice] = []
    seen_macs: set[str] = set()

    for item in data:
        device = _parse_bt_device(item, seen_macs)
        if device:
            devices.append(device)

    logger.info("Bluetooth scan complete: found %d devices.", len(devices))
    return devices


def _parse_bt_device(item: object, seen_macs: set[str]) -> BluetoothDevice | None:
    """Parse a single Bluetooth device entry from JSON.

    Args:
        item: Dictionary with device properties.
        seen_macs: Set of already-seen MAC addresses for dedup.

    Returns:
        BluetoothDevice if valid, None otherwise.
    """
    if not isinstance(item, dict):
        return None

    mac = item.get("MAC", "")
    name = item.get("Name", "")
    status = item.get("Status", "")

    if not mac and not name:
        return None

    if _is_bluetooth_adapter(name):
        logger.debug("Skipping Bluetooth adapter: %s", name)
        return None

    if mac:
        try:
            mac = normalize_mac(mac)
        except ValueError:
            logger.debug("Skipping device with invalid MAC: %s", mac)
            return None

        if mac in seen_macs:
            return None
        seen_macs.add(mac)

    return BluetoothDevice(
        mac_address=mac,
        device_name=name or None,
        is_connected=(status == "OK"),
        is_paired=True,
        device_class=item.get("Class"),
    )


def _is_bluetooth_adapter(name: str) -> bool:
    """Check if a device name indicates it's the local Bluetooth adapter.

    Args:
        name: Device friendly name.

    Returns:
        True if this appears to be the local adapter, not a remote device.
    """
    adapter_patterns = [
        r"(?i)bluetooth.*adapter",
        r"(?i)bluetooth.*radio",
        r"(?i)generic.*bluetooth.*adapter",
        r"(?i)intel.*wireless.*bluetooth$",
        r"(?i)realtek.*bluetooth.*adapter",
        r"(?i)qualcomm.*bluetooth.*adapter",
        r"(?i)broadcom.*bluetooth.*adapter",
        r"(?i)microsoft.*bluetooth.*enumerator",
    ]
    return any(re.search(pattern, name) for pattern in adapter_patterns)


def _is_wsl() -> bool:
    """Return True when running under Windows Subsystem for Linux."""
    if platform.system().lower() != "linux":
        return False
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    for version_path in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            with open(version_path, encoding="utf-8") as version_file:
                if "microsoft" in version_file.read().lower():
                    return True
        except OSError:
            continue
    return False
