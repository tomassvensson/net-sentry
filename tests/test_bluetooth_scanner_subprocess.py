"""Tests for Bluetooth scanner subprocess calls (mocked)."""

import types
from unittest.mock import MagicMock, patch

import pytest

from src.bluetooth_scanner import scan_ble_devices, scan_bluetooth_devices


class TestScanBluetoothDevices:
    """Tests for scan_bluetooth_devices with mocked subprocess."""

    @patch("src.bluetooth_scanner.subprocess.run")
    @patch("src.bluetooth_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_successful_scan(self, _mock_platform, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"Name": "Test Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}]',
            stderr="",
        )
        devices = scan_bluetooth_devices()
        assert len(devices) == 1
        assert devices[0].device_name == "Test Phone"

    @patch("src.bluetooth_scanner.subprocess.run")
    @patch("src.bluetooth_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_empty_scan(self, _mock_platform, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        devices = scan_bluetooth_devices()
        assert devices == []

    @patch("src.bluetooth_scanner.subprocess.run")
    @patch("src.bluetooth_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_powershell_not_found(self, _mock_platform, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError()
        with pytest.raises(RuntimeError, match="PowerShell"):
            scan_bluetooth_devices()

    @patch("src.bluetooth_scanner.subprocess.run")
    @patch("src.bluetooth_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_timeout(self, _mock_platform, mock_run) -> None:
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=30)
        with pytest.raises(RuntimeError, match="timed out"):
            scan_bluetooth_devices()

    @patch("src.bluetooth_scanner.subprocess.run")
    @patch("src.bluetooth_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_scan_with_warnings(self, _mock_platform, mock_run) -> None:
        """Scan continues even if PowerShell emits warnings."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='[{"Name": "Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}]',
            stderr="Some warning message",
        )
        devices = scan_bluetooth_devices()
        assert len(devices) == 1

    @patch("src.bluetooth_scanner._is_wsl", return_value=False)
    @patch("src.bluetooth_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_linux_classic_bluetooth_returns_empty(self, _mock_platform, _mock_wsl) -> None:
        assert scan_bluetooth_devices() == []


class TestScanBleDevices:
    """Tests for Linux BLE scanning with mocked bleak discovery."""

    class FakeBleDevice:
        def __init__(self, address: str, name: str | None) -> None:
            self.address = address
            self.name = name

    @patch("src.bluetooth_scanner._is_wsl", return_value=False)
    @patch("src.bluetooth_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_successful_linux_ble_scan(self, _mock_platform, _mock_wsl) -> None:
        outer_self = self

        class FakeBleakScanner:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def discover(self, timeout: float):  # type: ignore[override]
                assert timeout == pytest.approx(3.0)
                return [outer_self.FakeBleDevice("AA:BB:CC:DD:EE:FF", "Sensor")]

        with patch.dict("sys.modules", {"bleak": types.SimpleNamespace(BleakScanner=FakeBleakScanner)}):
            devices = scan_ble_devices(timeout_seconds=3.0)

        assert len(devices) == 1
        assert devices[0].device_name == "Sensor"
        assert devices[0].device_class == "BLE"

    @patch("src.bluetooth_scanner._is_wsl", return_value=False)
    @patch("src.bluetooth_scanner.platform.system", return_value="Linux")
    @patch("src.bluetooth_scanner._discover_ble_devices", side_effect=ImportError())
    @pytest.mark.timeout(30)
    def test_missing_bleak_returns_empty(self, _mock_discover, _mock_platform, _mock_wsl) -> None:
        assert scan_ble_devices() == []

    @patch("src.bluetooth_scanner._is_wsl", return_value=True)
    @patch("src.bluetooth_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_wsl_returns_empty(self, _mock_platform, _mock_wsl) -> None:
        assert scan_ble_devices() == []
