"""Tests for Bluetooth scanner module."""

import pytest

from src.bluetooth_scanner import (
    BluetoothDevice,
    _is_bluetooth_adapter,
    _parse_ble_discovery_results,
    _parse_bt_output,
)


class TestParseBtOutput:
    """Tests for Bluetooth JSON output parsing."""

    @pytest.mark.timeout(30)
    def test_empty_output(self) -> None:
        devices = _parse_bt_output("")
        assert devices == []

    @pytest.mark.timeout(30)
    def test_single_device(self) -> None:
        json_str = '[{"Name": "My Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}]'
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1
        assert devices[0].device_name == "My Phone"
        assert devices[0].mac_address == "AA:BB:CC:DD:EE:FF"
        assert devices[0].is_connected is True

    @pytest.mark.timeout(30)
    def test_single_device_as_object(self) -> None:
        """PowerShell outputs a single object (not array) when there's only one result."""
        json_str = '{"Name": "My Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}'
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1
        assert devices[0].device_name == "My Phone"

    @pytest.mark.timeout(30)
    def test_multiple_devices(self) -> None:
        json_str = """[
            {"Name": "Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"},
            {"Name": "Headphones", "MAC": "11:22:33:44:55:66", "Status": "Error", "Class": "Bluetooth"}
        ]"""
        devices = _parse_bt_output(json_str)
        assert len(devices) == 2

    @pytest.mark.timeout(30)
    def test_skips_adapter(self) -> None:
        json_str = """[
            {"Name": "Intel Wireless Bluetooth", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"},
            {"Name": "My Phone", "MAC": "11:22:33:44:55:66", "Status": "OK", "Class": "Bluetooth"}
        ]"""
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1
        assert devices[0].device_name == "My Phone"

    @pytest.mark.timeout(30)
    def test_deduplicates_by_mac(self) -> None:
        json_str = """[
            {"Name": "Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"},
            {"Name": "Phone (2)", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}
        ]"""
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1

    @pytest.mark.timeout(30)
    def test_invalid_json(self) -> None:
        devices = _parse_bt_output("not valid json")
        assert devices == []

    @pytest.mark.timeout(30)
    def test_skips_no_mac_no_name(self) -> None:
        json_str = '[{"MAC": "", "Name": "", "Status": "OK"}]'
        devices = _parse_bt_output(json_str)
        assert devices == []


class TestIsBluetoothAdapter:
    """Tests for Bluetooth adapter detection."""

    @pytest.mark.timeout(30)
    def test_intel_adapter(self) -> None:
        assert _is_bluetooth_adapter("Intel Wireless Bluetooth") is True

    @pytest.mark.timeout(30)
    def test_generic_adapter(self) -> None:
        assert _is_bluetooth_adapter("Generic Bluetooth Adapter") is True

    @pytest.mark.timeout(30)
    def test_realtek_adapter(self) -> None:
        assert _is_bluetooth_adapter("Realtek Bluetooth Adapter") is True

    @pytest.mark.timeout(30)
    def test_microsoft_enumerator(self) -> None:
        assert _is_bluetooth_adapter("Microsoft Bluetooth Enumerator") is True

    @pytest.mark.timeout(30)
    def test_regular_device(self) -> None:
        assert _is_bluetooth_adapter("My Phone") is False

    @pytest.mark.timeout(30)
    def test_headphones(self) -> None:
        assert _is_bluetooth_adapter("Sony WH-1000XM5") is False

    @pytest.mark.timeout(30)
    def test_bluetooth_keyboard(self) -> None:
        assert _is_bluetooth_adapter("Bluetooth Keyboard") is False

    @pytest.mark.timeout(30)
    def test_bluetooth_radio(self) -> None:
        assert _is_bluetooth_adapter("Bluetooth Radio") is True


class TestBluetoothDeviceDataclass:
    """Tests for BluetoothDevice dataclass."""

    @pytest.mark.timeout(30)
    def test_creation(self) -> None:
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_name="Test Device",
        )
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert device.device_name == "Test Device"

    @pytest.mark.timeout(30)
    def test_vendor_auto_lookup(self) -> None:
        device = BluetoothDevice(
            mac_address="AC:BC:32:00:00:00",  # Apple OUI
        )
        assert device.vendor is not None
        assert "Apple" in device.vendor


class TestParseBleDiscoveryResults:
    """Tests for Linux BLE discovery parsing."""

    class FakeBleDevice:
        def __init__(self, address: str, name: str | None) -> None:
            self.address = address
            self.name = name

    class FakeAdvertisement:
        def __init__(self, local_name: str | None) -> None:
            self.local_name = local_name

    @pytest.mark.timeout(30)
    def test_parses_list_of_ble_devices(self) -> None:
        devices = _parse_ble_discovery_results(
            [
                self.FakeBleDevice("AA:BB:CC:DD:EE:FF", "Beacon"),
                self.FakeBleDevice("11:22:33:44:55:66", None),
            ]
        )
        assert len(devices) == 2
        assert devices[0].device_name == "Beacon"
        assert devices[0].device_class == "BLE"

    @pytest.mark.timeout(30)
    def test_uses_advertisement_name_when_device_name_missing(self) -> None:
        devices = _parse_ble_discovery_results(
            {
                "device": (
                    self.FakeBleDevice("AA:BB:CC:DD:EE:FF", None),
                    self.FakeAdvertisement("Tag"),
                )
            }
        )
        assert len(devices) == 1
        assert devices[0].device_name == "Tag"

    @pytest.mark.timeout(30)
    def test_deduplicates_by_mac(self) -> None:
        devices = _parse_ble_discovery_results(
            [
                self.FakeBleDevice("AA:BB:CC:DD:EE:FF", "One"),
                self.FakeBleDevice("AA:BB:CC:DD:EE:FF", "Two"),
            ]
        )
        assert len(devices) == 1
