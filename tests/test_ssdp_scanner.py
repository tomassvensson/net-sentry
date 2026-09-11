"""Tests for SSDP/UPnP scanner module."""

from unittest.mock import MagicMock, patch

import pytest

from src.ssdp_scanner import SsdpDevice, _parse_ssdp_response


class TestSsdpDevice:
    """Tests for SsdpDevice dataclass."""

    @pytest.mark.timeout(30)
    def test_defaults(self) -> None:
        dev = SsdpDevice(ip_address="192.168.1.10")
        assert dev.ip_address == "192.168.1.10"
        assert dev.mac_address == ""
        assert dev.server == ""
        assert dev.location == ""
        assert dev.usn == ""
        assert dev.vendor is None
        assert dev.is_randomized is False

    @pytest.mark.timeout(30)
    def test_custom_values(self) -> None:
        dev = SsdpDevice(
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:DD:EE:FF",
            server="Linux/4.14 UPnP/1.0",
            location="http://192.168.1.1:80/desc.xml",
        )
        assert dev.server == "Linux/4.14 UPnP/1.0"
        assert dev.location == "http://192.168.1.1:80/desc.xml"


class TestParseSsdpResponse:
    """Tests for SSDP response parsing."""

    @patch("src.ssdp_scanner._arp_lookup_mac", return_value="AA:BB:CC:DD:EE:FF")
    @patch("src.ssdp_scanner.lookup_vendor", return_value="TestVendor")
    @patch("src.ssdp_scanner.is_randomized_mac", return_value=False)
    @pytest.mark.timeout(30)
    def test_valid_response(self, mock_rand, mock_vendor, mock_arp) -> None:
        response = (
            "HTTP/1.1 200 OK\r\n"
            "SERVER: Linux/4.14 UPnP/1.0 MyProduct/1.0\r\n"
            "LOCATION: http://192.168.1.1:80/desc.xml\r\n"
            "USN: uuid:abc-123::upnp:rootdevice\r\n"
            "ST: ssdp:all\r\n"
        )
        device = _parse_ssdp_response("192.168.1.1", response)
        assert device is not None
        assert device.ip_address == "192.168.1.1"
        assert "Linux" in device.server
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert device.vendor == "TestVendor"

    @patch("src.ssdp_scanner._arp_lookup_mac", return_value="")
    @pytest.mark.timeout(30)
    def test_no_mac_found(self, mock_arp) -> None:
        response = "HTTP/1.1 200 OK\r\nSERVER: Test/1.0\r\n"
        device = _parse_ssdp_response("192.168.1.1", response)
        assert device is not None
        assert device.mac_address == ""
        assert device.vendor is None

    @patch("src.ssdp_scanner._arp_lookup_mac", return_value="")
    @pytest.mark.timeout(30)
    def test_empty_response(self, mock_arp) -> None:
        device = _parse_ssdp_response("192.168.1.1", "")
        assert device is not None
        assert device.server == ""


class TestScanSsdpDevices:
    """Tests for scan_ssdp_devices function."""

    @patch("socket.socket")
    @pytest.mark.timeout(30)
    def test_timeout_returns_empty(self, mock_socket_cls) -> None:
        from src.ssdp_scanner import scan_ssdp_devices

        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError()

        result = scan_ssdp_devices(timeout=0.1)
        assert result == []

    @patch("socket.socket")
    @pytest.mark.timeout(30)
    def test_os_error_returns_empty(self, mock_socket_cls) -> None:
        from src.ssdp_scanner import scan_ssdp_devices

        mock_socket_cls.side_effect = OSError("socket failed")

        result = scan_ssdp_devices(timeout=0.1)
        assert result == []


class TestArpLookupMac:
    """Tests for SSDP _arp_lookup_mac."""

    @patch("subprocess.run")
    @pytest.mark.timeout(30)
    def test_found_mac(self, mock_run) -> None:
        from src.ssdp_scanner import _arp_lookup_mac

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  192.168.1.10  aa-bb-cc-dd-ee-ff  dynamic",
        )
        result = _arp_lookup_mac("192.168.1.10")
        assert result == "AA:BB:CC:DD:EE:FF"

    @patch("subprocess.run")
    @pytest.mark.timeout(30)
    def test_not_found(self, mock_run) -> None:
        from src.ssdp_scanner import _arp_lookup_mac

        mock_run.return_value = MagicMock(returncode=1, stdout="")
        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""

    @patch("subprocess.run", side_effect=Exception("fail"))
    @pytest.mark.timeout(30)
    def test_exception(self, mock_run) -> None:
        from src.ssdp_scanner import _arp_lookup_mac

        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""
