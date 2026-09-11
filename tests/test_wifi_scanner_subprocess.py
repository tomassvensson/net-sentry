"""Tests for WiFi scanner subprocess calls (mocked)."""

from unittest.mock import MagicMock, patch

import pytest

from src.wifi_scanner import get_wifi_interfaces, scan_wifi_networks


class TestScanWifiNetworks:
    """Tests for scan_wifi_networks with mocked subprocess."""

    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_successful_scan(self, _mock_platform, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""
SSID 1 : TestNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 80%
         Radio type         : 802.11ac
         Channel            : 36
""",
            stderr="",
        )
        networks = scan_wifi_networks()
        assert len(networks) == 1
        assert networks[0].ssid == "TestNetwork"

    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_netsh_failure(self, _mock_platform, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        with pytest.raises(RuntimeError, match="WiFi scan failed"):
            scan_wifi_networks()

    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_netsh_not_found(self, _mock_platform, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError()
        with pytest.raises(RuntimeError, match="netsh not found"):
            scan_wifi_networks()

    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Windows")
    @pytest.mark.timeout(30)
    def test_timeout(self, _mock_platform, mock_run) -> None:
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=30)
        with pytest.raises(RuntimeError, match="timed out"):
            scan_wifi_networks()

    @patch("src.wifi_scanner._is_wsl", return_value=False)
    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_linux_nmcli_scan_success(self, _mock_platform, mock_run, _mock_wsl) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""
SSID:LinuxWifi
BSSID:AA:BB:CC:DD:EE:FF
MODE:Infra
CHAN:11
SIGNAL:70
SECURITY:WPA2
""",
            stderr="",
        )
        networks = scan_wifi_networks()
        assert len(networks) == 1
        assert networks[0].ssid == "LinuxWifi"
        assert networks[0].channel == 11

    @patch("src.wifi_scanner._is_wsl", return_value=False)
    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_linux_iw_fallback_success(self, _mock_platform, mock_run, _mock_wsl) -> None:
        mock_run.side_effect = [
            FileNotFoundError(),
            MagicMock(returncode=0, stdout="\tInterface wlan0\n", stderr=""),
            MagicMock(
                returncode=0,
                stdout="""
BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2412
	signal: -55.00 dBm
	SSID:FallbackWifi
	DS Parameter set: channel 1
	RSN:
""",
                stderr="",
            ),
        ]
        networks = scan_wifi_networks()
        assert len(networks) == 1
        assert networks[0].ssid == "FallbackWifi"
        assert networks[0].channel == 1

    @patch("src.wifi_scanner._is_wsl", return_value=False)
    @patch("src.wifi_scanner.subprocess.run")
    @patch("src.wifi_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_linux_no_backend_returns_empty(self, _mock_platform, mock_run, _mock_wsl) -> None:
        mock_run.side_effect = [FileNotFoundError(), FileNotFoundError()]
        assert scan_wifi_networks() == []

    @patch("src.wifi_scanner._is_wsl", return_value=True)
    @patch("src.wifi_scanner.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_wsl_returns_empty(self, _mock_platform, _mock_wsl) -> None:
        assert scan_wifi_networks() == []


class TestGetWifiInterfaces:
    """Tests for get_wifi_interfaces with mocked subprocess."""

    @patch("src.wifi_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_successful_query(self, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""
    Name                   : Wi-Fi
    Description            : Goshyda AR9271
    GUID                   : {12345678-1234-1234-1234-123456789012}
    Physical address       : aa:bb:cc:dd:ee:ff
    State                  : connected
    SSID                   : MyNetwork
    BSSID                  : 11:22:33:44:55:66
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 36
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 866.7
    Signal                 : 95%
""",
            stderr="",
        )
        interfaces = get_wifi_interfaces()
        assert len(interfaces) >= 1

    @patch("src.wifi_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_no_interfaces(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        interfaces = get_wifi_interfaces()
        assert interfaces == []

    @patch("src.wifi_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_command_not_found(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError()
        interfaces = get_wifi_interfaces()
        assert interfaces == []
