"""Tests for WiFi scanner module."""

import pytest

from src.wifi_scanner import (
    WifiNetwork,
    _parse_iw_output,
    _parse_netsh_output,
    _parse_nmcli_output,
    signal_dbm_to_percent,
    signal_percent_to_dbm,
)


class TestSignalPercentToDbm:
    """Tests for signal strength conversion."""

    @pytest.mark.timeout(30)
    def test_zero_percent(self) -> None:
        assert signal_percent_to_dbm(0) == -100.0

    @pytest.mark.timeout(30)
    def test_hundred_percent(self) -> None:
        assert signal_percent_to_dbm(100) == -50.0

    @pytest.mark.timeout(30)
    def test_fifty_percent(self) -> None:
        assert signal_percent_to_dbm(50) == -75.0

    @pytest.mark.timeout(30)
    def test_negative_clamped(self) -> None:
        assert signal_percent_to_dbm(-10) == -100.0

    @pytest.mark.timeout(30)
    def test_over_hundred_clamped(self) -> None:
        assert signal_percent_to_dbm(150) == -50.0


class TestSignalDbmToPercent:
    """Tests for dBm to signal strength conversion."""

    @pytest.mark.timeout(30)
    def test_zero_floor(self) -> None:
        assert signal_dbm_to_percent(-120.0) == 0

    @pytest.mark.timeout(30)
    def test_midpoint(self) -> None:
        assert signal_dbm_to_percent(-75.0) == 50

    @pytest.mark.timeout(30)
    def test_hundred_ceiling(self) -> None:
        assert signal_dbm_to_percent(-20.0) == 100


class TestParseNetshOutput:
    """Tests for netsh output parsing."""

    SAMPLE_OUTPUT = """
There are 3 networks currently visible.

SSID 1 : MyHomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 85%
         Radio type         : 802.11ac
         Channel            : 36

SSID 2 : NeighborWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 45%
         Radio type         : 802.11n
         Channel            : 6
    BSSID 2                 : 11:22:33:44:55:77
         Signal             : 30%
         Radio type         : 802.11n
         Channel            : 11

SSID 3 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 00:14:6c:de:ad:01
         Signal             : 20%
         Radio type         : 802.11g
         Channel            : 1
"""

    @pytest.mark.timeout(30)
    def test_parses_multiple_networks(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        assert len(networks) == 4  # 2 SSIDs with 1 BSSID each + 1 SSID with 2 BSSIDs + 1 hidden

    @pytest.mark.timeout(30)
    def test_parses_ssid(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        ssids = [n.ssid for n in networks]
        assert "MyHomeNetwork" in ssids
        assert "NeighborWiFi" in ssids

    @pytest.mark.timeout(30)
    def test_parses_hidden_ssid(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        hidden = [n for n in networks if n.ssid == "<Hidden>"]
        assert len(hidden) == 1

    @pytest.mark.timeout(30)
    def test_parses_bssid(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        bssids = [n.bssid for n in networks]
        assert "AA:BB:CC:DD:EE:FF" in bssids

    @pytest.mark.timeout(30)
    def test_parses_signal(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        home = next(n for n in networks if n.ssid == "MyHomeNetwork")
        assert home.signal_percent == 85

    @pytest.mark.timeout(30)
    def test_parses_channel(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        home = next(n for n in networks if n.ssid == "MyHomeNetwork")
        assert home.channel == 36

    @pytest.mark.timeout(30)
    def test_parses_radio_type(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        home = next(n for n in networks if n.ssid == "MyHomeNetwork")
        assert home.radio_type == "802.11ac"

    @pytest.mark.timeout(30)
    def test_parses_authentication(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        home = next(n for n in networks if n.ssid == "MyHomeNetwork")
        assert home.authentication == "WPA2-Personal"

    @pytest.mark.timeout(30)
    def test_parses_encryption(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        home = next(n for n in networks if n.ssid == "MyHomeNetwork")
        assert home.encryption == "CCMP"

    @pytest.mark.timeout(30)
    def test_empty_output(self) -> None:
        networks = _parse_netsh_output("")
        assert networks == []

    @pytest.mark.timeout(30)
    def test_no_networks_output(self) -> None:
        networks = _parse_netsh_output("There are 0 networks currently visible.\n")
        assert networks == []

    @pytest.mark.timeout(30)
    def test_vendor_lookup_applied(self) -> None:
        networks = _parse_netsh_output(self.SAMPLE_OUTPUT)
        netgear = [n for n in networks if n.bssid == "00:14:6C:DE:AD:01"]
        assert len(netgear) == 1
        # Should match Netgear from OUI table
        assert netgear[0].vendor is not None


class TestWifiNetworkDataclass:
    """Tests for WifiNetwork dataclass."""

    @pytest.mark.timeout(30)
    def test_creation(self) -> None:
        network = WifiNetwork(
            ssid="Test",
            bssid="AA:BB:CC:DD:EE:FF",
            network_type="Infrastructure",
            authentication="WPA2-Personal",
            encryption="CCMP",
            signal_percent=75,
            signal_dbm=-62.5,
            radio_type="802.11ac",
            channel=36,
        )
        assert network.ssid == "Test"
        assert network.signal_percent == 75

    @pytest.mark.timeout(30)
    def test_vendor_auto_lookup(self) -> None:
        network = WifiNetwork(
            ssid="Test",
            bssid="00:14:6C:00:00:00",  # Netgear OUI
            network_type="Infrastructure",
            authentication="Open",
            encryption="None",
            signal_percent=50,
            signal_dbm=-75.0,
            radio_type="802.11n",
            channel=6,
        )
        assert network.vendor is not None


class TestParseNmcliOutput:
    """Tests for Linux nmcli WiFi parsing."""

    SAMPLE_OUTPUT = """
SSID:MyHomeNetwork
BSSID:AA:BB:CC:DD:EE:FF
MODE:Infra
CHAN:36
SIGNAL:85
SECURITY:WPA2

SSID:
BSSID:00:14:6C:DE:AD:01
MODE:Infra
CHAN:1
SIGNAL:20
SECURITY:
"""

    @pytest.mark.timeout(30)
    def test_parses_nmcli_blocks(self) -> None:
        networks = _parse_nmcli_output(self.SAMPLE_OUTPUT)
        assert len(networks) == 2
        assert networks[0].ssid == "MyHomeNetwork"
        assert networks[0].channel == 36
        assert networks[1].ssid == "<Hidden>"
        assert networks[1].authentication == "Open"
        assert networks[1].encryption == "None"


class TestParseIwOutput:
    """Tests for Linux iw WiFi parsing."""

    SAMPLE_OUTPUT = """
BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 5180
	signal: -42.00 dBm
	SSID: OfficeWiFi
	DS Parameter set: channel 36
	RSN:
		Version: 1

BSS 00:14:6c:de:ad:01(on wlan0)
	freq: 2412
	signal: -70.00 dBm
	SSID:
	capability: ESS Privacy ShortSlotTime (0x0431)
"""

    @pytest.mark.timeout(30)
    def test_parses_iw_blocks(self) -> None:
        networks = _parse_iw_output(self.SAMPLE_OUTPUT)
        assert len(networks) == 2
        assert networks[0].ssid == "OfficeWiFi"
        assert networks[0].channel == 36
        assert networks[0].signal_dbm == pytest.approx(-42.0)
        assert networks[0].authentication == "WPA2"
        assert networks[1].ssid == "<Hidden>"
        assert networks[1].channel == 1
        assert networks[1].authentication == "WEP"
