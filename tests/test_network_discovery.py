"""Tests for network discovery (ARP scanning) module."""

import pytest

from src.network_discovery import (
    NetworkDevice,
    _parse_arp_output,
    _parse_linux_routing_table,
    _parse_windows_routing_table,
    discover_subnets_from_routing_table,
)


class TestParseArpOutput:
    """Tests for ARP output parsing."""

    SAMPLE_OUTPUT = """
Interface: 192.168.1.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.2           aa-bb-cc-dd-ee-f1     dynamic
  192.168.1.3           10-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.2.1 --- 0x8
  Internet Address      Physical Address      Type
  192.168.2.5           aa-bb-cc-dd-ee-f2     dynamic
"""

    @pytest.mark.timeout(30)
    def test_parses_dynamic_entries(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        # Should find 3 unicast devices (broadcast ff-ff and multicast 01-00-5e excluded)
        assert len(devices) == 3

    @pytest.mark.timeout(30)
    def test_skips_broadcast(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        macs = [d.mac_address for d in devices]
        assert "FF:FF:FF:FF:FF:FF" not in macs

    @pytest.mark.timeout(30)
    def test_skips_multicast(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        macs = [d.mac_address for d in devices]
        # 01:00:5E is multicast
        assert not any(m.startswith("01:") for m in macs)

    @pytest.mark.timeout(30)
    def test_normalizes_mac(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        assert any(d.mac_address == "AA:BB:CC:DD:EE:F1" for d in devices)

    @pytest.mark.timeout(30)
    def test_captures_ip(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        device = next(d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:F1")
        assert device.ip_address == "192.168.1.2"

    @pytest.mark.timeout(30)
    def test_captures_interface(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        d1 = next(d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:F1")
        assert d1.interface == "192.168.1.1"

    @pytest.mark.timeout(30)
    def test_deduplicates_by_mac(self) -> None:
        dup_output = """
Interface: 192.168.1.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.2           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.3           aa-bb-cc-dd-ee-ff     dynamic
"""
        devices = _parse_arp_output(dup_output)
        assert len(devices) == 1

    @pytest.mark.timeout(30)
    def test_empty_output(self) -> None:
        devices = _parse_arp_output("")
        assert devices == []


class TestNetworkDeviceDataclass:
    """Tests for NetworkDevice dataclass."""

    @pytest.mark.timeout(30)
    def test_creation(self) -> None:
        device = NetworkDevice(
            ip_address="192.168.1.2",
            mac_address="AA:BB:CC:DD:EE:FF",
        )
        assert device.ip_address == "192.168.1.2"
        assert device.arp_type == "dynamic"

    @pytest.mark.timeout(30)
    def test_vendor_auto_lookup(self) -> None:
        device = NetworkDevice(
            ip_address="192.168.1.2",
            mac_address="AC:BC:32:00:00:00",  # Apple OUI
        )
        assert device.vendor is not None
        assert "Apple" in device.vendor


class TestDiscoverSubnetsFromRoutingTable:
    """Tests for automatic subnet discovery from the OS routing table (F)."""

    @pytest.mark.timeout(30)
    def test_parse_linux_routing_table_basic(self) -> None:
        from unittest.mock import patch

        fake_output = (
            "default via 192.168.1.1 dev eth0\n"
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100\n"
            "10.0.0.0/8 dev tun0 proto kernel scope link src 10.8.0.1\n"
        )
        with patch("src.network_discovery.subprocess.run") as mock_run:
            mock_run.return_value.stdout = fake_output
            mock_run.return_value.returncode = 0
            result = _parse_linux_routing_table()

        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result
        # default route must be excluded
        assert "0.0.0.0/0" not in result

    @pytest.mark.timeout(30)
    def test_parse_linux_routing_table_skips_small_prefix(self) -> None:
        from unittest.mock import patch

        fake_output = "1.0.0.0/4 dev lo proto kernel scope link\n"
        with patch("src.network_discovery.subprocess.run") as mock_run:
            mock_run.return_value.stdout = fake_output
            mock_run.return_value.returncode = 0
            result = _parse_linux_routing_table()

        # prefix < /8 should be excluded
        assert result == []

    @pytest.mark.timeout(30)
    def test_parse_linux_routing_table_command_not_found(self) -> None:
        from unittest.mock import patch

        with patch("src.network_discovery.subprocess.run", side_effect=FileNotFoundError):
            result = _parse_linux_routing_table()
        assert result == []

    @pytest.mark.timeout(30)
    def test_parse_windows_routing_table_basic(self) -> None:
        from unittest.mock import patch

        fake_output = (
            "===========================================================================\n"
            "IPv4 Route Table\n"
            "===========================================================================\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.50     25\n"
            "        192.168.1.0    255.255.255.0         On-link   192.168.1.50    281\n"
            "         10.10.0.0      255.255.0.0         On-link     10.10.0.1     35\n"
        )
        with patch("src.network_discovery.subprocess.run") as mock_run:
            mock_run.return_value.stdout = fake_output
            mock_run.return_value.returncode = 0
            result = _parse_windows_routing_table()

        assert "192.168.1.0/24" in result
        assert "10.10.0.0/16" in result
        assert "0.0.0.0/0" not in result

    @pytest.mark.timeout(30)
    def test_parse_windows_routing_table_command_not_found(self) -> None:
        from unittest.mock import patch

        with patch("src.network_discovery.subprocess.run", side_effect=FileNotFoundError):
            result = _parse_windows_routing_table()
        assert result == []

    @pytest.mark.timeout(30)
    def test_discover_subnets_from_routing_table_delegates_by_os(self) -> None:
        """discover_subnets_from_routing_table() calls the right OS parser."""
        from unittest.mock import patch

        with (
            patch("src.network_discovery.platform.system", return_value="Windows"),
            patch("src.network_discovery._parse_windows_routing_table", return_value=["192.168.0.0/24"]) as mock_win,
        ):
            result = discover_subnets_from_routing_table()
        mock_win.assert_called_once()
        assert result == ["192.168.0.0/24"]

        with (
            patch("src.network_discovery.platform.system", return_value="Linux"),
            patch("src.network_discovery._parse_linux_routing_table", return_value=["10.0.0.0/8"]) as mock_lin,
        ):
            result = discover_subnets_from_routing_table()
        mock_lin.assert_called_once()
        assert result == ["10.0.0.0/8"]
