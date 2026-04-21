"""Tests for network discovery subprocess calls (mocked)."""

import socket
import subprocess
from unittest.mock import MagicMock, patch

from src.network_discovery import (
    _ip_to_pseudo_mac,
    _parse_ip_neigh_output,
    _ping_host,
    _resolve_hostname,
    ping_sweep,
    scan_arp_table,
)

_WINDOWS_ARP_OUTPUT = """
Interface: 192.168.1.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.2           aa-bb-cc-dd-ee-f0     dynamic
"""

_LINUX_IP_NEIGH_OUTPUT = """
192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:f0 REACHABLE
192.168.1.3 dev eth0 lladdr 10:22:33:44:55:66 STALE
192.168.1.4 dev eth0 lladdr aa:bb:cc:dd:ee:f1 FAILED
192.168.1.255 dev eth0 lladdr ff:ff:ff:ff:ff:ff REACHABLE
192.168.1.5 dev eth0 lladdr 01:00:5e:00:00:16 REACHABLE
"""


class TestScanArpTableWindows:
    """Tests for scan_arp_table on Windows (mocked platform)."""

    @patch("src.network_discovery.platform.system", return_value="Windows")
    @patch("src.network_discovery._resolve_hostname")
    @patch("src.network_discovery.subprocess.run")
    def test_successful_scan(self, mock_run, mock_resolve, mock_system) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_WINDOWS_ARP_OUTPUT,
            stderr="",
        )
        mock_resolve.return_value = "my-laptop.local"

        devices = scan_arp_table()
        assert len(devices) == 1
        assert devices[0].hostname == "my-laptop.local"

    @patch("src.network_discovery.platform.system", return_value="Windows")
    @patch("src.network_discovery.subprocess.run")
    def test_command_not_found(self, mock_run, mock_system) -> None:
        mock_run.side_effect = FileNotFoundError()
        devices = scan_arp_table()
        assert devices == []

    @patch("src.network_discovery.platform.system", return_value="Windows")
    @patch("src.network_discovery.subprocess.run")
    def test_timeout(self, mock_run, mock_system) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="arp", timeout=15)
        devices = scan_arp_table()
        assert devices == []

    @patch("src.network_discovery.platform.system", return_value="Windows")
    @patch("src.network_discovery.subprocess.run")
    def test_command_failure(self, mock_run, mock_system) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        devices = scan_arp_table()
        assert devices == []


class TestScanArpTableLinux:
    """Tests for scan_arp_table on Linux (mocked platform)."""

    @patch("src.network_discovery.platform.system", return_value="Linux")
    @patch("src.network_discovery._resolve_hostname")
    @patch("src.network_discovery.subprocess.run")
    def test_successful_scan_linux(self, mock_run, mock_resolve, mock_system) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_LINUX_IP_NEIGH_OUTPUT,
            stderr="",
        )
        mock_resolve.return_value = "my-device.local"

        devices = scan_arp_table()
        # FAILED and broadcast ff:ff and multicast 01:00 are skipped → 2 devices
        assert len(devices) == 2
        assert devices[0].hostname == "my-device.local"

    @patch("src.network_discovery.platform.system", return_value="Linux")
    @patch("src.network_discovery.subprocess.run")
    def test_linux_command_not_found(self, mock_run, mock_system) -> None:
        mock_run.side_effect = FileNotFoundError()
        devices = scan_arp_table()
        assert devices == []

    @patch("src.network_discovery.platform.system", return_value="Linux")
    @patch("src.network_discovery.subprocess.run")
    def test_linux_command_failure(self, mock_run, mock_system) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        devices = scan_arp_table()
        assert devices == []


class TestParseIpNeighOutput:
    """Tests for Linux ip neigh output parser."""

    def test_parses_reachable_entries(self) -> None:
        output = "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:f0 REACHABLE\n"
        devices = _parse_ip_neigh_output(output)
        assert len(devices) == 1
        assert devices[0].ip_address == "192.168.1.2"
        assert devices[0].mac_address == "AA:BB:CC:DD:EE:F0"
        assert devices[0].interface == "eth0"
        assert devices[0].arp_type == "dynamic"

    def test_skips_failed_state(self) -> None:
        output = "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:f0 FAILED\n"
        devices = _parse_ip_neigh_output(output)
        assert devices == []

    def test_skips_broadcast_mac(self) -> None:
        output = "192.168.1.255 dev eth0 lladdr ff:ff:ff:ff:ff:ff REACHABLE\n"
        devices = _parse_ip_neigh_output(output)
        assert devices == []

    def test_skips_multicast_mac(self) -> None:
        output = "224.0.0.1 dev eth0 lladdr 01:00:5e:00:00:01 REACHABLE\n"
        devices = _parse_ip_neigh_output(output)
        assert devices == []

    def test_deduplicates_by_mac(self) -> None:
        output = (
            "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:f0 REACHABLE\n"
            "192.168.1.3 dev eth0 lladdr aa:bb:cc:dd:ee:f0 STALE\n"
        )
        devices = _parse_ip_neigh_output(output)
        assert len(devices) == 1

    def test_stale_is_dynamic(self) -> None:
        output = "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:f0 STALE\n"
        devices = _parse_ip_neigh_output(output)
        assert devices[0].arp_type == "dynamic"

    def test_empty_output(self) -> None:
        assert _parse_ip_neigh_output("") == []

    def test_lines_without_lladdr_skipped(self) -> None:
        output = "192.168.1.2 dev eth0  INCOMPLETE\n"
        devices = _parse_ip_neigh_output(output)
        assert devices == []


class TestIpToPseudoMac:
    """Tests for _ip_to_pseudo_mac helper."""

    def test_generates_locally_administered_mac(self) -> None:
        mac = _ip_to_pseudo_mac("192.168.1.1")
        assert mac.startswith("02:00:")

    def test_deterministic(self) -> None:
        assert _ip_to_pseudo_mac("10.0.0.1") == _ip_to_pseudo_mac("10.0.0.1")

    def test_different_ips_different_macs(self) -> None:
        assert _ip_to_pseudo_mac("192.168.1.1") != _ip_to_pseudo_mac("192.168.1.2")

    def test_format(self) -> None:
        mac = _ip_to_pseudo_mac("192.168.1.100")
        parts = mac.split(":")
        assert len(parts) == 6
        assert all(len(p) == 2 for p in parts)


class TestPingHost:
    """Tests for _ping_host helper."""

    @patch("src.network_discovery.subprocess.run")
    def test_responds(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        result = _ping_host("192.168.1.1")
        assert result == "192.168.1.1"

    @patch("src.network_discovery.subprocess.run")
    def test_no_response(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        result = _ping_host("192.168.1.1")
        assert result is None

    @patch("src.network_discovery.subprocess.run")
    def test_timeout(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=1)
        result = _ping_host("192.168.1.1")
        assert result is None

    @patch("src.network_discovery.subprocess.run")
    def test_os_error(self, mock_run) -> None:
        mock_run.side_effect = OSError("ping not found")
        result = _ping_host("192.168.1.1")
        assert result is None


class TestPingSweep:
    """Tests for ping_sweep function."""

    @patch("src.network_discovery._resolve_hostname", return_value=None)
    @patch("src.network_discovery._ping_host")
    def test_returns_responding_hosts(self, mock_ping, mock_resolve) -> None:
        mock_ping.side_effect = lambda ip, timeout=1.0: ip if ip == "192.168.1.1" else None
        devices = ping_sweep(["192.168.1.0/30"])
        assert len(devices) == 1
        assert devices[0].ip_address == "192.168.1.1"

    @patch("src.network_discovery._resolve_hostname", return_value=None)
    @patch("src.network_discovery._ping_host")
    def test_empty_subnets(self, mock_ping, mock_resolve) -> None:
        devices = ping_sweep([])
        assert devices == []
        mock_ping.assert_not_called()

    @patch("src.network_discovery._resolve_hostname", return_value=None)
    @patch("src.network_discovery._ping_host")
    def test_invalid_subnet_skipped(self, mock_ping, mock_resolve) -> None:
        devices = ping_sweep(["not-a-subnet"])
        assert devices == []

    @patch("src.network_discovery._resolve_hostname", return_value=None)
    @patch("src.network_discovery._ping_host", return_value=None)
    def test_no_hosts_respond(self, mock_ping, mock_resolve) -> None:
        devices = ping_sweep(["192.168.1.0/30"])
        assert devices == []

    @patch("src.network_discovery._resolve_hostname", return_value=None)
    @patch("src.network_discovery._ping_host")
    def test_pseudo_mac_assigned(self, mock_ping, mock_resolve) -> None:
        mock_ping.return_value = "10.0.0.1"
        devices = ping_sweep(["10.0.0.0/30"])
        assert len(devices) >= 1
        assert devices[0].mac_address.startswith("02:00:")

    @patch("src.network_discovery._resolve_hostname", return_value=None)
    @patch("src.network_discovery._ping_host")
    def test_sorted_by_ip(self, mock_ping, mock_resolve) -> None:
        mock_ping.side_effect = lambda ip, timeout=1.0: ip
        devices = ping_sweep(["10.0.0.0/29"])
        ips = [d.ip_address for d in devices]
        assert ips == sorted(ips, key=lambda x: tuple(int(o) for o in x.split(".")))


class TestResolveHostname:
    """Tests for hostname resolution."""

    @patch("src.network_discovery.socket.gethostbyaddr")
    def test_successful_resolve(self, mock_resolve) -> None:
        mock_resolve.return_value = ("my-laptop.local", [], ["192.168.1.2"])
        hostname = _resolve_hostname("192.168.1.2")
        assert hostname == "my-laptop.local"

    @patch("src.network_discovery.socket.gethostbyaddr")
    def test_resolve_failure(self, mock_resolve) -> None:
        mock_resolve.side_effect = socket.herror("Not found")
        hostname = _resolve_hostname("192.168.1.2")
        assert hostname is None

    @patch("src.network_discovery.socket.gethostbyaddr")
    def test_resolve_returns_ip(self, mock_resolve) -> None:
        """If hostname equals IP, return None."""
        mock_resolve.return_value = ("192.168.1.2", [], ["192.168.1.2"])
        hostname = _resolve_hostname("192.168.1.2")
        assert hostname is None
