"""Tests for IPv6 neighbor discovery scanner."""

from unittest.mock import MagicMock, patch

from src.ipv6_scanner import (
    Ipv6Neighbor,
    _parse_linux_output,
    _parse_windows_output,
    scan_ipv6_neighbors,
)

WINDOWS_OUTPUT = """\
Interface 5: Ethernet

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::1                                       00-11-22-33-44-55  Reachable
fe80::6e38:e6fe:8ec:8fbe                      aa-bb-cc-dd-ee-ff  Stale
ff02::1                                       33-33-00-00-00-01  Permanent
fe80::bad                                     ff-ff-ff-ff-ff-ff  Reachable
fe80::gone                                    00-00-00-00-00-01  Unreachable

Interface 12: Wi-Fi

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::abcd                                    11-22-33-44-55-66  Reachable
"""

LINUX_OUTPUT = """\
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
fe80::2 dev eth0 lladdr 11:22:33:44:55:66 STALE
fe80::bad dev eth0 lladdr 00:00:00:00:00:01 FAILED
fe80::3 dev wlan0 lladdr cc:dd:ee:ff:00:11 DELAY
"""


class TestParseWindowsOutput:
    """Tests for _parse_windows_output."""

    def test_parses_multiple_interfaces(self) -> None:
        neighbors = _parse_windows_output(WINDOWS_OUTPUT)
        # Should get: fe80::1, fe80::6e38..., ff02::1, fe80::abcd
        # Excludes: ff:ff:ff:ff:ff:ff (broadcast) and Unreachable
        macs = {n.mac_address for n in neighbors}
        assert "00:11:22:33:44:55" in macs
        assert "AA:BB:CC:DD:EE:FF" in macs
        assert "11:22:33:44:55:66" in macs
        assert "FF:FF:FF:FF:FF:FF" not in macs

    def test_interface_assignment(self) -> None:
        neighbors = _parse_windows_output(WINDOWS_OUTPUT)
        ethernet = [n for n in neighbors if n.interface == "Ethernet"]
        wifi = [n for n in neighbors if n.interface == "Wi-Fi"]
        assert len(ethernet) >= 2
        assert len(wifi) >= 1

    def test_mac_format_normalized(self) -> None:
        neighbors = _parse_windows_output(WINDOWS_OUTPUT)
        for n in neighbors:
            # Should be uppercase with colons
            assert "-" not in n.mac_address
            assert n.mac_address == n.mac_address.upper()

    def test_state_preserved(self) -> None:
        neighbors = _parse_windows_output(WINDOWS_OUTPUT)
        reachable = [n for n in neighbors if n.state == "Reachable"]
        assert len(reachable) >= 1

    def test_empty_output(self) -> None:
        assert _parse_windows_output("") == []

    def test_skips_unreachable(self) -> None:
        neighbors = _parse_windows_output(WINDOWS_OUTPUT)
        states = {n.state.lower() for n in neighbors}
        assert "unreachable" not in states


class TestParseLinuxOutput:
    """Tests for _parse_linux_output."""

    def test_parses_neighbors(self) -> None:
        neighbors = _parse_linux_output(LINUX_OUTPUT)
        # Should get: fe80::1, fe80::2, fe80::3 (not FAILED)
        assert len(neighbors) == 3

    def test_skips_failed(self) -> None:
        neighbors = _parse_linux_output(LINUX_OUTPUT)
        states = {n.state.lower() for n in neighbors}
        assert "failed" not in states

    def test_interface_captured(self) -> None:
        neighbors = _parse_linux_output(LINUX_OUTPUT)
        interfaces = {n.interface for n in neighbors}
        assert "eth0" in interfaces
        assert "wlan0" in interfaces

    def test_mac_uppercase(self) -> None:
        neighbors = _parse_linux_output(LINUX_OUTPUT)
        for n in neighbors:
            assert n.mac_address == n.mac_address.upper()

    def test_empty_output(self) -> None:
        assert _parse_linux_output("") == []


class TestScanIpv6Neighbors:
    """Tests for scan_ipv6_neighbors with mocked subprocess."""

    @patch("src.ipv6_scanner.platform")
    @patch("src.ipv6_scanner.subprocess")
    def test_windows_platform(self, mock_subprocess, mock_platform) -> None:
        mock_platform.system.return_value = "Windows"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = WINDOWS_OUTPUT
        mock_subprocess.run.return_value = mock_result

        neighbors = scan_ipv6_neighbors()
        assert len(neighbors) > 0
        mock_subprocess.run.assert_called_once()

    @patch("src.ipv6_scanner.platform")
    @patch("src.ipv6_scanner.subprocess")
    def test_linux_platform(self, mock_subprocess, mock_platform) -> None:
        mock_platform.system.return_value = "Linux"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = LINUX_OUTPUT
        mock_subprocess.run.return_value = mock_result

        neighbors = scan_ipv6_neighbors()
        assert len(neighbors) == 3

    @patch("src.ipv6_scanner.platform")
    @patch("src.ipv6_scanner.subprocess")
    def test_command_not_found(self, mock_subprocess, mock_platform) -> None:
        mock_platform.system.return_value = "Linux"
        mock_subprocess.run.side_effect = FileNotFoundError("ip not found")
        mock_subprocess.SubprocessError = (
            type(mock_subprocess.SubprocessError) if hasattr(mock_subprocess, "SubprocessError") else Exception
        )

        neighbors = scan_ipv6_neighbors()
        assert neighbors == []

    @patch("src.ipv6_scanner.platform")
    @patch("src.ipv6_scanner.subprocess")
    def test_nonzero_return_code(self, mock_subprocess, mock_platform) -> None:
        mock_platform.system.return_value = "Windows"
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error"
        mock_subprocess.run.return_value = mock_result

        neighbors = scan_ipv6_neighbors()
        assert neighbors == []


class TestIpv6NeighborDataclass:
    """Tests for Ipv6Neighbor dataclass."""

    def test_repr(self) -> None:
        n = Ipv6Neighbor(ipv6_address="fe80::1", mac_address="AA:BB:CC:DD:EE:FF", state="Reachable")
        r = repr(n)
        assert "fe80::1" in r
        assert "AA:BB:CC:DD:EE:FF" in r
        assert "Reachable" in r

    def test_defaults(self) -> None:
        n = Ipv6Neighbor(ipv6_address="fe80::1", mac_address="AA:BB:CC:DD:EE:FF")
        assert n.interface == ""
        assert n.state == ""
        assert n.scan_time is not None
