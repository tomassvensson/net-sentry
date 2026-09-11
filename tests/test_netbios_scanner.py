"""Tests for NetBIOS name resolution module."""

import struct
from unittest.mock import MagicMock, patch

import pytest

from src.netbios_scanner import (
    NetBiosInfo,
    _build_nbstat_request,
    _parse_nbstat_response,
    resolve_netbios_name,
    resolve_netbios_names,
)


class TestNetBiosInfo:
    """Tests for NetBiosInfo dataclass."""

    @pytest.mark.timeout(30)
    def test_defaults(self) -> None:
        info = NetBiosInfo(ip_address="192.168.1.10")
        assert info.ip_address == "192.168.1.10"
        assert info.netbios_name == ""
        assert info.domain == ""
        assert info.mac_address == ""


class TestBuildNbstatRequest:
    """Tests for NBSTAT request packet building."""

    @pytest.mark.timeout(30)
    def test_builds_packet(self) -> None:
        packet = _build_nbstat_request(0x1234)
        assert isinstance(packet, bytes)
        assert len(packet) > 12  # At least header size

    @pytest.mark.timeout(30)
    def test_correct_transaction_id(self) -> None:
        packet = _build_nbstat_request(0xABCD)
        # First 2 bytes are transaction ID
        tid = struct.unpack(">H", packet[:2])[0]
        assert tid == 0xABCD


class TestParseNbstatResponse:
    """Tests for NBSTAT response parsing."""

    @pytest.mark.timeout(30)
    def test_too_short_response(self) -> None:
        result = _parse_nbstat_response("192.168.1.10", b"\x00" * 10)
        assert result is None

    @pytest.mark.timeout(30)
    def test_valid_response(self) -> None:
        """Test parsing a minimal valid-looking NBSTAT response."""
        # Build a fake response: 56 bytes header area + 1 name count + 1 entry
        header = b"\x00" * 56  # Header/query echo
        name_count = b"\x01"  # 1 name
        # 15-byte name + 1-byte suffix + 2-byte flags
        name = b"MYCOMPUTER     "  # 15 bytes, padded
        suffix = b"\x00"  # Workstation service
        flags = struct.pack(">H", 0x0000)  # Unique
        # 6-byte MAC
        mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

        data = header + name_count + name + suffix + flags + mac
        result = _parse_nbstat_response("192.168.1.10", data)
        assert result is not None
        assert result.netbios_name == "MYCOMPUTER"
        assert result.ip_address == "192.168.1.10"
        assert result.mac_address == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_zero_mac_ignored(self) -> None:
        """Test that all-zero MACs are ignored."""
        header = b"\x00" * 56
        name_count = b"\x01"
        name = b"TESTHOST       "
        suffix = b"\x00"
        flags = struct.pack(">H", 0x0000)
        mac = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        data = header + name_count + name + suffix + flags + mac
        result = _parse_nbstat_response("192.168.1.10", data)
        assert result is not None
        assert result.mac_address == ""

    @pytest.mark.timeout(30)
    def test_with_domain(self) -> None:
        """Test parsing response with both computer name and domain."""
        header = b"\x00" * 56
        name_count = b"\x02"
        # Entry 1: Computer name (unique)
        name1 = b"WORKSTATION    "
        suffix1 = b"\x00"
        flags1 = struct.pack(">H", 0x0000)
        # Entry 2: Domain (group)
        name2 = b"WORKGROUP      "
        suffix2 = b"\x00"
        flags2 = struct.pack(">H", 0x8000)  # Group flag
        mac = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

        data = header + name_count + name1 + suffix1 + flags1 + name2 + suffix2 + flags2 + mac
        result = _parse_nbstat_response("192.168.1.20", data)
        assert result is not None
        assert result.netbios_name == "WORKSTATION"
        assert result.domain == "WORKGROUP"


class TestResolveNetbiosName:
    """Tests for single NetBIOS name resolution."""

    @patch("socket.socket")
    @pytest.mark.timeout(30)
    def test_timeout_returns_none(self, mock_socket_cls) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError()

        result = resolve_netbios_name("192.168.1.10", timeout=0.1)
        assert result is None

    @patch("socket.socket")
    @pytest.mark.timeout(30)
    def test_os_error_returns_none(self, mock_socket_cls) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError("network error")

        result = resolve_netbios_name("192.168.1.10", timeout=0.1)
        assert result is None


class TestResolveNetbiosNames:
    """Tests for batch NetBIOS name resolution."""

    @patch("src.netbios_scanner.resolve_netbios_name")
    @pytest.mark.timeout(30)
    def test_resolves_multiple(self, mock_resolve) -> None:
        mock_resolve.side_effect = [
            NetBiosInfo(ip_address="192.168.1.10", netbios_name="PC1"),
            None,
            NetBiosInfo(ip_address="192.168.1.30", netbios_name="PC3"),
        ]
        result = resolve_netbios_names(["192.168.1.10", "192.168.1.20", "192.168.1.30"])
        assert len(result) == 2
        assert result[0].netbios_name == "PC1"
        assert result[1].netbios_name == "PC3"

    @patch("src.netbios_scanner.resolve_netbios_name")
    @pytest.mark.timeout(30)
    def test_empty_list(self, mock_resolve) -> None:
        result = resolve_netbios_names([])
        assert result == []
        mock_resolve.assert_not_called()

    @patch("src.netbios_scanner.resolve_netbios_name")
    @pytest.mark.timeout(30)
    def test_all_failed(self, mock_resolve) -> None:
        mock_resolve.return_value = None
        result = resolve_netbios_names(["192.168.1.10", "192.168.1.20"])
        assert result == []

    @patch("src.netbios_scanner.resolve_netbios_name")
    @pytest.mark.timeout(30)
    def test_empty_name_excluded(self, mock_resolve) -> None:
        mock_resolve.return_value = NetBiosInfo(ip_address="192.168.1.10", netbios_name="")
        result = resolve_netbios_names(["192.168.1.10"])
        assert result == []
