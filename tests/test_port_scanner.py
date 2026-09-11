"""Unit tests for src/port_scanner.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.port_scanner import (
    DEFAULT_PORTS,
    OpenPort,
    decode_open_ports,
    encode_open_ports,
    port_to_service,
    scan_host_ports,
)


class TestOpenPort:
    def test_str_format(self):
        op = OpenPort(port=22, service="ssh")
        assert str(op) == "22/ssh"

    def test_unknown_service(self):
        op = OpenPort(port=9999, service="unknown")
        assert str(op) == "9999/unknown"


class TestPortToService:
    def test_known_ports(self):
        assert port_to_service(22) == "ssh"
        assert port_to_service(80) == "http"
        assert port_to_service(443) == "https"
        assert port_to_service(3389) == "rdp"

    def test_unknown_port_returns_port_number_string(self):
        assert port_to_service(65000) == "65000"


class TestEncodeDecodePorts:
    def test_encode_empty(self):
        assert encode_open_ports([]) == ""

    def test_encode_single(self):
        assert encode_open_ports([OpenPort(22, "ssh")]) == "22/ssh"

    def test_encode_multiple(self):
        ports = [OpenPort(22, "ssh"), OpenPort(80, "http")]
        assert encode_open_ports(ports) == "22/ssh,80/http"

    def test_decode_empty_string(self):
        assert decode_open_ports("") == []

    def test_decode_single(self):
        result = decode_open_ports("22/ssh")
        assert len(result) == 1
        assert result[0].port == 22
        assert result[0].service == "ssh"

    def test_decode_multiple(self):
        result = decode_open_ports("22/ssh,80/http")
        assert len(result) == 2
        ports = [p.port for p in result]
        assert 22 in ports
        assert 80 in ports

    def test_roundtrip(self):
        original = [OpenPort(22, "ssh"), OpenPort(443, "https")]
        encoded = encode_open_ports(original)
        decoded = decode_open_ports(encoded)
        assert [p.port for p in decoded] == [p.port for p in original]

    def test_decode_none_returns_empty(self):
        assert decode_open_ports(None) == []  # type: ignore[arg-type]


class TestScanHostPorts:
    def _make_socket_mock(self, connect_ex_return: int):
        """Create a socket mock that behaves as a context manager."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = connect_ex_return
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        return mock_sock

    def test_open_port_discovered(self):
        """A port that connects immediately is returned."""
        mock_sock = self._make_socket_mock(connect_ex_return=0)
        with patch("src.port_scanner.socket.socket", return_value=mock_sock):
            result = scan_host_ports("192.168.1.1", ports=[22], timeout=0.1)

        assert len(result) == 1
        assert result[0].port == 22
        assert result[0].service == "ssh"

    def test_closed_port_not_returned(self):
        """A port that rejects connection is not included in the result."""
        mock_sock = self._make_socket_mock(connect_ex_return=111)
        with patch("src.port_scanner.socket.socket", return_value=mock_sock):
            result = scan_host_ports("192.168.1.1", ports=[22], timeout=0.1)

        assert result == []

    def test_empty_ports_list_returns_empty(self):
        result = scan_host_ports("192.168.1.1", ports=[], timeout=0.1)
        assert result == []

    def test_returns_multiple_open_ports(self):
        """All ports returning 0 are reported."""
        mock_sock = self._make_socket_mock(connect_ex_return=0)
        with patch("src.port_scanner.socket.socket", return_value=mock_sock):
            result = scan_host_ports("192.168.1.1", ports=[22, 80, 443], timeout=0.1)

        assert len(result) == 3
        discovered_ports = {p.port for p in result}
        assert discovered_ports == {22, 80, 443}

    def test_default_ports_constant_nonempty(self):
        assert len(DEFAULT_PORTS) > 0

    def test_exception_in_connect_does_not_crash(self):
        """OSError during connection should be handled gracefully."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("network unreachable")
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("src.port_scanner.socket.socket", return_value=mock_sock):
            result = scan_host_ports("192.168.1.1", ports=[22], timeout=0.1)

        assert result == []
