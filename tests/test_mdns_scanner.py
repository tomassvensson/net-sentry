"""Tests for mDNS scanner module."""

import struct
from unittest.mock import MagicMock, patch

import pytest

from src.mdns_scanner import (
    MdnsDevice,
    _arp_lookup_mac,
    _build_devices_from_records,
    _build_ptr_query,
    _create_mdns_socket,
    _decode_dns_name,
    _encode_dns_name,
    _parse_dns_records,
    _parse_txt_rdata,
    _query_service_type,
    _resolve_instance,
    scan_mdns_services,
)


class TestMdnsDevice:
    """Tests for MdnsDevice dataclass."""

    @pytest.mark.timeout(5)
    def test_defaults(self) -> None:
        dev = MdnsDevice(hostname="test.local", ip_address="192.168.1.10")
        assert dev.hostname == "test.local"
        assert dev.ip_address == "192.168.1.10"
        assert dev.mac_address == ""
        assert dev.service_type == ""
        assert dev.port == 0
        assert dev.vendor is None
        assert dev.is_randomized is False
        assert dev.txt_records == {}

    @pytest.mark.timeout(5)
    def test_custom_values(self) -> None:
        dev = MdnsDevice(
            hostname="printer.local",
            ip_address="192.168.1.20",
            mac_address="AA:BB:CC:DD:EE:FF",
            service_type="ipp",
            port=631,
            vendor="Brother",
        )
        assert dev.mac_address == "AA:BB:CC:DD:EE:FF"
        assert dev.service_type == "ipp"
        assert dev.port == 631
        assert dev.vendor == "Brother"


class TestEncodeDnsName:
    """Tests for _encode_dns_name."""

    @pytest.mark.timeout(5)
    def test_simple_name(self) -> None:
        result = _encode_dns_name("_http._tcp.local.")
        assert result == b"\x05_http\x04_tcp\x05local\x00"

    @pytest.mark.timeout(5)
    def test_trailing_dot_stripped(self) -> None:
        r1 = _encode_dns_name("_http._tcp.local.")
        r2 = _encode_dns_name("_http._tcp.local")
        assert r1 == r2

    @pytest.mark.timeout(5)
    def test_ends_with_null(self) -> None:
        result = _encode_dns_name("x.y.")
        assert result[-1:] == b"\x00"


class TestBuildPtrQuery:
    """Tests for _build_ptr_query."""

    @pytest.mark.timeout(5)
    def test_returns_bytes(self) -> None:
        result = _build_ptr_query("_http._tcp.local.")
        assert isinstance(result, bytes)

    @pytest.mark.timeout(5)
    def test_minimum_length(self) -> None:
        result = _build_ptr_query("_http._tcp.local.")
        assert len(result) > 12

    @pytest.mark.timeout(5)
    def test_has_dns_header(self) -> None:
        result = _build_ptr_query("_http._tcp.local.")
        tx_id, flags, qdcount = struct.unpack(">HHH", result[:6])
        assert tx_id == 0
        assert flags == 0
        assert qdcount == 1


class TestDecodeDnsName:
    """Tests for _decode_dns_name."""

    @pytest.mark.timeout(5)
    def test_simple_name(self) -> None:
        data = b"\x04test\x05local\x00"
        name, end = _decode_dns_name(data, 0)
        assert name == "test.local."
        assert end == len(data)

    @pytest.mark.timeout(5)
    def test_pointer_compression(self) -> None:
        data = b"\x05local\x00\xc0\x00"
        name, end = _decode_dns_name(data, 7)
        assert "local" in name
        assert end == 9

    @pytest.mark.timeout(5)
    def test_empty_name(self) -> None:
        data = b"\x00"
        name, end = _decode_dns_name(data, 0)
        assert name == "."
        assert end == 1

    @pytest.mark.timeout(5)
    def test_offset_beyond_data_returns_gracefully(self) -> None:
        data = b"\x04test\x00"
        name, _end = _decode_dns_name(data, 100)
        assert isinstance(name, str)


class TestParseTxtRdata:
    """Tests for _parse_txt_rdata."""

    @pytest.mark.timeout(5)
    def test_key_value_pair(self) -> None:
        entry = b"md=Chromecast"
        rdata = bytes([len(entry)]) + entry
        result = _parse_txt_rdata(rdata)
        assert result == {"md": "Chromecast"}

    @pytest.mark.timeout(5)
    def test_multiple_entries(self) -> None:
        e1 = b"md=Chromecast"
        e2 = b"fn=Living Room"
        rdata = bytes([len(e1)]) + e1 + bytes([len(e2)]) + e2
        result = _parse_txt_rdata(rdata)
        assert result["md"] == "Chromecast"
        assert result["fn"] == "Living Room"

    @pytest.mark.timeout(5)
    def test_key_only(self) -> None:
        entry = b"isdefault"
        rdata = bytes([len(entry)]) + entry
        result = _parse_txt_rdata(rdata)
        assert result.get("isdefault") == ""

    @pytest.mark.timeout(5)
    def test_empty_rdata(self) -> None:
        result = _parse_txt_rdata(b"")
        assert result == {}


class TestParseDnsRecords:
    """Tests for _parse_dns_records."""

    @pytest.mark.timeout(5)
    def test_invalid_data_returns_empty(self) -> None:
        result = _parse_dns_records(b"\x00\x01\x02")
        assert isinstance(result, list)

    @pytest.mark.timeout(5)
    def test_empty_data_returns_empty(self) -> None:
        result = _parse_dns_records(b"")
        assert result == []

    @pytest.mark.timeout(5)
    def test_garbage_data_does_not_raise(self) -> None:
        result = _parse_dns_records(b"\xff" * 100)
        assert isinstance(result, list)


class TestArpLookupMac:
    """Tests for _arp_lookup_mac."""

    @pytest.mark.timeout(10)
    @patch("subprocess.run")
    @pytest.mark.timeout(30)
    def test_found_mac(self, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  192.168.1.10  aa-bb-cc-dd-ee-ff  dynamic",
        )
        result = _arp_lookup_mac("192.168.1.10")
        assert result == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(10)
    @patch("subprocess.run")
    @pytest.mark.timeout(30)
    def test_not_found(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""

    @pytest.mark.timeout(10)
    @patch("subprocess.run", side_effect=OSError("command not found"))
    @pytest.mark.timeout(30)
    def test_command_failure(self, _mock_run) -> None:
        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""


class TestCreateMdnsSocket:
    """Tests for _create_mdns_socket."""

    @pytest.mark.timeout(10)
    @patch("socket.socket", side_effect=OSError("no socket"))
    @pytest.mark.timeout(30)
    def test_returns_none_on_error(self, _mock_socket) -> None:
        result = _create_mdns_socket()
        assert result is None


class TestQueryServiceType:
    """Tests for _query_service_type."""

    @pytest.mark.timeout(10)
    def test_returns_list_on_empty_select(self) -> None:
        mock_sock = MagicMock()
        with patch("select.select", return_value=([], [], [])):
            result = _query_service_type(mock_sock, "_http._tcp.local.", timeout=0.01)
        assert isinstance(result, list)

    @pytest.mark.timeout(10)
    def test_collects_response_data(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"\x00" * 20, ("224.0.0.251", 5353))
        with patch("select.select", side_effect=[([mock_sock], [], []), ([], [], [])]):
            result = _query_service_type(mock_sock, "_http._tcp.local.", timeout=0.01)
        assert isinstance(result, list)

    @pytest.mark.timeout(10)
    def test_send_error_returns_empty(self) -> None:
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError("network error")
        result = _query_service_type(mock_sock, "_http._tcp.local.", timeout=0.01)
        assert result == []


class TestBuildDevicesFromRecords:
    """Tests for _build_devices_from_records."""

    @pytest.mark.timeout(5)
    def test_no_srv_records_returns_empty(self) -> None:
        records = [{"type": 12, "target": "inst._http._tcp.local.", "name": "_http._tcp.local."}]
        ptr_targets = ["inst._http._tcp.local."]
        result = _build_devices_from_records(records, ptr_targets, set())
        assert result == []

    @pytest.mark.timeout(5)
    @patch("src.mdns_scanner.lookup_vendor", return_value="Acme")
    @patch("src.mdns_scanner.is_randomized_mac", return_value=False)
    @patch("src.mdns_scanner._arp_lookup_mac", return_value="AA:BB:CC:DD:EE:FF")
    @pytest.mark.timeout(30)
    def test_resolves_device(self, _m_arp, _m_rand, _m_vendor) -> None:
        records = [
            {"type": 33, "name": "inst._http._tcp.local.", "target": "myhost.local.", "port": 80},
            {"type": 1, "name": "myhost.local.", "address": "192.168.1.50"},
        ]
        ptr_targets = ["inst._http._tcp.local."]
        result = _build_devices_from_records(records, ptr_targets, set())
        assert len(result) == 1
        assert result[0].ip_address == "192.168.1.50"
        assert result[0].port == 80

    @pytest.mark.timeout(5)
    def test_deduplication(self) -> None:
        seen: set[str] = {"192.168.1.50:inst._http._tcp.local."}
        records = [
            {"type": 33, "name": "inst._http._tcp.local.", "target": "myhost.local.", "port": 80},
            {"type": 1, "name": "myhost.local.", "address": "192.168.1.50"},
        ]
        with patch("src.mdns_scanner._arp_lookup_mac", return_value="AA:BB:CC:DD:EE:FF"):
            result = _build_devices_from_records(records, ["inst._http._tcp.local."], seen)
        assert result == []


class TestResolveInstance:
    """Tests for _resolve_instance."""

    @pytest.mark.timeout(5)
    def test_returns_none_if_no_srv(self) -> None:
        result = _resolve_instance("inst._http._tcp.local.", {}, {}, {}, set())
        assert result is None

    @pytest.mark.timeout(5)
    def test_returns_none_if_no_a_record(self) -> None:
        srv_by_name = {"inst._http._tcp.local.": {"target": "myhost.local.", "port": 80}}
        result = _resolve_instance("inst._http._tcp.local.", srv_by_name, {}, {}, set())
        assert result is None

    @pytest.mark.timeout(5)
    @patch("src.mdns_scanner.lookup_vendor", return_value=None)
    @patch("src.mdns_scanner.is_randomized_mac", return_value=False)
    @patch("src.mdns_scanner._arp_lookup_mac", return_value="")
    @pytest.mark.timeout(30)
    def test_resolves_with_minimal_data(self, _m_arp, _m_rand, _m_vendor) -> None:
        srv_by_name = {"inst._http._tcp.local.": {"target": "myhost.local.", "port": 80}}
        a_by_host = {"myhost.local.": "10.0.0.1"}
        result = _resolve_instance("inst._http._tcp.local.", srv_by_name, {}, a_by_host, set())
        assert result is not None
        assert result.ip_address == "10.0.0.1"
        assert result.port == 80
        assert result.hostname == "myhost.local"


class TestScanMdnsServices:
    """Integration-style tests for scan_mdns_services."""

    @pytest.mark.timeout(10)
    @patch("src.mdns_scanner._create_mdns_socket", return_value=None)
    @pytest.mark.timeout(30)
    def test_returns_empty_when_socket_fails(self, _mock_socket) -> None:
        result = scan_mdns_services(timeout=0.01)
        assert result == []

    @pytest.mark.timeout(10)
    @patch("src.mdns_scanner._build_devices_from_records", return_value=[])
    @patch("src.mdns_scanner._query_service_type", return_value=[])
    @patch("src.mdns_scanner._create_mdns_socket")
    @pytest.mark.timeout(30)
    def test_happy_path_no_devices(self, mock_socket, _mock_query, _mock_build) -> None:
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        result = scan_mdns_services(timeout=0.01)
        assert isinstance(result, list)
        mock_sock.close.assert_called_once()

    @pytest.mark.timeout(10)
    @patch("src.mdns_scanner._build_devices_from_records")
    @patch("src.mdns_scanner._query_service_type", return_value=[])
    @patch("src.mdns_scanner._create_mdns_socket")
    @pytest.mark.timeout(30)
    def test_returns_discovered_devices(self, mock_socket, _mock_query, mock_build) -> None:
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        device = MdnsDevice(hostname="printer.local", ip_address="10.0.0.2", mac_address="11:22:33:44:55:66")
        mock_build.return_value = [device]
        result = scan_mdns_services(timeout=0.01)
        assert len(result) >= 1
        assert result[0].hostname == "printer.local"
