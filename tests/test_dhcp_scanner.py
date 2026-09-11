"""Tests for the DHCP lease file parser (src/dhcp_scanner.py)."""

from __future__ import annotations

import pytest

from src.dhcp_scanner import _parse_lease_text, parse_dhcp_leases

_SAMPLE_LEASES = """\
lease 192.168.1.100 {
  starts 2 2024/01/02 10:00:00;
  ends   2 2024/01/02 22:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "laptop1";
}
lease 192.168.1.101 {
  starts 2 2024/01/02 09:00:00;
  ends   2 2024/01/02 21:00:00;
  binding state expired;
  hardware ethernet 11:22:33:44:55:66;
  client-hostname "phone1";
}
lease 192.168.1.102 {
  starts 2 2024/01/02 08:00:00;
  ends   2 2024/01/02 20:00:00;
  binding state active;
  hardware ethernet ff:ee:dd:cc:bb:aa;
}
"""


class TestParseDhcpLeaseText:
    """Unit tests for _parse_lease_text()."""

    @pytest.mark.timeout(10)
    def test_active_leases_returned(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=True)
        macs = {d.mac_address for d in devices}
        assert "AA:BB:CC:DD:EE:FF" in macs
        assert "FF:EE:DD:CC:BB:AA" in macs

    @pytest.mark.timeout(10)
    def test_expired_lease_excluded_when_active_only(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=True)
        macs = {d.mac_address for d in devices}
        assert "11:22:33:44:55:66" not in macs

    @pytest.mark.timeout(10)
    def test_expired_lease_included_when_not_active_only(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=False)
        macs = {d.mac_address for d in devices}
        assert "11:22:33:44:55:66" in macs
        assert len(devices) == 3

    @pytest.mark.timeout(10)
    def test_hostname_captured(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=True)
        host_map = {d.mac_address: d.hostname for d in devices}
        assert host_map.get("AA:BB:CC:DD:EE:FF") == "laptop1"

    @pytest.mark.timeout(10)
    def test_no_hostname_is_none(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=True)
        host_map = {d.mac_address: d.hostname for d in devices}
        assert host_map.get("FF:EE:DD:CC:BB:AA") is None

    @pytest.mark.timeout(10)
    def test_ip_address_captured(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=True)
        ip_map = {d.mac_address: d.ip_address for d in devices}
        assert ip_map["AA:BB:CC:DD:EE:FF"] == "192.168.1.100"

    @pytest.mark.timeout(10)
    def test_deduplication_keeps_latest_ending_lease(self) -> None:
        duplicate_leases = """\
lease 10.0.0.1 {
  ends 2 2024/01/01 12:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
}
lease 10.0.0.2 {
  ends 2 2024/01/02 12:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
}
"""
        devices = _parse_lease_text(duplicate_leases, active_only=True)
        assert len(devices) == 1
        assert devices[0].ip_address == "10.0.0.2"

    @pytest.mark.timeout(10)
    def test_empty_text_returns_empty_list(self) -> None:
        assert _parse_lease_text("", active_only=True) == []

    @pytest.mark.timeout(10)
    def test_arp_type_is_dhcp(self) -> None:
        devices = _parse_lease_text(_SAMPLE_LEASES, active_only=True)
        for d in devices:
            assert d.arp_type == "dhcp"


class TestParseDhcpLeases:
    """Tests for the file-level parse_dhcp_leases() function."""

    @pytest.mark.timeout(10)
    def test_missing_file_returns_empty_list(self) -> None:
        result = parse_dhcp_leases("/nonexistent/path/dhcpd.leases")
        assert result == []

    @pytest.mark.timeout(10)
    def test_reads_from_real_file(self, tmp_path) -> None:
        lease_file = tmp_path / "dhcpd.leases"
        lease_file.write_text(_SAMPLE_LEASES, encoding="utf-8")
        devices = parse_dhcp_leases(str(lease_file))
        assert len(devices) == 2  # active only by default
