"""Tests for IPv6 privacy address deduplication (src/ipv6_scanner.py)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.ipv6_scanner import Ipv6Neighbor, _is_privacy_address, deduplicate_privacy_addresses


def _make_neighbor(ipv6: str, mac: str = "AA:BB:CC:DD:EE:FF") -> Ipv6Neighbor:
    return Ipv6Neighbor(
        ipv6_address=ipv6,
        mac_address=mac,
        interface="eth0",
        state="REACHABLE",
        scan_time=datetime.now(UTC),
    )


class TestIsPrivacyAddress:
    """Tests for _is_privacy_address()."""

    @pytest.mark.timeout(10)
    def test_link_local_not_privacy(self) -> None:
        assert not _is_privacy_address("fe80::1")

    @pytest.mark.timeout(10)
    def test_eui64_derived_not_privacy(self) -> None:
        # EUI-64 interface IDs embed FF:FE at offset 3-4 of the IID
        # e.g. MAC aa:bb:cc:dd:ee:ff → 2606:2800::a8bb:ccff:fedd:eeff
        assert not _is_privacy_address("2606:2800::a8bb:ccff:fedd:eeff")

    @pytest.mark.timeout(10)
    def test_random_global_unicast_is_privacy(self) -> None:
        # Typical privacy address: global unicast (2606:2800::/32), random IID (no FF:FE)
        assert _is_privacy_address("2606:2800::1234:5678:9abc:def0")

    @pytest.mark.timeout(10)
    def test_invalid_address_returns_false(self) -> None:
        assert not _is_privacy_address("not-an-address")

    @pytest.mark.timeout(10)
    def test_loopback_not_privacy(self) -> None:
        assert not _is_privacy_address("::1")

    @pytest.mark.timeout(10)
    def test_ula_not_classified_as_privacy(self) -> None:
        # ULA addresses (fc00::/7) are not global, so not classified as privacy
        assert not _is_privacy_address("fd12:3456:789a::1")


class TestDeduplicatePrivacyAddresses:
    """Tests for deduplicate_privacy_addresses()."""

    @pytest.mark.timeout(10)
    def test_empty_list_returns_empty(self) -> None:
        assert deduplicate_privacy_addresses([]) == []

    @pytest.mark.timeout(10)
    def test_single_entry_unchanged(self) -> None:
        neighbors = [_make_neighbor("fe80::1")]
        result = deduplicate_privacy_addresses(neighbors)
        assert len(result) == 1

    @pytest.mark.timeout(10)
    def test_privacy_address_suppressed_when_eui64_present(self) -> None:
        # One EUI-64 derived + one privacy address for the same MAC
        eui64 = _make_neighbor("2606:2800::a8bb:ccff:fedd:eeff", mac="AA:BB:CC:DD:EE:FF")
        privacy = _make_neighbor("2606:2800::1234:5678:9abc:def0", mac="AA:BB:CC:DD:EE:FF")
        result = deduplicate_privacy_addresses([eui64, privacy])
        # Specifically: only one global entry for this MAC
        from ipaddress import IPv6Address

        globals_ = [n for n in result if IPv6Address(n.ipv6_address).is_global]
        assert len(globals_) == 1
        assert globals_[0].ipv6_address == "2606:2800::a8bb:ccff:fedd:eeff"

    @pytest.mark.timeout(10)
    def test_link_locals_always_kept(self) -> None:
        ll1 = _make_neighbor("fe80::1", mac="AA:BB:CC:DD:EE:FF")
        ll2 = _make_neighbor("fe80::2", mac="11:22:33:44:55:66")
        result = deduplicate_privacy_addresses([ll1, ll2])
        assert len(result) == 2

    @pytest.mark.timeout(10)
    def test_multiple_privacy_addresses_collapsed_to_one(self) -> None:
        p1 = _make_neighbor("2606:2800::1111:2222:3333:4444", mac="AA:BB:CC:DD:EE:FF")
        p2 = _make_neighbor("2606:2800::5555:6666:7777:8888", mac="AA:BB:CC:DD:EE:FF")
        result = deduplicate_privacy_addresses([p1, p2])
        from ipaddress import IPv6Address

        globals_ = [n for n in result if IPv6Address(n.ipv6_address).is_global]
        assert len(globals_) == 1

    @pytest.mark.timeout(10)
    def test_different_macs_kept_separately(self) -> None:
        n1 = _make_neighbor("2606:2800::1111:2222:3333:4444", mac="AA:BB:CC:DD:EE:FF")
        n2 = _make_neighbor("2606:2800::5555:6666:7777:8888", mac="11:22:33:44:55:66")
        result = deduplicate_privacy_addresses([n1, n2])
        from ipaddress import IPv6Address

        globals_ = [n for n in result if IPv6Address(n.ipv6_address).is_global]
        assert len(globals_) == 2
