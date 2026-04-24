"""Tests for device fingerprinting."""

import pytest

from src.fingerprint import (
    DeviceFingerprint,
    FingerprintEvidence,
    _parse_os_string,
    compute_confidence,
    fingerprint_from_hostname,
    fingerprint_from_mdns_txt,
    fingerprint_from_ssdp_server,
)


class TestDeviceFingerprint:
    """Tests for DeviceFingerprint dataclass."""

    @pytest.mark.timeout(30)
    def test_default_values(self) -> None:
        fp = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.os_family == ""
        assert fp.os_version == ""
        assert fp.device_model == ""
        assert fp.manufacturer == ""
        assert fp.services == []
        assert fp.confidence == pytest.approx(0.0)

    @pytest.mark.timeout(30)
    def test_merge_fills_empty_fields(self) -> None:
        fp1 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF", os_family="macOS")
        fp2 = DeviceFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            os_version="14.2",
            manufacturer="Apple",
            device_model="MacBook Pro",
            services=["http"],
        )
        # Add evidence to fp2 so that merged confidence is non-zero
        fp2.add_evidence("mdns", "device_model", "MacBook Pro", 0.8)
        fp1.merge(fp2)
        assert fp1.os_family == "macOS"  # not overwritten
        assert fp1.os_version == "14.2"
        assert fp1.manufacturer == "Apple"
        assert fp1.device_model == "MacBook Pro"
        assert "http" in fp1.services
        # Confidence is derived from merged evidence
        assert fp1.confidence == pytest.approx(0.8)

    @pytest.mark.timeout(30)
    def test_merge_does_not_overwrite(self) -> None:
        fp1 = DeviceFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            os_family="macOS",
            manufacturer="Apple",
        )
        fp2 = DeviceFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            os_family="Linux",
            manufacturer="Dell",
        )
        fp1.merge(fp2)
        assert fp1.os_family == "macOS"
        assert fp1.manufacturer == "Apple"

    @pytest.mark.timeout(30)
    def test_merge_deduplicates_services(self) -> None:
        fp1 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF", services=["http"])
        fp2 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF", services=["http", "ssh"])
        fp1.merge(fp2)
        assert fp1.services == ["http", "ssh"]


class TestFingerprintFromMdnsTxt:
    """Tests for mDNS TXT record fingerprinting."""

    @pytest.mark.timeout(30)
    def test_model_descriptor(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"md": "Synology DS920+"})
        assert fp.device_model == "Synology DS920+"
        assert fp.confidence >= 0.7

    @pytest.mark.timeout(30)
    def test_apple_model(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"am": "MacBookPro18,1"})
        assert fp.device_model == "MacBookPro18,1"
        assert fp.manufacturer == "Apple"
        assert fp.confidence >= 0.8

    @pytest.mark.timeout(30)
    def test_os_info(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"os": "macOS 14.2"})
        assert fp.os_family == "macOS"
        assert fp.os_version == "14.2"

    @pytest.mark.timeout(30)
    def test_friendly_name(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"fn": "Living Room Speaker"})
        assert fp.device_model == "Living Room Speaker"

    @pytest.mark.timeout(30)
    def test_service_type_recorded(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {}, service_type="_http._tcp")
        assert "_http._tcp" in fp.services

    @pytest.mark.timeout(30)
    def test_empty_records(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {})
        assert fp.device_model == ""
        assert fp.confidence == pytest.approx(0.0)


class TestFingerprintFromSsdpServer:
    """Tests for SSDP server string fingerprinting."""

    @pytest.mark.timeout(30)
    def test_linux_server(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "Linux/4.14.0 UPnP/1.0 Synology/DSM")
        assert fp.os_family == "Linux"
        assert fp.os_version == "4.14.0"
        assert fp.manufacturer == "Synology"

    @pytest.mark.timeout(30)
    def test_windows_server(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "Windows/10.0 UPnP/1.0")
        assert fp.os_family == "Windows"
        assert fp.os_version == "10.0"

    @pytest.mark.timeout(30)
    def test_empty_server_string(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "")
        assert fp.os_family == ""
        assert fp.confidence == pytest.approx(0.0)

    @pytest.mark.timeout(30)
    def test_product_only(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "SomeProduct/2.0")
        assert fp.manufacturer == "SomeProduct"
        assert fp.confidence >= 0.4


class TestFingerprintFromHostname:
    """Tests for hostname-based fingerprinting."""

    @pytest.mark.timeout(30)
    def test_iphone(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "iPhone-de-Jean")
        assert fp.manufacturer == "Apple"
        assert fp.device_model == "iPhone"
        assert fp.os_family == "iOS"

    @pytest.mark.timeout(30)
    def test_ipad(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "iPad-Pro")
        assert fp.manufacturer == "Apple"
        assert fp.device_model == "iPad"
        assert fp.os_family == "iOS"

    @pytest.mark.timeout(30)
    def test_macbook(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "Jeans-MacBook-Pro")
        assert fp.manufacturer == "Apple"
        assert fp.device_model == "MacBook"
        assert fp.os_family == "macOS"

    @pytest.mark.timeout(30)
    def test_galaxy(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "Galaxy-S23")
        assert fp.manufacturer == "Samsung"
        assert "Galaxy" in fp.device_model
        assert fp.os_family == "Android"

    @pytest.mark.timeout(30)
    def test_windows_desktop(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "DESKTOP-ABC123")
        assert fp.os_family == "Windows"

    @pytest.mark.timeout(30)
    def test_android_hostname(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "android-abc123")
        assert fp.os_family == "Android"

    @pytest.mark.timeout(30)
    def test_synology(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "DiskStation")
        assert fp.manufacturer == "Synology"
        assert fp.os_family == "DSM"

    @pytest.mark.timeout(30)
    def test_empty_hostname(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "")
        assert fp.os_family == ""
        assert fp.confidence == pytest.approx(0.0)

    @pytest.mark.timeout(30)
    def test_generic_hostname(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "just-a-hostname")
        assert fp.confidence == pytest.approx(0.0)


class TestFingerprintEvidence:
    """Tests for evidence-weighted confidence scoring."""

    @pytest.mark.timeout(30)
    def test_compute_confidence_empty(self) -> None:
        """No evidence → confidence 0."""
        assert compute_confidence([]) == pytest.approx(0.0)

    @pytest.mark.timeout(30)
    def test_compute_confidence_single(self) -> None:
        """Single evidence item with weight w → confidence w."""
        ev = FingerprintEvidence(source="mdns", field="device_model", value="iPhone", weight=0.8)
        assert compute_confidence([ev]) == pytest.approx(0.8)

    @pytest.mark.timeout(30)
    def test_compute_confidence_two_independent(self) -> None:
        """Two independent evidence items combine: 1 − (1−w1)(1−w2)."""
        ev1 = FingerprintEvidence(source="mdns", field="device_model", value="iPhone", weight=0.8)
        ev2 = FingerprintEvidence(source="hostname", field="manufacturer", value="Apple", weight=0.6)
        expected = 1.0 - (1.0 - 0.8) * (1.0 - 0.6)
        assert compute_confidence([ev1, ev2]) == pytest.approx(expected, abs=1e-6)

    @pytest.mark.timeout(30)
    def test_compute_confidence_capped_at_one(self) -> None:
        """Confidence should never exceed 1.0."""
        evs = [FingerprintEvidence(source="s", field="f", value="v", weight=0.99) for _ in range(5)]
        result = compute_confidence(evs)
        assert result <= 1.0

    @pytest.mark.timeout(30)
    def test_add_evidence_updates_confidence(self) -> None:
        """add_evidence() appends and recomputes confidence immediately."""
        fp = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        assert fp.confidence == pytest.approx(0.0)
        fp.add_evidence("mdns", "device_model", "iPhone", 0.8)
        assert fp.confidence == pytest.approx(0.8)
        fp.add_evidence("hostname", "manufacturer", "Apple", 0.6)
        expected = 1.0 - (1.0 - 0.8) * (1.0 - 0.6)
        assert fp.confidence == pytest.approx(expected, abs=1e-6)

    @pytest.mark.timeout(30)
    def test_add_evidence_stores_evidence_items(self) -> None:
        """add_evidence() stores each item in the evidence list."""
        fp = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        fp.add_evidence("mdns", "device_model", "Galaxy S23", 0.7)
        fp.add_evidence("hostname", "os_family", "Android", 0.5)
        assert len(fp.evidence) == 2
        assert fp.evidence[0].source == "mdns"
        assert fp.evidence[1].source == "hostname"

    @pytest.mark.timeout(30)
    def test_merge_combines_evidence(self) -> None:
        """merge() concatenates evidence lists from both fingerprints."""
        fp1 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        fp1.add_evidence("mdns", "device_model", "MacBook", 0.7)

        fp2 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        fp2.add_evidence("ssdp", "os_family", "macOS", 0.5)

        fp1.merge(fp2)

        # Both evidence items should be present
        sources = {e.source for e in fp1.evidence}
        assert "mdns" in sources
        assert "ssdp" in sources

    @pytest.mark.timeout(30)
    def test_merge_recomputes_confidence(self) -> None:
        """After merge(), confidence reflects all combined evidence."""
        fp1 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        fp1.add_evidence("mdns", "device_model", "MacBook", 0.7)
        confidence_before = fp1.confidence

        fp2 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        fp2.add_evidence("ssdp", "os_family", "macOS", 0.5)

        fp1.merge(fp2)

        # Combined confidence must be higher (more evidence = higher certainty)
        assert fp1.confidence > confidence_before

    @pytest.mark.timeout(30)
    def test_fingerprint_evidence_dataclass_fields(self) -> None:
        """FingerprintEvidence stores all four fields correctly."""
        ev = FingerprintEvidence(source="hostname", field="os_family", value="Linux", weight=0.4)
        assert ev.source == "hostname"
        assert ev.field == "os_family"
        assert ev.value == "Linux"
        assert ev.weight == pytest.approx(0.4)


class TestParseOsString:
    """Tests for OS string parsing."""

    @pytest.mark.timeout(30)
    def test_macos(self) -> None:
        family, version = _parse_os_string("macOS 14.2")
        assert family == "macOS"
        assert version == "14.2"

    @pytest.mark.timeout(30)
    def test_linux(self) -> None:
        family, version = _parse_os_string("Linux 5.15.0")
        assert family == "Linux"
        assert version == "5.15.0"

    @pytest.mark.timeout(30)
    def test_no_version(self) -> None:
        family, version = _parse_os_string("FreeBSD")
        assert family == "FreeBSD"
        assert version == ""

    @pytest.mark.timeout(30)
    def test_empty_string(self) -> None:
        family, version = _parse_os_string("")
        assert family == ""
        assert version == ""
