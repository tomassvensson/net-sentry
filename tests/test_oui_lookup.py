"""Tests for OUI/vendor lookup module."""

import pytest

from src.oui_lookup import (
    _load_oui_csv,
    get_oui_prefix,
    is_randomized_mac,
    lookup_vendor,
    normalize_mac,
)


class TestNormalizeMac:
    """Tests for MAC address normalization."""

    @pytest.mark.timeout(30)
    def test_colon_separated(self) -> None:
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_hyphen_separated(self) -> None:
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_dot_separated(self) -> None:
        assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_no_separator(self) -> None:
        assert normalize_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_with_whitespace(self) -> None:
        assert normalize_mac("  aa:bb:cc:dd:ee:ff  ") == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_mixed_case(self) -> None:
        assert normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_invalid_too_short(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aa:bb:cc")

    @pytest.mark.timeout(30)
    def test_invalid_too_long(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aa:bb:cc:dd:ee:ff:00")

    @pytest.mark.timeout(30)
    def test_invalid_characters(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("gg:hh:ii:jj:kk:ll")

    @pytest.mark.timeout(30)
    def test_empty_string(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("")


class TestGetOuiPrefix:
    """Tests for OUI prefix extraction."""

    @pytest.mark.timeout(30)
    def test_standard_mac(self) -> None:
        assert get_oui_prefix("AA:BB:CC:DD:EE:FF") == "AA:BB:CC"

    @pytest.mark.timeout(30)
    def test_lowercase_mac(self) -> None:
        assert get_oui_prefix("aa:bb:cc:dd:ee:ff") == "AA:BB:CC"

    @pytest.mark.timeout(30)
    def test_hyphen_separated(self) -> None:
        assert get_oui_prefix("14-CC-20-01-02-03") == "14:CC:20"


class TestLookupVendor:
    """Tests for vendor lookup."""

    @pytest.mark.timeout(30)
    def test_known_apple_mac(self) -> None:
        vendor = lookup_vendor("AC:BC:32:00:00:00")
        assert vendor is not None
        assert "Apple" in vendor

    @pytest.mark.timeout(30)
    def test_known_samsung_mac(self) -> None:
        vendor = lookup_vendor("00:07:AB:00:00:00")
        assert vendor is not None
        assert "Samsung" in vendor

    @pytest.mark.timeout(30)
    def test_known_tp_link_mac(self) -> None:
        vendor = lookup_vendor("14:CC:20:00:00:00")
        assert vendor is not None
        # Could be "TP-Link" from full DB or builtin
        assert "TP" in vendor or "tp" in vendor.lower()

    @pytest.mark.timeout(30)
    def test_known_intel_mac(self) -> None:
        vendor = lookup_vendor("00:13:E8:00:00:00")
        assert vendor is not None
        assert "Intel" in vendor

    @pytest.mark.timeout(30)
    def test_invalid_mac_returns_none(self) -> None:
        assert lookup_vendor("invalid") is None

    @pytest.mark.timeout(30)
    def test_unknown_mac_returns_none_or_vendor(self) -> None:
        """Unknown MACs should return None from builtin, may return value from full DB."""
        result = lookup_vendor("00:00:00:00:00:01")
        # This may return something from the full database or None from builtin
        # Either outcome is acceptable
        assert result is None or isinstance(result, str)


class TestIsRandomizedMac:
    """Tests for randomized/locally administered MAC detection."""

    @pytest.mark.timeout(30)
    def test_globally_unique_mac(self) -> None:
        # First byte 0x00 — bit 1 is 0 → globally unique
        assert is_randomized_mac("00:11:22:33:44:55") is False

    @pytest.mark.timeout(30)
    def test_locally_administered_mac(self) -> None:
        # First byte 0x02 — bit 1 is 1 → locally administered
        assert is_randomized_mac("02:11:22:33:44:55") is True

    @pytest.mark.timeout(30)
    def test_another_locally_administered(self) -> None:
        # First byte 0x06 — bit 1 is 1 → locally administered
        assert is_randomized_mac("06:11:22:33:44:55") is True

    @pytest.mark.timeout(30)
    def test_common_vendor_mac_not_random(self) -> None:
        # Apple MAC — should not be randomized
        assert is_randomized_mac("AC:BC:32:00:00:00") is False

    @pytest.mark.timeout(30)
    def test_invalid_mac_returns_false(self) -> None:
        assert is_randomized_mac("invalid") is False


class TestLoadOuiCsv:
    """Tests for the local IEEE OUI CSV loader."""

    @pytest.mark.timeout(30)
    def test_missing_csv_returns_empty_dict(self, tmp_path, monkeypatch) -> None:
        """When the OUI CSV file doesn't exist, return an empty dict without error."""
        import src.oui_lookup as oui_mod

        monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", tmp_path / "nonexistent.csv")
        monkeypatch.setattr(oui_mod, "_csv_vendors", None)
        monkeypatch.setattr(oui_mod, "_CSV_LOAD_ATTEMPTED", False)

        result = _load_oui_csv()
        assert result == {}

    @pytest.mark.timeout(30)
    def test_valid_csv_parsed_correctly(self, tmp_path, monkeypatch) -> None:
        """A valid OUI CSV should be parsed into prefix→vendor mappings."""
        import src.oui_lookup as oui_mod

        csv_content = (
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-L,001B63,Apple Inc.,Cupertino CA US\n"
            "MA-L,00005E,ICANN,Los Angeles CA US\n"
        )
        csv_file = tmp_path / "oui.csv"
        csv_file.write_text(csv_content, encoding="utf-8")

        monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", csv_file)
        monkeypatch.setattr(oui_mod, "_csv_vendors", None)
        monkeypatch.setattr(oui_mod, "_CSV_LOAD_ATTEMPTED", False)

        result = _load_oui_csv()
        assert result.get("00:1B:63") == "Apple Inc."
        assert result.get("00:00:5E") == "ICANN"

    @pytest.mark.timeout(30)
    def test_malformed_csv_returns_empty_dict(self, tmp_path, monkeypatch) -> None:
        """A file with garbage content should not raise, just return empty."""
        import src.oui_lookup as oui_mod

        csv_file = tmp_path / "oui.csv"
        csv_file.write_bytes(b"\x00\xff\xfe garbage bytes \x00")

        monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", csv_file)
        monkeypatch.setattr(oui_mod, "_csv_vendors", None)
        monkeypatch.setattr(oui_mod, "_CSV_LOAD_ATTEMPTED", False)

        # Should not raise
        result = _load_oui_csv()
        assert isinstance(result, dict)

    @pytest.mark.timeout(30)
    def test_csv_vendor_used_in_lookup(self, tmp_path, monkeypatch) -> None:
        """lookup_vendor should prefer the CSV source when mac-vendor-lookup misses."""
        import src.oui_lookup as oui_mod

        csv_content = (
            "Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,TestCorp Ltd.,Testville TS US\n"
        )
        csv_file = tmp_path / "oui.csv"
        csv_file.write_text(csv_content, encoding="utf-8")

        monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", csv_file)
        monkeypatch.setattr(oui_mod, "_csv_vendors", None)
        monkeypatch.setattr(oui_mod, "_CSV_LOAD_ATTEMPTED", False)
        # Force mac-vendor-lookup to miss
        monkeypatch.setattr(oui_mod, "_mac_lookup", None)
        monkeypatch.setattr(oui_mod, "_INIT_ATTEMPTED", True)

        vendor = lookup_vendor("AA:BB:CC:00:00:01")
        assert vendor == "TestCorp Ltd."

    @pytest.mark.timeout(30)
    def test_cached_after_first_call(self, tmp_path, monkeypatch) -> None:
        """_load_oui_csv should return the same dict object on repeated calls."""
        import src.oui_lookup as oui_mod

        csv_content = "Registry,Assignment,Organization Name,Organization Address\n"
        csv_file = tmp_path / "oui.csv"
        csv_file.write_text(csv_content, encoding="utf-8")

        monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", csv_file)
        monkeypatch.setattr(oui_mod, "_csv_vendors", None)
        monkeypatch.setattr(oui_mod, "_CSV_LOAD_ATTEMPTED", False)

        first = _load_oui_csv()
        second = _load_oui_csv()
        assert first is second  # same dict object — cached
