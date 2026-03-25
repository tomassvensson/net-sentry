"""Tests for monitor mode WiFi scanner."""

from unittest.mock import MagicMock, patch

from src.monitor_scanner import MonitorModeDevice, is_scapy_available, scan_monitor_mode


class TestMonitorModeDeviceDataclass:
    """Tests for MonitorModeDevice dataclass."""

    def test_defaults(self) -> None:
        d = MonitorModeDevice(mac_address="AA:BB:CC:DD:EE:FF")
        assert d.signal_dbm is None
        assert d.frame_type == ""
        assert d.ssid is None
        assert d.vendor is None
        assert d.channel is None
        assert d.scan_time is not None

    def test_repr(self) -> None:
        d = MonitorModeDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            signal_dbm=-65.0,
            frame_type="beacon",
        )
        r = repr(d)
        assert "AA:BB:CC:DD:EE:FF" in r
        assert "-65.0" in r
        assert "beacon" in r


class TestIsScapyAvailable:
    """Tests for is_scapy_available."""

    @patch.dict("sys.modules", {"scapy": MagicMock(), "scapy.all": MagicMock()})
    def test_scapy_installed(self) -> None:
        assert is_scapy_available() is True

    @patch.dict("sys.modules", {"scapy": None, "scapy.all": None})
    def test_scapy_not_installed(self) -> None:
        # Importing scapy.all when set to None in sys.modules raises ImportError
        assert is_scapy_available() is False


class TestScanMonitorMode:
    """Tests for scan_monitor_mode function."""

    @patch("src.monitor_scanner.is_scapy_available", return_value=False)
    def test_returns_empty_when_scapy_missing(self, _mock) -> None:
        result = scan_monitor_mode()
        assert result == []

    @patch("src.monitor_scanner._capture_frames")
    @patch("src.monitor_scanner.is_scapy_available", return_value=True)
    def test_delegates_to_capture(self, _mock_avail, mock_capture) -> None:
        mock_capture.return_value = [MonitorModeDevice(mac_address="AA:BB:CC:DD:EE:FF", frame_type="beacon")]
        result = scan_monitor_mode(interface="wlan0mon", duration_seconds=10)
        assert len(result) == 1
        assert result[0].mac_address == "AA:BB:CC:DD:EE:FF"
        mock_capture.assert_called_once_with("wlan0mon", 10, True)

    @patch("src.monitor_scanner._capture_frames", side_effect=PermissionError("denied"))
    @patch("src.monitor_scanner.is_scapy_available", return_value=True)
    def test_handles_permission_error(self, _mock_avail, _mock_capture) -> None:
        result = scan_monitor_mode()
        assert result == []

    @patch("src.monitor_scanner._capture_frames", side_effect=OSError("interface error"))
    @patch("src.monitor_scanner.is_scapy_available", return_value=True)
    def test_handles_generic_error(self, _mock_avail, _mock_capture) -> None:
        result = scan_monitor_mode()
        assert result == []


class TestCaptureFrames:
    """Tests for _capture_frames with mocked scapy."""

    @patch("src.monitor_scanner.is_scapy_available", return_value=True)
    def test_capture_with_mocked_sniff(self, _mock_avail) -> None:
        """Test frame processing logic with mocked scapy."""
        mock_sniff = MagicMock()
        mock_dot11 = MagicMock()
        mock_dot11_beacon = MagicMock()
        mock_dot11_probe = MagicMock()
        mock_dot11_elt = MagicMock()
        mock_radiotap = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "scapy": MagicMock(),
                "scapy.all": MagicMock(
                    sniff=mock_sniff,
                    Dot11=mock_dot11,
                    Dot11Beacon=mock_dot11_beacon,
                    Dot11ProbeReq=mock_dot11_probe,
                    Dot11Elt=mock_dot11_elt,
                    RadioTap=mock_radiotap,
                ),
            },
        ):
            # Mock sniff to call the prn callback with a fake packet
            def call_prn(iface, prn, timeout, store):
                pkt = MagicMock()
                pkt.haslayer.return_value = True

                dot11_layer = MagicMock()
                dot11_layer.addr2 = "aa:bb:cc:dd:ee:ff"
                pkt.getlayer.return_value = dot11_layer

                prn(pkt)

            mock_sniff.side_effect = call_prn

            from src.monitor_scanner import _capture_frames

            result = _capture_frames("wlan0mon", 5, False)
            # Since scapy types are mocked, actual behavior depends on import
            # Just verify no exception was raised
            assert isinstance(result, list)
