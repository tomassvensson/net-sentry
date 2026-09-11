"""Tests for main module — display and scan orchestration."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine

from src.config import AppConfig
from src.database import get_session
from src.main import (
    _best_name,
    _categorize_all_devices,
    _display_results,
    _drop_ping_sweep_devices_with_arp_match,
    _execute_all_scanners,
    _format_signal,
    _format_time,
    _friendly_vendor,
    _handle_shutdown,
    _import_and_scan_mdns,
    _import_and_scan_ssdp,
    _merge_bluetooth_devices,
    _merge_network_devices_by_mac,
    _PortScanTarget,
    _resolve_netbios,
    _scan_port_targets_parallel,
    _shorten_vendor_name,
    _subnets_safe_for_forced_host_discovery,
    _upsert_mdns_device,
    _upsert_network_device,
    _upsert_ssdp_device,
    main,
    run_scan,
)
from src.models import Base, Device, VisibilityWindow


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


class TestFormatSignal:
    """Tests for signal strength formatting."""

    @pytest.mark.timeout(30)
    def test_none(self) -> None:
        assert _format_signal(None) == "N/A"

    @pytest.mark.timeout(30)
    def test_excellent(self) -> None:
        result = _format_signal(-45.0)
        assert "Excellent" in result
        assert "-45" in result

    @pytest.mark.timeout(30)
    def test_good(self) -> None:
        result = _format_signal(-55.0)
        assert "Good" in result

    @pytest.mark.timeout(30)
    def test_fair(self) -> None:
        result = _format_signal(-65.0)
        assert "Fair" in result

    @pytest.mark.timeout(30)
    def test_weak(self) -> None:
        result = _format_signal(-75.0)
        assert "Weak" in result

    @pytest.mark.timeout(30)
    def test_very_weak(self) -> None:
        result = _format_signal(-90.0)
        assert "Very Weak" in result


class TestFormatTime:
    """Tests for time formatting."""

    @pytest.mark.timeout(30)
    def test_none(self) -> None:
        assert _format_time(None) == "N/A"

    @pytest.mark.timeout(30)
    def test_datetime(self) -> None:
        dt = datetime(2026, 3, 9, 14, 30, 0)
        result = _format_time(dt)
        assert "2026-03-09" in result
        assert "14:30:00" in result


class TestShortenVendorName:
    """Tests for automatic vendor name shortening."""

    @pytest.mark.timeout(30)
    def test_strips_inc(self) -> None:
        assert _shorten_vendor_name("Espressif Inc.") == "Espressif"

    @pytest.mark.timeout(30)
    def test_strips_corporation(self) -> None:
        assert _shorten_vendor_name("Microsoft Corporation") == "Microsoft"

    @pytest.mark.timeout(30)
    def test_strips_co_ltd(self) -> None:
        assert _shorten_vendor_name("Samsung Electronics Co.,Ltd") == "Samsung"

    @pytest.mark.timeout(30)
    def test_strips_gmbh(self) -> None:
        assert _shorten_vendor_name("BSH Hausgeräte GmbH") == "BSH Hausgeräte"

    @pytest.mark.timeout(30)
    def test_strips_technologies(self) -> None:
        assert _shorten_vendor_name("TP-LINK TECHNOLOGIES CO.,LTD.") == "TP-LINK"

    @pytest.mark.timeout(30)
    def test_strips_parenthetical(self) -> None:
        result = _shorten_vendor_name("LG Electronics (Mobile Communications)")
        assert result == "LG"

    @pytest.mark.timeout(30)
    def test_preserves_simple_name(self) -> None:
        assert _shorten_vendor_name("Apple") == "Apple"

    @pytest.mark.timeout(30)
    def test_preserves_short_name(self) -> None:
        assert _shorten_vendor_name("Dell") == "Dell"


class TestFriendlyVendor:
    """Tests for vendor name display."""

    @pytest.mark.timeout(30)
    def test_known_vendor(self) -> None:
        result = _friendly_vendor("Google, Inc.", "AA:BB:CC:DD:EE:FF")
        assert result == "Google"

    @pytest.mark.timeout(30)
    def test_randomized_mac_no_vendor(self) -> None:
        # Locally administered (randomized) MAC: bit 1 of first byte set
        result = _friendly_vendor(None, "FA:BB:CC:DD:EE:FF")
        assert "Randomized" in result

    @pytest.mark.timeout(30)
    def test_no_vendor_no_randomized(self) -> None:
        result = _friendly_vendor(None, "00:BB:CC:DD:EE:FF")
        assert "Unknown" in result


class TestBestName:
    """Tests for best device name selection."""

    @pytest.mark.timeout(30)
    def test_device_name_preferred(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            device_name="MyRouter",
            ssid="Home",
        )
        assert _best_name(device) == "MyRouter"

    @pytest.mark.timeout(30)
    def test_hostname_when_no_name(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            hostname="my-server",
        )
        assert _best_name(device) == "my-server"

    @pytest.mark.timeout(30)
    def test_ssid_when_no_name_or_hostname(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            ssid="Home",
        )
        assert _best_name(device) == "Home"

    @pytest.mark.timeout(30)
    def test_vendor_when_no_name_or_ssid(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            vendor="TP-Link",
        )
        assert _best_name(device) == "TP-Link device"

    @pytest.mark.timeout(30)
    def test_mac_as_fallback(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
        )
        assert _best_name(device) == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.timeout(30)
    def test_hidden_ssid_uses_vendor(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            ssid="<Hidden>",
            vendor="Netgear",
        )
        assert _best_name(device) == "Netgear device"


class TestDisplayResults:
    """Tests for result display."""

    @pytest.mark.timeout(30)
    def test_no_devices(self, in_memory_engine, capsys) -> None:
        with get_session(in_memory_engine) as session:
            _display_results(session)
        captured = capsys.readouterr()
        assert "No devices found" in captured.out

    @pytest.mark.timeout(30)
    def test_with_devices(self, in_memory_engine, capsys) -> None:
        now = datetime.now(UTC)
        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="AA:BB:CC:DD:EE:FF",
                device_type="wifi_ap",
                ssid="TestNet",
                vendor="TestVendor",
                authentication="WPA2",
                encryption="CCMP",
                radio_type="802.11ac",
                channel=36,
            )
            session.add(device)
            session.flush()

            window = VisibilityWindow(
                mac_address="AA:BB:CC:DD:EE:FF",
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-65.0,
                scan_count=1,
            )
            session.add(window)
            session.flush()

            _display_results(session)

        captured = capsys.readouterr()
        assert "DISCOVERED DEVICES" in captured.out
        assert "TestNet" in captured.out
        assert "TestVendor" in captured.out
        assert "Total devices:" in captured.out

    @pytest.mark.timeout(30)
    def test_hides_multicast_protocol_entries(self, in_memory_engine, capsys) -> None:
        now = datetime.now(UTC)
        with get_session(in_memory_engine) as session:
            session.add(
                Device(
                    mac_address="33:33:00:00:00:01",
                    device_type="network",
                    extra_info="IPv6: ff02::1 (Permanent)",
                )
            )
            session.add(
                VisibilityWindow(
                    mac_address="33:33:00:00:00:01",
                    first_seen=now,
                    last_seen=now,
                    scan_count=1,
                )
            )
            session.flush()

            _display_results(session)

        captured = capsys.readouterr()
        assert "No devices found" in captured.out
        assert "33:33:00:00:00:01" not in captured.out


class TestRunScan:
    """Integration-level tests for the full scan cycle."""

    @patch("src.main.scan_arp_table")
    @patch("src.main.scan_bluetooth_devices")
    @patch("src.main.scan_wifi_networks")
    @patch("src.main.platform.system", return_value="Windows")
    @patch("src.main.init_database")
    @pytest.mark.timeout(30)
    def test_full_scan_with_mocked_scanners(
        self,
        mock_init_db,
        _mock_platform,
        mock_wifi_scan,
        mock_bt_scan,
        mock_arp_scan,
    ) -> None:
        """Test full scan cycle with mocked external dependencies."""
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        from src.wifi_scanner import WifiNetwork

        mock_wifi_scan.return_value = [
            WifiNetwork(
                ssid="MockNet",
                bssid="AA:BB:CC:DD:EE:FF",
                network_type="Infrastructure",
                authentication="WPA2-Personal",
                encryption="CCMP",
                signal_percent=80,
                signal_dbm=-60.0,
                radio_type="802.11ac",
                channel=36,
            )
        ]

        from src.bluetooth_scanner import BluetoothDevice

        mock_bt_scan.return_value = [BluetoothDevice(mac_address="11:22:33:44:55:66", device_name="MockPhone")]

        from src.network_discovery import NetworkDevice

        mock_arp_scan.return_value = [
            NetworkDevice(
                ip_address="192.168.1.100",
                mac_address="AA:00:CC:DD:EE:FF",
                hostname="my-laptop",
            )
        ]

        config = AppConfig()
        config.scan.mdns_enabled = False
        config.scan.ssdp_enabled = False
        config.scan.netbios_enabled = False
        config.scan.ipv6_enabled = False
        run_scan(config)

        with get_session(engine) as session:
            devices = session.query(Device).all()
            assert len(devices) == 3

    @patch("src.main.scan_arp_table")
    @patch("src.main.scan_bluetooth_devices")
    @patch("src.main.scan_wifi_networks")
    @patch("src.main.platform.system", return_value="Windows")
    @patch("src.main.init_database")
    @pytest.mark.timeout(30)
    def test_scan_handles_scanner_errors(
        self,
        mock_init_db,
        _mock_platform,
        mock_wifi_scan,
        mock_bt_scan,
        mock_arp_scan,
    ) -> None:
        """Test that scan continues even if individual scanners fail."""
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        mock_wifi_scan.side_effect = RuntimeError("WiFi not available")
        mock_bt_scan.side_effect = RuntimeError("BT not available")
        mock_arp_scan.return_value = []

        config = AppConfig()
        config.scan.mdns_enabled = False
        config.scan.ssdp_enabled = False
        config.scan.netbios_enabled = False
        config.scan.ipv6_enabled = False
        run_scan(config)

    @patch("src.main.scan_ble_devices")
    @patch("src.main.scan_wifi_networks")
    @patch("src.main.platform.system", return_value="Linux")
    @pytest.mark.timeout(30)
    def test_runs_wifi_and_ble_scanners_on_linux(
        self,
        _mock_platform,
        mock_wifi_scan,
        mock_ble_scan,
    ) -> None:
        """Linux runs should execute WiFi and BLE scanners when enabled."""
        from src.bluetooth_scanner import BluetoothDevice
        from src.wifi_scanner import WifiNetwork

        config = AppConfig()
        config.scan.arp_enabled = False
        config.scan.bluetooth_enabled = False
        config.scan.mdns_enabled = False
        config.scan.ssdp_enabled = False
        config.scan.netbios_enabled = False
        config.scan.ipv6_enabled = False

        mock_wifi_scan.return_value = [
            WifiNetwork(
                ssid="LinuxWiFi",
                bssid="AA:BB:CC:DD:EE:FF",
                network_type="Infrastructure",
                authentication="WPA2",
                encryption="WPA2",
                signal_percent=70,
                signal_dbm=-65.0,
                radio_type="",
                channel=11,
            )
        ]
        mock_ble_scan.return_value = [
            BluetoothDevice(mac_address="11:22:33:44:55:66", device_name="Beacon", device_class="BLE")
        ]

        data = _execute_all_scanners(config)

        assert len(data.wifi_networks) == 1
        assert len(data.bt_devices) == 1
        mock_wifi_scan.assert_called_once()
        mock_ble_scan.assert_called_once()


class TestMergeBluetoothDevices:
    """Tests for deduplicating merged Bluetooth device lists."""

    @pytest.mark.timeout(30)
    def test_merges_duplicate_mac(self) -> None:
        from src.bluetooth_scanner import BluetoothDevice

        existing = [BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", device_name=None, is_paired=False)]
        additional = [
            BluetoothDevice(
                mac_address="AA:BB:CC:DD:EE:FF",
                device_name="Beacon",
                is_paired=True,
                device_class="BLE",
            )
        ]

        merged = _merge_bluetooth_devices(existing, additional)

        assert len(merged) == 1
        assert merged[0].device_name == "Beacon"
        assert merged[0].is_paired is True


class TestMergeNetworkDevices:
    """Tests for network device merging after ping sweeps."""

    @pytest.mark.timeout(30)
    def test_merges_duplicate_mac(self) -> None:
        from src.network_discovery import NetworkDevice

        existing = [NetworkDevice(ip_address="192.168.0.10", mac_address="AA:BB:CC:DD:EE:FF")]
        refreshed = [
            NetworkDevice(
                ip_address="192.168.0.20",
                mac_address="AA:BB:CC:DD:EE:FF",
                hostname="host",
                interface="wifi",
            )
        ]

        merged = _merge_network_devices_by_mac(existing, refreshed)

        assert len(merged) == 1
        assert merged[0].ip_address == "192.168.0.20"
        assert merged[0].hostname == "host"
        assert merged[0].interface == "wifi"

    @pytest.mark.timeout(30)
    def test_drops_ping_sweep_pseudo_device_when_arp_has_same_ip(self) -> None:
        from src.network_discovery import NetworkDevice

        arp_devices = [NetworkDevice(ip_address="192.168.0.10", mac_address="AA:BB:CC:DD:EE:FF")]
        ping_devices = [
            NetworkDevice(ip_address="192.168.0.10", mac_address="02:00:C0:A8:00:0A"),
            NetworkDevice(ip_address="192.168.0.11", mac_address="02:00:C0:A8:00:0B"),
        ]

        remaining = _drop_ping_sweep_devices_with_arp_match(arp_devices, ping_devices)

        assert [device.ip_address for device in remaining] == ["192.168.0.11"]


class TestForcedHostDiscoverySubnets:
    """Tests for implicit host-discovery subnet safety."""

    @pytest.mark.timeout(30)
    def test_keeps_small_subnets(self) -> None:
        assert _subnets_safe_for_forced_host_discovery(["192.168.0.0/24"]) == ["192.168.0.0/24"]

    @pytest.mark.timeout(30)
    def test_skips_large_subnets(self) -> None:
        assert _subnets_safe_for_forced_host_discovery(["10.0.0.0/8"]) == []

    @pytest.mark.timeout(30)
    def test_skips_medium_virtual_subnets(self) -> None:
        assert _subnets_safe_for_forced_host_discovery(["172.17.32.0/20"]) == []

    @pytest.mark.timeout(30)
    def test_skips_host_routes_and_public_routes(self) -> None:
        assert _subnets_safe_for_forced_host_discovery(["192.168.0.20/32", "155.4.74.144/32"]) == []

    @pytest.mark.timeout(30)
    def test_skips_invalid_subnets(self) -> None:
        assert _subnets_safe_for_forced_host_discovery(["not-a-subnet"]) == []


class TestParallelPortScan:
    """Tests for host-level port scan parallelism."""

    @patch("src.main.scan_host_ports")
    @pytest.mark.timeout(30)
    def test_scans_multiple_hosts_with_host_workers(self, mock_scan: MagicMock) -> None:
        import threading
        import time

        from src.port_scanner import OpenPort

        active = 0
        max_active = 0
        lock = threading.Lock()

        def fake_scan(ip_address: str, **_kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return [OpenPort(80, "http")] if ip_address.endswith(".1") else []

        mock_scan.side_effect = fake_scan
        cfg = AppConfig()
        cfg.port_scan.host_workers = 2
        cfg.port_scan.ports = [80]

        results = _scan_port_targets_parallel(
            [
                _PortScanTarget("AA:BB:CC:DD:EE:01", "192.168.0.1"),
                _PortScanTarget("AA:BB:CC:DD:EE:02", "192.168.0.2"),
                _PortScanTarget("AA:BB:CC:DD:EE:03", "192.168.0.3"),
            ],
            cfg,
        )

        assert len(results) == 3
        assert max_active == 2
        assert sum(len(result.open_ports) for result in results) == 1


class TestHandleShutdown:
    """Tests for _handle_shutdown signal handler."""

    @pytest.mark.timeout(30)
    def test_sets_shutdown_flag(self) -> None:
        import src.main as m

        m._shutdown_requested = False
        _handle_shutdown(2, None)
        assert m._shutdown_requested is True
        # Reset for other tests
        m._shutdown_requested = False

    @pytest.mark.timeout(30)
    def test_sets_flag_with_sigterm(self) -> None:
        import src.main as m

        m._shutdown_requested = False
        _handle_shutdown(15, None)
        assert m._shutdown_requested is True
        m._shutdown_requested = False


class TestFriendlyVendorEdgeCases:
    """Additional edge-case tests for _friendly_vendor."""

    @patch("src.main.is_randomized_mac", side_effect=ValueError("bad mac"))
    @pytest.mark.timeout(30)
    def test_value_error_returns_unknown(self, _mock_rand: MagicMock) -> None:
        result = _friendly_vendor(None, "INVALID")
        assert result == "(Unknown vendor)"


class TestBestNameWhitelist:
    """Tests for _best_name with whitelist integration."""

    @pytest.mark.timeout(30)
    def test_whitelist_custom_name(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            device_name="Original",
        )
        wl = MagicMock()
        wl.get_custom_name.return_value = "My Printer (Whitelist)"
        assert _best_name(device, wl) == "My Printer (Whitelist)"

    @pytest.mark.timeout(30)
    def test_whitelist_no_custom_name_falls_through(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            device_name="Original",
        )
        wl = MagicMock()
        wl.get_custom_name.return_value = None
        assert _best_name(device, wl) == "Original"


class TestUpsertMdnsDevice:
    """Tests for _upsert_mdns_device — insert and update paths."""

    @pytest.mark.timeout(30)
    def test_insert_new_mdns_device(self, in_memory_engine) -> None:
        from src.mdns_scanner import MdnsDevice

        mdns_dev = MdnsDevice(
            hostname="printer.local",
            ip_address="192.168.1.50",
            mac_address="AA:BB:CC:DD:EE:01",
            service_type="ipp",
            vendor="Brother",
        )
        wl = MagicMock()
        wl.is_known.return_value = False
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            _upsert_mdns_device(session, mdns_dev, wl, alert_mgr, gap_seconds=300)
            session.flush()

            device = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:01").first()
            assert device is not None
            assert device.hostname == "printer.local"
            assert device.vendor == "Brother"
            assert "mDNS: ipp" in device.extra_info
            alert_mgr.on_new_device.assert_called_once()

    @pytest.mark.timeout(30)
    def test_update_existing_mdns_device(self, in_memory_engine) -> None:
        from src.mdns_scanner import MdnsDevice

        wl = MagicMock()
        wl.is_known.return_value = False
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            # Pre-insert a device
            existing = Device(
                mac_address="AA:BB:CC:DD:EE:02",
                device_type="network",
                hostname="old-name.local",
                vendor="OldVendor",
            )
            session.add(existing)
            session.flush()

            mdns_dev = MdnsDevice(
                hostname="new-name.local",
                ip_address="192.168.1.60",
                mac_address="AA:BB:CC:DD:EE:02",
                service_type="http",
                vendor="NewVendor",
            )
            _upsert_mdns_device(session, mdns_dev, wl, alert_mgr, gap_seconds=300)
            session.flush()

            device = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:02").first()
            assert device.hostname == "new-name.local"
            assert device.vendor == "NewVendor"
            # on_new_device should NOT be called for updates
            alert_mgr.on_new_device.assert_not_called()

    @pytest.mark.timeout(30)
    def test_skip_device_without_mac(self, in_memory_engine) -> None:
        from src.mdns_scanner import MdnsDevice

        mdns_dev = MdnsDevice(
            hostname="no-mac.local",
            ip_address="192.168.1.70",
            mac_address="",  # No MAC
        )
        wl = MagicMock()
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            _upsert_mdns_device(session, mdns_dev, wl, alert_mgr, gap_seconds=300)
            session.flush()
            assert session.query(Device).count() == 0


class TestUpsertSsdpDevice:
    """Tests for _upsert_ssdp_device — insert and update paths."""

    @pytest.mark.timeout(30)
    def test_insert_new_ssdp_device(self, in_memory_engine) -> None:
        from src.ssdp_scanner import SsdpDevice

        ssdp_dev = SsdpDevice(
            ip_address="192.168.1.80",
            mac_address="BB:CC:DD:EE:FF:01",
            server="MediaServer/1.0",
            vendor="Samsung",
        )
        wl = MagicMock()
        wl.is_known.return_value = False
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            _upsert_ssdp_device(session, ssdp_dev, wl, alert_mgr, gap_seconds=300)
            session.flush()

            device = session.query(Device).filter_by(mac_address="BB:CC:DD:EE:FF:01").first()
            assert device is not None
            assert device.device_name == "MediaServer/1.0"
            assert "SSDP: MediaServer/1.0" in device.extra_info
            alert_mgr.on_new_device.assert_called_once()

    @pytest.mark.timeout(30)
    def test_update_existing_ssdp_device(self, in_memory_engine) -> None:
        from src.ssdp_scanner import SsdpDevice

        wl = MagicMock()
        wl.is_known.return_value = False
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            existing = Device(
                mac_address="BB:CC:DD:EE:FF:02",
                device_type="network",
                extra_info="SSDP: OldServer",
            )
            session.add(existing)
            session.flush()

            ssdp_dev = SsdpDevice(
                ip_address="192.168.1.90",
                mac_address="BB:CC:DD:EE:FF:02",
                server="NewServer/2.0",
                vendor="LG",
            )
            _upsert_ssdp_device(session, ssdp_dev, wl, alert_mgr, gap_seconds=300)
            session.flush()

            device = session.query(Device).filter_by(mac_address="BB:CC:DD:EE:FF:02").first()
            assert device.vendor == "LG"
            assert "NewServer/2.0" in device.extra_info
            alert_mgr.on_new_device.assert_not_called()

    @pytest.mark.timeout(30)
    def test_skip_device_without_mac(self, in_memory_engine) -> None:
        from src.ssdp_scanner import SsdpDevice

        ssdp_dev = SsdpDevice(ip_address="192.168.1.99", mac_address="")
        wl = MagicMock()
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            _upsert_ssdp_device(session, ssdp_dev, wl, alert_mgr, gap_seconds=300)
            session.flush()
            assert session.query(Device).count() == 0


class TestUpsertNetworkDeviceUpdate:
    """Tests for _upsert_network_device — update path."""

    @pytest.mark.timeout(30)
    def test_update_existing_network_device(self, in_memory_engine) -> None:
        from src.network_discovery import NetworkDevice

        wl = MagicMock()
        wl.is_known.return_value = False
        alert_mgr = MagicMock()

        with get_session(in_memory_engine) as session:
            existing = Device(
                mac_address="CC:DD:EE:FF:00:11",
                device_type="network",
                hostname="old-host",
                vendor="OldVendor",
            )
            session.add(existing)
            session.flush()

            arp_dev = NetworkDevice(
                ip_address="192.168.1.41",
                mac_address="CC:DD:EE:FF:00:11",
                hostname="new-host",
                vendor="NewVendor",
            )
            _upsert_network_device(session, arp_dev, wl, alert_mgr, {}, gap_seconds=300)
            session.flush()

            device = session.query(Device).filter_by(mac_address="CC:DD:EE:FF:00:11").first()
            assert device.hostname == "new-host"
            assert device.vendor == "NewVendor"
            assert device.ip_address == "192.168.1.41"
            alert_mgr.on_new_device.assert_not_called()


class TestCategorizeAllDevices:
    """Tests for _categorize_all_devices with whitelist category."""

    @pytest.mark.timeout(30)
    def test_whitelist_category_applied(self, in_memory_engine) -> None:
        wl = MagicMock()
        entry = MagicMock()
        entry.category = "smart_home"
        wl.get_entry.return_value = entry
        wl.is_known.return_value = True

        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="DD:EE:FF:00:11:22",
                device_type="network",
                category=None,
            )
            session.add(device)
            session.flush()

            _categorize_all_devices(session, wl)
            session.flush()

            updated = session.query(Device).filter_by(mac_address="DD:EE:FF:00:11:22").first()
            assert updated.category == "smart_home"
            assert updated.is_whitelisted is True


class TestDisplayWhitelistedDevice:
    """Tests for displaying whitelisted devices with checkmark."""

    @pytest.mark.timeout(30)
    def test_whitelisted_device_has_checkmark(self, in_memory_engine, capsys) -> None:
        now = datetime.now(UTC)
        wl = MagicMock()
        wl.get_custom_name.return_value = "KnownDevice"

        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="EE:FF:00:11:22:33",
                device_type="network",
                vendor="TestCorp",
                is_whitelisted=True,
            )
            session.add(device)
            session.flush()

            window = VisibilityWindow(
                mac_address="EE:FF:00:11:22:33",
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-50.0,
                scan_count=1,
            )
            session.add(window)
            session.flush()

            _display_results(session, wl)

        captured = capsys.readouterr()
        assert "✓" in captured.out


class TestImportAndScanWrappers:
    """Tests for _import_and_scan_mdns and _import_and_scan_ssdp."""

    @patch("src.mdns_scanner.scan_mdns_services")
    @pytest.mark.timeout(30)
    def test_import_and_scan_mdns(self, mock_scan: MagicMock) -> None:
        from src.mdns_scanner import MdnsDevice

        mock_scan.return_value = [MdnsDevice(hostname="test.local", ip_address="10.0.0.1")]
        result = _import_and_scan_mdns()
        assert len(result) == 1

    @patch("src.ssdp_scanner.scan_ssdp_devices")
    @pytest.mark.timeout(30)
    def test_import_and_scan_ssdp(self, mock_scan: MagicMock) -> None:
        from src.ssdp_scanner import SsdpDevice

        mock_scan.return_value = [SsdpDevice(ip_address="10.0.0.2", server="TestServer")]
        result = _import_and_scan_ssdp()
        assert len(result) == 1


class TestResolveNetbios:
    """Tests for _resolve_netbios helper."""

    @patch("src.netbios_scanner.resolve_netbios_names")
    @pytest.mark.timeout(30)
    def test_resolve_success(self, mock_resolve: MagicMock) -> None:
        from src.network_discovery import NetworkDevice

        nb_info = MagicMock()
        nb_info.ip_address = "192.168.1.1"
        nb_info.netbios_name = "DESKTOP-PC"
        mock_resolve.return_value = [nb_info]

        devices = [NetworkDevice(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:FF")]
        result = _resolve_netbios(devices)
        assert result == {"192.168.1.1": "DESKTOP-PC"}

    @patch("src.netbios_scanner.resolve_netbios_names", side_effect=RuntimeError("fail"))
    @pytest.mark.timeout(30)
    def test_resolve_error_returns_empty(self, _mock: MagicMock) -> None:
        from src.network_discovery import NetworkDevice

        devices = [NetworkDevice(ip_address="192.168.1.2", mac_address="11:22:33:44:55:66")]
        result = _resolve_netbios(devices)
        assert result == {}


class TestContinuousMode:
    """Tests for continuous scanning mode."""

    @patch("src.main._run_single_scan")
    @patch("src.main.init_database")
    @pytest.mark.timeout(30)
    def test_continuous_mode_shutdown(
        self,
        mock_init_db: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Continuous mode stops when shutdown is requested."""
        import src.main as m

        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        # Shutdown after first scan
        def trigger_shutdown(*_args: object, **_kwargs: object) -> None:
            m._shutdown_requested = True

        mock_scan.side_effect = trigger_shutdown
        m._shutdown_requested = False

        config = AppConfig()
        config.scan.continuous = True
        config.scan.interval_seconds = 1
        run_scan(config)

        assert mock_scan.call_count == 1
        m._shutdown_requested = False


class TestRunScanDefaultConfig:
    """Tests for run_scan with default config loading."""

    @patch("src.main._run_single_scan")
    @patch("src.main.init_database")
    @patch("src.main.load_config")
    @pytest.mark.timeout(30)
    def test_loads_default_config_when_none(
        self,
        mock_load_config: MagicMock,
        mock_init_db: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        default_config = AppConfig()
        default_config.scan.mdns_enabled = False
        default_config.scan.ssdp_enabled = False
        default_config.scan.netbios_enabled = False
        mock_load_config.return_value = default_config

        run_scan(None)
        mock_load_config.assert_called_once()


class TestRunScanWithAllScanners:
    """Tests for run_scan with mDNS/SSDP/NetBIOS enabled."""

    @patch("src.main._resolve_netbios")
    @patch("src.main._import_and_scan_ssdp")
    @patch("src.main._import_and_scan_mdns")
    @patch("src.main.scan_arp_table")
    @patch("src.main.scan_bluetooth_devices")
    @patch("src.main.scan_wifi_networks")
    @patch("src.main.init_database")
    @pytest.mark.timeout(30)
    def test_all_scanners_enabled(
        self,
        mock_init_db: MagicMock,
        mock_wifi: MagicMock,
        mock_bt: MagicMock,
        mock_arp: MagicMock,
        mock_mdns: MagicMock,
        mock_ssdp: MagicMock,
        mock_netbios: MagicMock,
    ) -> None:
        from src.mdns_scanner import MdnsDevice
        from src.network_discovery import NetworkDevice
        from src.ssdp_scanner import SsdpDevice

        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        mock_wifi.return_value = []
        mock_bt.return_value = []
        mock_arp.return_value = [
            NetworkDevice(
                ip_address="192.168.1.100",
                mac_address="AA:00:CC:DD:EE:FF",
            )
        ]
        mock_mdns.return_value = [
            MdnsDevice(
                hostname="chromecast.local",
                ip_address="192.168.1.101",
                mac_address="BB:00:CC:DD:EE:FF",
                service_type="googlecast",
                vendor="Google",
            )
        ]
        mock_ssdp.return_value = [
            SsdpDevice(
                ip_address="192.168.1.102",
                mac_address="CC:00:CC:DD:EE:FF",
                server="Samsung TV",
                vendor="Samsung",
            )
        ]
        mock_netbios.return_value = {"192.168.1.100": "MY-PC"}

        config = AppConfig()
        config.scan.ble_enabled = False
        config.scan.mdns_enabled = True
        config.scan.ssdp_enabled = True
        config.scan.netbios_enabled = True
        config.scan.ipv6_enabled = False
        run_scan(config)

        with get_session(engine) as session:
            devices = session.query(Device).all()
            assert len(devices) == 3  # ARP + mDNS + SSDP


class TestMainEntryPoint:
    """Tests for main() CLI entry point."""

    @patch("src.main.run_scan", side_effect=KeyboardInterrupt)
    @patch("src.main.load_config")
    @pytest.mark.timeout(30)
    def test_keyboard_interrupt_exit_zero(self, mock_cfg: MagicMock, _mock_scan: MagicMock) -> None:
        mock_cfg.return_value.api.enabled = False
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    @patch("src.main.run_scan", side_effect=RuntimeError("fatal"))
    @patch("src.main.load_config")
    @pytest.mark.timeout(30)
    def test_fatal_error_exit_one(self, mock_cfg: MagicMock, _mock_scan: MagicMock) -> None:
        mock_cfg.return_value.api.enabled = False
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("src.main.run_scan")
    @patch("src.main.load_config")
    @pytest.mark.timeout(30)
    def test_normal_exit(self, mock_cfg: MagicMock, _mock_scan: MagicMock) -> None:
        mock_cfg.return_value.api.enabled = False
        # Should complete without raising
        main()

    @patch("src.main.run_scan")
    @patch("src.main.load_config")
    @pytest.mark.timeout(30)
    def test_rescan_ports_enables_port_scan(self, mock_cfg: MagicMock, mock_run_scan: MagicMock) -> None:
        """--rescan-ports must enable port_scan.enabled even when it defaults to False."""
        import sys

        cfg = AppConfig()
        cfg.api.enabled = False
        cfg.port_scan.enabled = False  # default disabled
        mock_cfg.return_value = cfg

        with patch.object(sys, "argv", ["btwifi", "--rescan-ports"]):
            main()

        assert cfg.port_scan.enabled is True
        mock_run_scan.assert_called_once()

    @patch("src.main.run_scan")
    @patch("src.main.load_config")
    @pytest.mark.timeout(30)
    def test_full_port_scan_sets_full_range_and_rescans(self, mock_cfg: MagicMock, mock_run_scan: MagicMock) -> None:
        """--full-port-scan scans TCP 1-65535 and implies a forced rescan."""
        import sys

        cfg = AppConfig()
        cfg.api.enabled = False
        cfg.port_scan.enabled = False
        mock_cfg.return_value = cfg

        with patch.object(sys, "argv", ["btwifi", "--full-port-scan"]):
            main()

        assert cfg.port_scan.enabled is True
        assert cfg.port_scan.ports[0] == 1
        assert cfg.port_scan.ports[-1] == 65535
        assert len(cfg.port_scan.ports) == 65535
        assert cfg.port_scan.max_workers >= 200
        assert cfg.port_scan.host_workers >= 4
        mock_run_scan.assert_called_once_with(cfg, rescan_ports=True)
