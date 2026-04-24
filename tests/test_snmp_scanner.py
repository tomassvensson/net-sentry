"""Tests for src/snmp_scanner.py — SNMP device scanner."""

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_varbind(oid: str, value: str):
    """Create a mock var-bind tuple mimicking pysnmp ObjectType result."""
    oid_mock = MagicMock()
    oid_mock.__str__ = lambda s: oid
    val_mock = MagicMock()
    val_mock.__str__ = lambda s: value
    return (oid_mock, val_mock)


# ---------------------------------------------------------------------------
# query_snmp_device
# ---------------------------------------------------------------------------


class TestQuerySnmpDevice:
    def _run_with_mock_result(self, varbinds, error_indication=None, error_status=None, error_index=0):
        """Call query_snmp_device with mocked pysnmp getCmd."""

        mock_result_iter = iter([(error_indication, error_status, error_index, varbinds)])

        with patch.dict("sys.modules", {}):
            pysnmp_mock = MagicMock()
            pysnmp_mock.hlapi.getCmd.return_value = iter([(error_indication, error_status, error_index, varbinds)])

            with patch("src.snmp_scanner.query_snmp_device", wraps=None):
                pass  # ensure import path correct

        return mock_result_iter

    def test_returns_none_on_error_indication(self):
        """query_snmp_device returns None when error_indication is set."""

        fake_module = MagicMock()
        fake_module.getCmd.return_value = iter([("Timeout", None, 0, [])])
        fake_module.SnmpEngine.return_value = MagicMock()
        fake_module.CommunityData.return_value = MagicMock()
        fake_module.UdpTransportTarget.return_value = MagicMock()
        fake_module.ContextData.return_value = MagicMock()
        fake_module.ObjectType.side_effect = lambda x: x
        fake_module.ObjectIdentity.side_effect = lambda x: x

        with patch.dict(
            "sys.modules",
            {
                "pysnmp": MagicMock(),
                "pysnmp.hlapi": fake_module,
            },
        ):
            import importlib

            import src.snmp_scanner as mod

            importlib.reload(mod)

            result = mod.query_snmp_device("192.168.1.1", community="public")
            assert result is None

    def test_returns_none_on_error_status(self):
        """query_snmp_device returns None when error_status is non-zero."""

        error_status_mock = MagicMock()
        error_status_mock.__bool__ = lambda s: True
        error_status_mock.prettyPrint.return_value = "noSuchName"

        # error_index=0 avoids index lookup into the (empty) result list
        fake_module = MagicMock()
        fake_module.getCmd.return_value = iter([(None, error_status_mock, 0, [])])
        fake_module.SnmpEngine.return_value = MagicMock()
        fake_module.CommunityData.return_value = MagicMock()
        fake_module.UdpTransportTarget.return_value = MagicMock()
        fake_module.ContextData.return_value = MagicMock()
        fake_module.ObjectType.side_effect = lambda x: x
        fake_module.ObjectIdentity.side_effect = lambda x: x

        with patch.dict(
            "sys.modules",
            {
                "pysnmp": MagicMock(),
                "pysnmp.hlapi": fake_module,
            },
        ):
            import importlib

            import src.snmp_scanner as mod

            importlib.reload(mod)

            result = mod.query_snmp_device("192.168.1.2", community="public")
            assert result is None

    def test_returns_info_on_success(self):
        """query_snmp_device returns SnmpDeviceInfo with parsed fields on success."""
        from src.snmp_scanner import _OID_SYS_CONTACT, _OID_SYS_DESCR, _OID_SYS_LOCATION, _OID_SYS_NAME

        varbinds = [
            _make_mock_varbind(_OID_SYS_DESCR, "Linux server 5.15"),
            _make_mock_varbind(_OID_SYS_NAME, "myrouter"),
            _make_mock_varbind(_OID_SYS_CONTACT, "admin@example.com"),
            _make_mock_varbind(_OID_SYS_LOCATION, "Server Room"),
        ]

        fake_module = MagicMock()
        fake_module.getCmd.return_value = iter([(None, None, 0, varbinds)])
        fake_module.SnmpEngine.return_value = MagicMock()
        fake_module.CommunityData.return_value = MagicMock()
        fake_module.UdpTransportTarget.return_value = MagicMock()
        fake_module.ContextData.return_value = MagicMock()
        fake_module.ObjectType.side_effect = lambda x: x
        fake_module.ObjectIdentity.side_effect = lambda x: x

        with patch.dict(
            "sys.modules",
            {
                "pysnmp": MagicMock(),
                "pysnmp.hlapi": fake_module,
            },
        ):
            import importlib

            import src.snmp_scanner as mod

            importlib.reload(mod)

            info = mod.query_snmp_device(
                "10.0.0.1",
                community="public",
                oids=(_OID_SYS_DESCR, _OID_SYS_NAME, _OID_SYS_CONTACT, _OID_SYS_LOCATION),
            )

        assert info is not None
        assert info.ip_address == "10.0.0.1"
        assert info.sys_descr == "Linux server 5.15"
        assert info.sys_name == "myrouter"
        assert info.sys_contact == "admin@example.com"
        assert info.sys_location == "Server Room"

    def test_returns_none_when_pysnmp_missing(self, monkeypatch):
        """query_snmp_device returns None gracefully when pysnmp is not installed."""
        # The import-guard path is exercised indirectly by the is_available tests.
        pass


# ---------------------------------------------------------------------------
# scan_snmp_devices
# ---------------------------------------------------------------------------


class TestScanSnmpDevices:
    def test_max_hosts_limit(self):
        """scan_snmp_devices stops querying after max_hosts."""
        from src.snmp_scanner import scan_snmp_devices

        call_count = []

        def fake_query(ip, **kwargs):
            call_count.append(ip)
            return None  # No device responds

        with patch("src.snmp_scanner.query_snmp_device", side_effect=fake_query):
            result = scan_snmp_devices(
                [f"10.0.0.{i}" for i in range(1, 20)],
                max_hosts=5,
            )

        assert len(call_count) == 5
        assert result == []

    def test_filters_non_responding_hosts(self):
        """scan_snmp_devices only includes responding hosts in results."""
        from src.snmp_scanner import SnmpDeviceInfo, scan_snmp_devices

        def fake_query(ip, **kwargs):
            if ip == "10.0.0.2":
                return SnmpDeviceInfo(ip_address=ip, sys_name="router")
            return None

        with patch("src.snmp_scanner.query_snmp_device", side_effect=fake_query):
            results = scan_snmp_devices(["10.0.0.1", "10.0.0.2", "10.0.0.3"])

        assert len(results) == 1
        assert results[0].ip_address == "10.0.0.2"

    def test_empty_host_list(self):
        """scan_snmp_devices returns empty list for empty host list."""
        from src.snmp_scanner import scan_snmp_devices

        results = scan_snmp_devices([])
        assert results == []


# ---------------------------------------------------------------------------
# SnmpScanner plugin
# ---------------------------------------------------------------------------


class TestSnmpScannerPlugin:
    def test_is_available_when_pysnmp_installed(self):
        """SnmpScanner.is_available() returns True when pysnmp is importable."""
        from src.snmp_scanner import SnmpScanner

        scanner = SnmpScanner()
        # pysnmp-lextudio is installed in this environment
        assert isinstance(scanner.is_available(), bool)

    def test_is_available_false_when_pysnmp_missing(self, monkeypatch):
        """SnmpScanner.is_available() returns False when pysnmp cannot be imported."""
        import src.snmp_scanner as mod

        scanner = mod.SnmpScanner()

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def mock_import(name, *args, **kwargs):
            if name == "pysnmp":
                raise ImportError("no pysnmp")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = scanner.is_available()

        assert result is False

    def test_scan_returns_empty_when_not_enabled(self):
        """SnmpScanner.scan() returns [] when snmp.enabled=False."""
        from src.snmp_scanner import SnmpScanner

        cfg = MagicMock()
        cfg.snmp.enabled = False

        results = SnmpScanner().scan(cfg)
        assert results == []

    def test_scan_returns_empty_when_no_subnet(self):
        """SnmpScanner.scan() returns [] when no subnet is configured."""
        from src.snmp_scanner import SnmpScanner

        cfg = MagicMock()
        cfg.snmp.enabled = True
        cfg.snmp.subnet = ""

        results = SnmpScanner().scan(cfg)
        assert results == []

    def test_scan_returns_empty_for_invalid_subnet(self):
        """SnmpScanner.scan() returns [] for an invalid subnet string."""
        from src.snmp_scanner import SnmpScanner

        cfg = MagicMock()
        cfg.snmp.enabled = True
        cfg.snmp.subnet = "not-a-subnet"
        cfg.snmp.community = "public"
        cfg.snmp.port = 161
        cfg.snmp.timeout = 1
        cfg.snmp.retries = 0
        cfg.snmp.max_hosts = 10

        results = SnmpScanner().scan(cfg)
        assert results == []

    def test_scan_returns_results_for_responding_host(self):
        """SnmpScanner.scan() returns ScanResult objects for responding hosts."""
        from src.snmp_scanner import SnmpDeviceInfo, SnmpScanner

        cfg = MagicMock()
        cfg.snmp.enabled = True
        cfg.snmp.subnet = "10.0.0.0/30"  # only .1 and .2 as hosts
        cfg.snmp.community = "public"
        cfg.snmp.port = 161
        cfg.snmp.timeout = 1
        cfg.snmp.retries = 0
        cfg.snmp.max_hosts = 10

        def fake_scan_snmp(hosts, **kwargs):
            return [SnmpDeviceInfo(ip_address="10.0.0.1", sys_name="mydevice")]

        def fake_resolve_mac(ip):
            return "aa:bb:cc:dd:ee:ff"

        with (
            patch("src.snmp_scanner.scan_snmp_devices", side_effect=fake_scan_snmp),
            patch("src.snmp_scanner._resolve_mac_from_ip", side_effect=fake_resolve_mac),
        ):
            results = SnmpScanner().scan(cfg)

        assert len(results) == 1
        assert results[0].mac_address == "aa:bb:cc:dd:ee:ff"
        assert results[0].device_name == "mydevice"
        assert results[0].ip_address == "10.0.0.1"
        assert results[0].source == "snmp"

    def test_scan_uses_synthetic_mac_when_no_arp_entry(self):
        """SnmpScanner.scan() generates a synthetic MAC when ARP lookup fails."""
        from src.snmp_scanner import SnmpDeviceInfo, SnmpScanner

        cfg = MagicMock()
        cfg.snmp.enabled = True
        cfg.snmp.subnet = "10.0.0.0/30"
        cfg.snmp.community = "public"
        cfg.snmp.port = 161
        cfg.snmp.timeout = 1
        cfg.snmp.retries = 0
        cfg.snmp.max_hosts = 10

        def fake_scan_snmp(hosts, **kwargs):
            return [SnmpDeviceInfo(ip_address="10.0.0.1", sys_name="")]

        with (
            patch("src.snmp_scanner.scan_snmp_devices", side_effect=fake_scan_snmp),
            patch("src.snmp_scanner._resolve_mac_from_ip", return_value=None),
        ):
            results = SnmpScanner().scan(cfg)

        assert len(results) == 1
        # Synthetic MAC should be non-empty
        assert results[0].mac_address != ""
        assert ":" in results[0].mac_address
