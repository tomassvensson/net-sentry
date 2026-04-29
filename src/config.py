"""Application configuration management.

Loads configuration from a YAML file (config.yaml) with environment variable
overrides. Provides sensible defaults for all settings.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = "config.yaml"


@dataclass
class ScanConfig:
    """Scan timing and behavior settings."""

    continuous: bool = False
    interval_seconds: int = 60
    gap_seconds: int = 300
    wifi_enabled: bool = True
    bluetooth_enabled: bool = True
    ble_enabled: bool = True
    arp_enabled: bool = True
    mdns_enabled: bool = True
    ssdp_enabled: bool = True
    netbios_enabled: bool = True
    snmp_enabled: bool = False
    monitor_mode_enabled: bool = False
    ipv6_enabled: bool = True


@dataclass
class ArpConfig:
    """ARP hostname resolution settings."""

    resolve_hostnames: bool = True
    max_concurrent: int = 10
    timeout_seconds: float = 2.0
    min_delay_seconds: float = 0.05
    max_delay_seconds: float = 0.2
    jitter: bool = True


@dataclass
class SnmpConfig:
    """SNMP discovery settings."""

    enabled: bool = False
    community: str = "public"
    version: int = 2
    port: int = 161
    timeout_seconds: float = 2.0
    retries: int = 1
    max_hosts: int = 254
    subnet: str = ""
    target_hosts: list[str] = field(default_factory=list)


@dataclass
class PortScanConfig:
    """TCP port scanning settings.

    Port scan results are cached in the Device record and are only
    re-run when ``--rescan-ports`` is passed on the command line or
    when a device has no cached port data.
    """

    enabled: bool = False
    ports: list[int] = field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080, 8443])
    timeout_seconds: float = 0.5
    max_workers: int = 20


@dataclass
class HomeAssistantConfig:
    """Home Assistant REST API integration for device name enrichment.

    When enabled, Net Sentry queries the HA REST API once per scan cycle
    and uses ``device_tracker.*`` entity names and areas to enrich
    the device names stored in the database.
    """

    enabled: bool = False
    url: str = ""  # e.g. "http://homeassistant.local:8123"
    token: str = ""  # Long-lived access token
    timeout_seconds: float = 5.0


@dataclass
class PingSweepConfig:
    """Ping sweep discovery settings."""

    enabled: bool = False
    subnets: list[str] = field(default_factory=list)
    max_workers: int = 40
    timeout_seconds: float = 1.0
    # Optional human-readable labels for subnets.  Keys are CIDR strings
    # matching entries in ``subnets``; values are short label strings
    # (e.g. "office", "IoT", "guest") stored in Device.network_segment.
    subnet_labels: dict[str, str] = field(default_factory=dict)


@dataclass
class DatabaseConfig:
    """Database configuration."""

    url: str = "sqlite:///net-sentry.db"
    retention_days: int = 0  # 0 = keep forever
    vacuum_on_cleanup: bool = True


@dataclass
class AlertConfig:
    """Alert/notification settings."""

    enabled: bool = True
    log_new_devices: bool = True
    log_file: str | None = None
    sound_enabled: bool = False
    cooldown_seconds: int = 300  # Minimum seconds between alerts for the same MAC address


@dataclass
class WhitelistEntry:
    """A known/trusted device."""

    mac_address: str
    name: str = ""
    category: str = ""
    trusted: bool = True


@dataclass
class OuiConfig:
    """OUI database update settings."""

    auto_update: bool = True
    update_interval_hours: int = 168  # 1 week
    cache_file: str = "src/data/oui_cache.txt"


@dataclass
class MonitorModeConfig:
    """Monitor mode (scapy) settings."""

    interface: str = "wlan0mon"
    use_docker: bool = True
    docker_image: str = "net-sentry-monitor:latest"
    channel_hop: bool = True
    hop_interval_seconds: float = 0.5
    capture_duration_seconds: int = 30


@dataclass
class ApiConfig:
    """Web API and dashboard settings.

    Auth defaults (auth_enabled=False):
    - All endpoints are public.
    - Set auth_enabled=True and jwt_secret to protect /api/v1/* endpoints.
    - Obtain a token via POST /api/v1/auth/token with {username, password}.
    - Use Authorization: Bearer <token> header on subsequent requests.

    CORS defaults (cors_origins=["http://localhost", "http://127.0.0.1"]):
    - Override with a comma-separated list or a YAML list in config.yaml.
    - Set cors_origins=["*"] only for fully public deployments.
    """

    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8000
    auth_enabled: bool = False
    jwt_secret: str = "change-me-in-production-use-env-var"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    # username -> bcrypt-hashed password; add entries to protect the API.
    # Generate a hash: python -c "import bcrypt; print(bcrypt.hashpw(b'pass', bcrypt.gensalt()).decode())"
    api_users: dict[str, str] = field(default_factory=dict)
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost", "http://127.0.0.1"])


@dataclass
class MqttConfig:
    """MQTT publishing settings."""

    enabled: bool = False
    broker_host: str = "localhost"
    broker_port: int = 1883
    topic_prefix: str = "net-sentry"
    username: str | None = None
    password: str | None = None
    client_id: str = "net-sentry-scanner"


@dataclass
class MetricsConfig:
    """Prometheus metrics settings."""

    enabled: bool = True


@dataclass
class AppConfig:
    """Root application configuration."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    arp: ArpConfig = field(default_factory=ArpConfig)
    ping_sweep: PingSweepConfig = field(default_factory=PingSweepConfig)
    snmp: SnmpConfig = field(default_factory=SnmpConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    whitelist: list[WhitelistEntry] = field(default_factory=list)
    oui: OuiConfig = field(default_factory=OuiConfig)
    monitor_mode: MonitorModeConfig = field(default_factory=MonitorModeConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    mqtt: MqttConfig = field(default_factory=MqttConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    home_assistant: HomeAssistantConfig = field(default_factory=HomeAssistantConfig)


def load_config(config_path: str | None = None) -> AppConfig:
    """Load configuration from YAML file with env var overrides.

    Args:
        config_path: Path to YAML config file. Defaults to config.yaml.

    Returns:
        Populated AppConfig instance.
    """
    path = config_path or os.environ.get("NET_SENTRY_CONFIG") or os.environ.get("BTWIFI_CONFIG", _DEFAULT_CONFIG_PATH)
    config = AppConfig()

    if Path(path).exists():
        try:
            import yaml  # noqa: F811
        except ImportError:
            logger.warning("PyYAML not installed. Using default configuration. Install with: pip install pyyaml")
            return _apply_env_overrides(config)

        try:
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            config = _parse_raw_config(raw)
            logger.info("Configuration loaded from %s", path)
        except Exception:
            logger.exception("Failed to load config from %s, using defaults.", path)
    else:
        logger.debug("No config file at %s, using defaults.", path)

    return _apply_env_overrides(config)


def _parse_raw_config(raw: dict) -> AppConfig:
    """Parse a raw dictionary into an AppConfig.

    Args:
        raw: Dictionary from YAML parsing.

    Returns:
        Populated AppConfig.
    """
    config = AppConfig()

    if "scan" in raw:
        s = raw["scan"]
        config.scan = ScanConfig(
            continuous=s.get("continuous", config.scan.continuous),
            interval_seconds=s.get("interval_seconds", config.scan.interval_seconds),
            gap_seconds=s.get("gap_seconds", config.scan.gap_seconds),
            wifi_enabled=s.get("wifi_enabled", config.scan.wifi_enabled),
            bluetooth_enabled=s.get("bluetooth_enabled", config.scan.bluetooth_enabled),
            ble_enabled=s.get("ble_enabled", config.scan.ble_enabled),
            arp_enabled=s.get("arp_enabled", config.scan.arp_enabled),
            mdns_enabled=s.get("mdns_enabled", config.scan.mdns_enabled),
            ssdp_enabled=s.get("ssdp_enabled", config.scan.ssdp_enabled),
            netbios_enabled=s.get("netbios_enabled", config.scan.netbios_enabled),
            snmp_enabled=s.get("snmp_enabled", config.scan.snmp_enabled),
            monitor_mode_enabled=s.get("monitor_mode_enabled", config.scan.monitor_mode_enabled),
            ipv6_enabled=s.get("ipv6_enabled", config.scan.ipv6_enabled),
        )

    if "arp" in raw:
        a = raw["arp"]
        config.arp = ArpConfig(
            resolve_hostnames=a.get("resolve_hostnames", config.arp.resolve_hostnames),
            max_concurrent=a.get("max_concurrent", config.arp.max_concurrent),
            timeout_seconds=a.get("timeout_seconds", config.arp.timeout_seconds),
            min_delay_seconds=a.get("min_delay_seconds", config.arp.min_delay_seconds),
            max_delay_seconds=a.get("max_delay_seconds", config.arp.max_delay_seconds),
            jitter=a.get("jitter", config.arp.jitter),
        )

    if "ping_sweep" in raw:
        ps = raw["ping_sweep"]
        config.ping_sweep = PingSweepConfig(
            enabled=ps.get("enabled", config.ping_sweep.enabled),
            subnets=ps.get("subnets", config.ping_sweep.subnets),
            max_workers=ps.get("max_workers", config.ping_sweep.max_workers),
            timeout_seconds=ps.get("timeout_seconds", config.ping_sweep.timeout_seconds),
            subnet_labels=ps.get("subnet_labels", config.ping_sweep.subnet_labels),
        )

    if "port_scan" in raw:
        po = raw["port_scan"]
        config.port_scan = PortScanConfig(
            enabled=po.get("enabled", config.port_scan.enabled),
            ports=po.get("ports", config.port_scan.ports),
            timeout_seconds=po.get("timeout_seconds", config.port_scan.timeout_seconds),
            max_workers=po.get("max_workers", config.port_scan.max_workers),
        )

    if "home_assistant" in raw:
        ha = raw["home_assistant"]
        config.home_assistant = HomeAssistantConfig(
            enabled=ha.get("enabled", config.home_assistant.enabled),
            url=ha.get("url", config.home_assistant.url),
            token=ha.get("token", config.home_assistant.token),
            timeout_seconds=ha.get("timeout_seconds", config.home_assistant.timeout_seconds),
        )

    if "snmp" in raw:
        sn = raw["snmp"]
        timeout_seconds = sn.get("timeout_seconds", sn.get("timeout", config.snmp.timeout_seconds))
        config.snmp = SnmpConfig(
            enabled=sn.get("enabled", config.snmp.enabled),
            community=sn.get("community", config.snmp.community),
            version=sn.get("version", config.snmp.version),
            port=sn.get("port", config.snmp.port),
            timeout_seconds=timeout_seconds,
            retries=sn.get("retries", config.snmp.retries),
            max_hosts=sn.get("max_hosts", config.snmp.max_hosts),
            subnet=sn.get("subnet", config.snmp.subnet),
            target_hosts=sn.get("target_hosts", config.snmp.target_hosts),
        )

    if "database" in raw:
        db = raw["database"]
        config.database = DatabaseConfig(
            url=db.get("url", config.database.url),
            retention_days=db.get("retention_days", config.database.retention_days),
            vacuum_on_cleanup=db.get("vacuum_on_cleanup", config.database.vacuum_on_cleanup),
        )

    if "alert" in raw:
        al = raw["alert"]
        config.alert = AlertConfig(
            enabled=al.get("enabled", config.alert.enabled),
            log_new_devices=al.get("log_new_devices", config.alert.log_new_devices),
            log_file=al.get("log_file", config.alert.log_file),
            sound_enabled=al.get("sound_enabled", config.alert.sound_enabled),
            cooldown_seconds=al.get("cooldown_seconds", config.alert.cooldown_seconds),
        )

    if "whitelist" in raw:
        config.whitelist = [
            WhitelistEntry(
                mac_address=entry.get("mac_address", ""),
                name=entry.get("name", ""),
                category=entry.get("category", ""),
                trusted=entry.get("trusted", True),
            )
            for entry in raw["whitelist"]
            if isinstance(entry, dict) and entry.get("mac_address")
        ]

    if "oui" in raw:
        o = raw["oui"]
        config.oui = OuiConfig(
            auto_update=o.get("auto_update", config.oui.auto_update),
            update_interval_hours=o.get("update_interval_hours", config.oui.update_interval_hours),
            cache_file=o.get("cache_file", config.oui.cache_file),
        )

    if "monitor_mode" in raw:
        mm = raw["monitor_mode"]
        config.monitor_mode = MonitorModeConfig(
            interface=mm.get("interface", config.monitor_mode.interface),
            use_docker=mm.get("use_docker", config.monitor_mode.use_docker),
            docker_image=mm.get("docker_image", config.monitor_mode.docker_image),
            channel_hop=mm.get("channel_hop", config.monitor_mode.channel_hop),
            hop_interval_seconds=mm.get("hop_interval_seconds", config.monitor_mode.hop_interval_seconds),
            capture_duration_seconds=mm.get("capture_duration_seconds", config.monitor_mode.capture_duration_seconds),
        )

    if "api" in raw:
        ap = raw["api"]
        config.api = ApiConfig(
            enabled=ap.get("enabled", config.api.enabled),
            host=ap.get("host", config.api.host),
            port=ap.get("port", config.api.port),
            auth_enabled=ap.get("auth_enabled", config.api.auth_enabled),
            jwt_secret=ap.get("jwt_secret", config.api.jwt_secret),
            jwt_algorithm=ap.get("jwt_algorithm", config.api.jwt_algorithm),
            jwt_expire_minutes=ap.get("jwt_expire_minutes", config.api.jwt_expire_minutes),
            api_users=ap.get("api_users", config.api.api_users),
            cors_origins=ap.get("cors_origins", config.api.cors_origins),
        )

    if "mqtt" in raw:
        mq = raw["mqtt"]
        config.mqtt = MqttConfig(
            enabled=mq.get("enabled", config.mqtt.enabled),
            broker_host=mq.get("broker_host", config.mqtt.broker_host),
            broker_port=mq.get("broker_port", config.mqtt.broker_port),
            topic_prefix=mq.get("topic_prefix", config.mqtt.topic_prefix),
            username=mq.get("username", config.mqtt.username),
            password=mq.get("password", config.mqtt.password),
            client_id=mq.get("client_id", config.mqtt.client_id),
        )

    if "metrics" in raw:
        me = raw["metrics"]
        config.metrics = MetricsConfig(
            enabled=me.get("enabled", config.metrics.enabled),
        )

    return config


def _apply_env_overrides(config: AppConfig) -> AppConfig:
    """Apply environment variable overrides to configuration.

    Environment variables follow the pattern NET_SENTRY_<SECTION>_<KEY>.
    The legacy BTWIFI_* names are also accepted for backwards-compatibility.

    Args:
        config: Configuration to override.

    Returns:
        Configuration with env var overrides applied.
    """
    if db_url := os.environ.get("DATABASE_URL"):
        config.database.url = db_url

    if jwt_secret := (os.environ.get("NET_SENTRY_JWT_SECRET") or os.environ.get("BTWIFI_JWT_SECRET")):
        config.api.jwt_secret = jwt_secret

    if cors := (os.environ.get("NET_SENTRY_CORS_ORIGINS") or os.environ.get("BTWIFI_CORS_ORIGINS")):
        config.api.cors_origins = [o.strip() for o in cors.split(",") if o.strip()]

    if auth_enabled := (os.environ.get("NET_SENTRY_AUTH_ENABLED") or os.environ.get("BTWIFI_AUTH_ENABLED")):
        config.api.auth_enabled = auth_enabled.lower() in ("1", "true", "yes")

    if interval := (os.environ.get("NET_SENTRY_SCAN_INTERVAL") or os.environ.get("BTWIFI_SCAN_INTERVAL")):
        try:
            config.scan.interval_seconds = int(interval)
        except ValueError:
            logger.warning("Invalid NET_SENTRY_SCAN_INTERVAL: %s", interval)

    if continuous := (os.environ.get("NET_SENTRY_CONTINUOUS") or os.environ.get("BTWIFI_CONTINUOUS")):
        config.scan.continuous = continuous.lower() in ("1", "true", "yes")

    if gap := (os.environ.get("NET_SENTRY_GAP_SECONDS") or os.environ.get("BTWIFI_GAP_SECONDS")):
        try:
            config.scan.gap_seconds = int(gap)
        except ValueError:
            logger.warning("Invalid NET_SENTRY_GAP_SECONDS: %s", gap)

    return config
