"""Application configuration management.

Loads configuration from a YAML file (config.yaml) with environment variable
overrides. Provides sensible defaults for all settings.
"""

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = "config.yaml"
# Placeholder secret used in the example config.  If the loaded config still
# contains this value, a new random secret is generated and written back.
_PLACEHOLDER_JWT_SECRET = "change-me-in-production-use-env-var"


@dataclass
class ScanConfig:
    """Scan timing and behavior settings."""

    continuous: bool = False
    interval_seconds: int = 60
    gap_seconds: int = 300
    wifi_enabled: bool = True
    bluetooth_enabled: bool = True
    ble_enabled: bool = True
    ble_scanning_mode: Literal["active", "passive"] = "passive"
    arp_enabled: bool = True
    mdns_enabled: bool = True
    ssdp_enabled: bool = True
    netbios_enabled: bool = True
    snmp_enabled: bool = False
    monitor_mode_enabled: bool = False
    ipv6_enabled: bool = True
    dhcp_enabled: bool = False
    dhcp_lease_file: str = "/var/lib/dhcp/dhcpd.leases"


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
    max_workers: int = 20  # Concurrent port probes per host.
    host_workers: int = 4  # Concurrent hosts scanned during the port phase.


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
class AlertRule:
    """A configurable alert rule.

    rule_type "disappearance": fire when a specific device has not been seen
    for longer than ``threshold_minutes``.

    rule_type "time_window": fire when any new device is first discovered
    during the given hour window (0-23, end_hour exclusive, wraps midnight).
    """

    rule_type: str  # "disappearance" | "time_window"
    # -- disappearance fields --
    mac_address: str | None = None
    threshold_minutes: int = 30
    # -- time_window fields --
    start_hour: int = 0  # 0-23 inclusive
    end_hour: int = 6  # 0-23 exclusive (alert if start_hour <= hour < end_hour)
    device_type_filter: str | None = None  # optional; e.g. "bluetooth"
    # -- common --
    label: str = ""  # human-readable name for log messages


@dataclass
class AlertConfig:
    """Alert/notification settings."""

    enabled: bool = True
    log_new_devices: bool = True
    log_file: str | None = None
    sound_enabled: bool = False
    cooldown_seconds: int = 300  # Minimum seconds between alerts for the same MAC address
    rules: list[AlertRule] = field(default_factory=list)
    # Webhook URL for outbound alert notifications.  Leave empty to disable.
    webhook_url: str = ""
    # Payload format: "slack" (default) or "pagerduty"
    webhook_format: str = "slack"
    # Warn when a device reappears after being absent for at least this many days (0 = disabled)
    warn_returning_after_days: int = 14


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
class MdnsConfig:
    """mDNS scanner settings."""

    # If empty, all built-in service types are scanned.
    # Set to a list of service types to scan only those, e.g. ["_http._tcp.local.", "_ssh._tcp.local."]
    service_types: list[str] = field(default_factory=list)


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
class TracingConfig:
    """OpenTelemetry tracing settings."""

    enabled: bool = False
    service_name: str = "net-sentry"
    exporter: str = "console"


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
    mdns: MdnsConfig = field(default_factory=MdnsConfig)
    monitor_mode: MonitorModeConfig = field(default_factory=MonitorModeConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    mqtt: MqttConfig = field(default_factory=MqttConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    home_assistant: HomeAssistantConfig = field(default_factory=HomeAssistantConfig)
    json_logging: bool = False
    tracing: TracingConfig = field(default_factory=TracingConfig)


def load_config(config_path: str | None = None) -> AppConfig:
    """Load configuration from YAML file with env var overrides.

    If the loaded configuration still has the placeholder JWT secret
    (``change-me-in-production-use-env-var``), a cryptographically random
    secret is generated and written back to ``config.yaml`` so that
    subsequent startups use the same stable secret without requiring
    manual intervention.

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

    config = _apply_env_overrides(config)

    # Auto-generate JWT secret if still using the insecure placeholder
    _maybe_rotate_jwt_secret(config, path)

    return config


def _maybe_rotate_jwt_secret(config: AppConfig, config_path: str) -> None:
    """Generate and persist a random JWT secret if the placeholder is still set.

    This runs once on startup so operators don't need to manually generate a
    secret for basic deployments.  The generated secret is written back to
    ``config_path`` so the same token remains valid across restarts.

    A secret set via the ``NET_SENTRY_JWT_SECRET`` / ``BTWIFI_JWT_SECRET``
    environment variable is never overwritten — the env override wins.

    Args:
        config: Loaded application configuration (mutated in place).
        config_path: Path to the config file to update.
    """
    # Respect an explicit env-var override — don't replace it.
    env_secret = os.environ.get("NET_SENTRY_JWT_SECRET") or os.environ.get("BTWIFI_JWT_SECRET")
    if env_secret:
        return

    if config.api.jwt_secret != _PLACEHOLDER_JWT_SECRET:
        return

    new_secret = secrets.token_urlsafe(32)
    config.api.jwt_secret = new_secret
    logger.warning(
        "JWT secret was set to the insecure placeholder. A random secret has been generated and will be written to %s.",
        config_path,
    )

    # Write back to the config file if it exists and can be updated
    _write_jwt_secret_to_config(config_path, new_secret)


def _write_jwt_secret_to_config(config_path: str, new_secret: str) -> None:
    """Write the generated JWT secret back to the config YAML file.

    Performs a targeted line-by-line replacement to preserve all comments and
    formatting in the file.

    Args:
        config_path: Path to the config YAML file.
        new_secret: The new JWT secret to write.
    """
    # Resolve to a canonical path to prevent path-traversal exploits.
    # Only write to YAML files within the current working directory tree.
    try:
        resolved = Path(config_path).resolve()
        allowed_base = Path.cwd().resolve()
        rel = resolved.relative_to(allowed_base)  # raises ValueError if outside cwd
    except ValueError:
        logger.warning("Refusing to write JWT secret: config path is outside the working directory: %s", config_path)
        return
    except (OSError, RuntimeError):
        logger.warning("Could not resolve config path: %s", config_path)
        return

    if resolved.suffix not in (".yaml", ".yml"):
        logger.warning("Refusing to write JWT secret to non-YAML file: %s", config_path)
        return

    # Reconstruct from the validated base using only the sanitised relative
    # path parts — none of the components come from user-controlled input.
    safe_parts: list[str] = list(rel.parts)
    safe_path = Path(str(allowed_base)).joinpath(*safe_parts)

    if not safe_path.exists():
        return
    try:
        content = safe_path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        updated_lines = []
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("jwt_secret:"):
                indent = line[: len(line) - len(stripped)]
                updated_lines.append(f'{indent}jwt_secret: "{new_secret}"\n')
            else:
                updated_lines.append(line)
        safe_path.write_text("".join(updated_lines), encoding="utf-8")
        logger.info("JWT secret written to %s.", config_path)
    except OSError:
        logger.warning("Could not write generated JWT secret to %s (read-only filesystem?).", config_path)


def _parse_alert_rules(raw_rules: list) -> list[AlertRule]:
    """Parse raw alert rule dicts into AlertRule objects."""
    parsed: list[AlertRule] = []
    for r in raw_rules:
        if isinstance(r, dict) and r.get("rule_type"):
            parsed.append(
                AlertRule(
                    rule_type=r["rule_type"],
                    mac_address=r.get("mac_address"),
                    threshold_minutes=int(r.get("threshold_minutes", 30)),
                    start_hour=int(r.get("start_hour", 0)),
                    end_hour=int(r.get("end_hour", 6)),
                    device_type_filter=r.get("device_type_filter"),
                    label=r.get("label", ""),
                )
            )
    return parsed


def _parse_alert_section(al: dict, default: AlertConfig) -> AlertConfig:
    """Parse the 'alert' section of the raw config dict."""
    return AlertConfig(
        enabled=al.get("enabled", default.enabled),
        log_new_devices=al.get("log_new_devices", default.log_new_devices),
        log_file=al.get("log_file", default.log_file),
        sound_enabled=al.get("sound_enabled", default.sound_enabled),
        cooldown_seconds=al.get("cooldown_seconds", default.cooldown_seconds),
        rules=_parse_alert_rules(al.get("rules", [])),
        webhook_url=al.get("webhook_url", default.webhook_url),
        webhook_format=al.get("webhook_format", default.webhook_format),
        warn_returning_after_days=al.get("warn_returning_after_days", default.warn_returning_after_days),
    )


def _parse_whitelist_entries(raw_entries: list) -> list[WhitelistEntry]:
    """Parse raw whitelist entries into WhitelistEntry objects."""
    return [
        WhitelistEntry(
            mac_address=entry.get("mac_address", ""),
            name=entry.get("name", ""),
            category=entry.get("category", ""),
            trusted=entry.get("trusted", True),
        )
        for entry in raw_entries
        if isinstance(entry, dict) and entry.get("mac_address")
    ]


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
            dhcp_enabled=s.get("dhcp_enabled", config.scan.dhcp_enabled),
            dhcp_lease_file=s.get("dhcp_lease_file", config.scan.dhcp_lease_file),
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
            host_workers=po.get("host_workers", config.port_scan.host_workers),
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
        config.alert = _parse_alert_section(al, config.alert)

    if "whitelist" in raw:
        config.whitelist = _parse_whitelist_entries(raw["whitelist"])

    if "oui" in raw:
        o = raw["oui"]
        config.oui = OuiConfig(
            auto_update=o.get("auto_update", config.oui.auto_update),
            update_interval_hours=o.get("update_interval_hours", config.oui.update_interval_hours),
            cache_file=o.get("cache_file", config.oui.cache_file),
        )

    if "mdns" in raw:
        md = raw["mdns"]
        config.mdns = MdnsConfig(
            service_types=md.get("service_types", config.mdns.service_types),
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

    _apply_output_settings(raw, config)

    return config


def _apply_output_settings(raw: dict, config: AppConfig) -> None:
    """Apply metrics, logging, tracing, and monitor-mode settings from raw config dict."""
    if "metrics" in raw:
        me = raw["metrics"]
        config.metrics = MetricsConfig(
            enabled=me.get("enabled", config.metrics.enabled),
        )

    if "json_logging" in raw:
        config.json_logging = bool(raw["json_logging"])

    if "tracing" in raw:
        tr = raw["tracing"]
        config.tracing = TracingConfig(
            enabled=tr.get("enabled", config.tracing.enabled),
            service_name=tr.get("service_name", config.tracing.service_name),
            exporter=tr.get("exporter", config.tracing.exporter),
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


def _env(primary: str, fallback: str) -> str | None:
    """Return the first non-empty value from two environment variable names."""
    return os.environ.get(primary) or os.environ.get(fallback) or None


def _env_int(primary: str, fallback: str) -> int | None:
    """Return an environment variable as int, warning on invalid values."""
    raw = _env(primary, fallback)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid %s environment variable value: %s", primary, raw)
        return None


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

    if jwt_secret := _env("NET_SENTRY_JWT_SECRET", "BTWIFI_JWT_SECRET"):
        config.api.jwt_secret = jwt_secret

    if cors := _env("NET_SENTRY_CORS_ORIGINS", "BTWIFI_CORS_ORIGINS"):
        config.api.cors_origins = [o.strip() for o in cors.split(",") if o.strip()]

    if auth_enabled := _env("NET_SENTRY_AUTH_ENABLED", "BTWIFI_AUTH_ENABLED"):
        config.api.auth_enabled = auth_enabled.lower() in ("1", "true", "yes")

    if (interval := _env_int("NET_SENTRY_SCAN_INTERVAL", "BTWIFI_SCAN_INTERVAL")) is not None:
        config.scan.interval_seconds = interval

    if continuous := _env("NET_SENTRY_CONTINUOUS", "BTWIFI_CONTINUOUS"):
        config.scan.continuous = continuous.lower() in ("1", "true", "yes")

    if (gap := _env_int("NET_SENTRY_GAP_SECONDS", "BTWIFI_GAP_SECONDS")) is not None:
        config.scan.gap_seconds = gap

    return config
