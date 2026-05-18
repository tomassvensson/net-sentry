"""Alert system for new/unknown device detection.

Logs alerts when new devices are discovered that are not in the
whitelist. Optionally writes alerts to a dedicated log file.

Alert deduplication is controlled by ``AlertConfig.cooldown_seconds`` (default
300 s). The same MAC address will not trigger a second alert within that window,
preventing log spam when a device flaps on/off.
"""

import logging
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from src.config import AlertConfig, AlertRule

logger = logging.getLogger(__name__)

# Dedicated alert logger
_alert_logger = logging.getLogger("net_sentry.alerts")


class WebhookDispatcher:
    """Send alert notifications to a configured webhook URL.

    Supports Slack-compatible payloads (default) and PagerDuty Events API v2.
    """

    def __init__(self, url: str, payload_format: str = "slack") -> None:
        """Initialize dispatcher.

        Args:
            url: Webhook URL to POST alerts to.
            payload_format: Payload format — "slack" or "pagerduty".
        """
        self._url = url
        self._format = payload_format

    def dispatch(self, message: str, mac_address: str = "", device_type: str = "") -> None:
        """Send an alert payload to the webhook URL.

        Failures are logged as warnings and never re-raised so they cannot
        disrupt the main scan loop.

        Args:
            message: Human-readable alert message.
            mac_address: MAC address of the triggering device (used in PD payload).
            device_type: Device type string (used in PD payload).
        """
        import json

        if not self._url:
            return

        # Validate URL scheme to prevent SSRF — only http/https are permitted.
        parsed_scheme = urlparse(self._url).scheme.lower()
        if parsed_scheme not in ("http", "https"):
            logger.error("Webhook URL has disallowed scheme %r; skipping dispatch", parsed_scheme)
            return
        try:
            payload = self._build_payload(message, mac_address, device_type)
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                status = resp.status
                if status not in (200, 201, 202):
                    logger.warning("Webhook returned non-success status %d", status)
                else:
                    logger.debug("Webhook dispatched successfully (status=%d)", status)
        except Exception:
            logger.warning("Failed to dispatch webhook alert", exc_info=True)

    def _build_payload(self, message: str, mac_address: str, device_type: str) -> dict:
        """Build the format-specific payload dict.

        Args:
            message: Alert message text.
            mac_address: MAC address for PagerDuty dedup key.
            device_type: Device type label.

        Returns:
            Dictionary ready for JSON serialisation.
        """
        if self._format == "pagerduty":
            return {
                "routing_key": "",  # must be set by operator at the URL level
                "event_action": "trigger",
                "dedup_key": f"net-sentry:{mac_address}",
                "payload": {
                    "summary": message,
                    "severity": "warning",
                    "source": "net-sentry",
                    "custom_details": {"mac_address": mac_address, "device_type": device_type},
                },
            }
        # Default: Slack-compatible
        return {"text": message}


class AlertManager:
    """Manages alerts for new device discoveries."""

    def __init__(self, config: AlertConfig) -> None:
        """Initialize alert manager from configuration.

        Args:
            config: Alert configuration settings.
        """
        self._config = config
        self._rules: list[AlertRule] = list(config.rules)
        self._alert_count = 0
        # MAC address -> timestamp of last alert for deduplication
        self._last_alerted: dict[str, datetime] = {}
        self._webhook = WebhookDispatcher(config.webhook_url, config.webhook_format) if config.webhook_url else None

        if config.log_file:
            self._setup_file_handler(config.log_file)

    def _setup_file_handler(self, log_file: str) -> None:
        """Set up a file handler for alert logging.

        Args:
            log_file: Path to the alert log file.
        """
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(str(path), encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
            _alert_logger.addHandler(handler)
            _alert_logger.setLevel(logging.INFO)
            logger.info("Alert log file: %s", log_file)
        except OSError:
            logger.exception("Failed to set up alert log file: %s", log_file)

    def on_new_device(
        self,
        mac_address: str,
        device_type: str,
        vendor: str | None = None,
        device_name: str | None = None,
        is_whitelisted: bool = False,
    ) -> None:
        """Handle a new device discovery.

        Alerts are deduplicated: if the same MAC address was already alerted
        within ``cooldown_seconds``, the call is a no-op.

        Args:
            mac_address: MAC address of the new device.
            device_type: Type of device (wifi_ap, bluetooth, network, etc.).
            vendor: Vendor name.
            device_name: Human-readable device name.
            is_whitelisted: Whether the device is in the whitelist.
        """
        if not self._config.enabled:
            return

        now_dt = datetime.now(timezone.utc)

        if self._is_in_cooldown(mac_address, now_dt):
            return

        self._last_alerted[mac_address] = now_dt
        self._alert_count += 1
        now = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        status = "TRUSTED" if is_whitelisted else "UNKNOWN"
        # Include presence-only indicators for device name / vendor so the log
        # entry is more informative without leaking PII values directly.
        extra_parts: list[str] = []
        if device_name is not None:
            extra_parts.append("named device")
        if vendor is not None:
            extra_parts.append("known vendor")
        extra = f" ({', '.join(extra_parts)})" if extra_parts else ""
        message = f"[{status}] New {device_type} device{extra} detected at {now}"

        self._log_new_device(device_type, is_whitelisted, message)
        self._check_time_window_rules(mac_address, device_type, now_dt)

    def on_returning_device(
        self,
        mac_address: str,
        device_type: str,
        days_absent: float,
        is_whitelisted: bool = False,
    ) -> None:
        """Handle a device that reappears after a long absence.

        Fires a console warning when a device that has not been seen for at
        least ``warn_returning_after_days`` days is detected again.
        Alerts are deduplicated using the same cooldown window as new-device
        alerts.

        Args:
            mac_address: MAC address of the returning device.
            device_type: Type of device.
            days_absent: Number of days since the device was last seen.
            is_whitelisted: Whether the device is in the whitelist.
        """
        if not self._config.enabled or self._config.warn_returning_after_days <= 0:
            return

        now_dt = datetime.now(timezone.utc)
        cooldown_key = f"returning:{mac_address}"
        if self._is_in_cooldown(cooldown_key, now_dt):
            return

        self._last_alerted[cooldown_key] = now_dt
        self._alert_count += 1
        status = "trusted" if is_whitelisted else "unknown"
        logger.warning(
            "Returning %s device (%s) reappeared after %.1f day(s) absent: %s",
            device_type,
            status,
            days_absent,
            mac_address,
        )
        _alert_logger.info(
            "[RETURNING] %s device %s reappeared after %.1f day(s) absent",
            device_type,
            mac_address,
            days_absent,
        )

    def _is_in_cooldown(self, key: str, now_dt: datetime) -> bool:
        """Return True if ``key`` was alerted within the cooldown window."""
        last = self._last_alerted.get(key)
        if last is None:
            return False
        elapsed = (now_dt - last).total_seconds()
        if elapsed < self._config.cooldown_seconds:
            logger.debug(
                "Alert suppressed for %s (cooldown: %.0f / %d s)",
                key,
                elapsed,
                self._config.cooldown_seconds,
            )
            return True
        return False

    def _log_new_device(self, device_type: str, is_whitelisted: bool, message: str) -> None:
        """Log a new-device alert to the main logger and alert logger."""
        if self._config.log_new_devices:
            if is_whitelisted:
                logger.info("New trusted %s device detected.", device_type)
            else:
                logger.warning("New unknown %s device detected.", device_type)
        _alert_logger.info(message)
        if self._webhook:
            self._webhook.dispatch(message)

    def _check_time_window_rules(self, mac_address: str, device_type: str, now_dt: datetime) -> None:
        """Evaluate time-window alert rules for a newly detected device."""
        now_hour = now_dt.hour
        for rule in self._rules:
            if rule.rule_type != "time_window":
                continue
            if rule.device_type_filter and device_type != rule.device_type_filter:
                continue
            self._maybe_fire_time_window_rule(mac_address, device_type, now_dt, now_hour, rule)

    def _maybe_fire_time_window_rule(
        self,
        mac_address: str,
        device_type: str,
        now_dt: datetime,
        now_hour: int,
        rule: AlertRule,
    ) -> None:
        """Fire a time-window rule alert if the device is within the time window."""
        s, e = rule.start_hour, rule.end_hour
        in_window = (s <= e and s <= now_hour < e) or (s > e and (now_hour >= s or now_hour < e))
        if not in_window:
            return
        rule_key = f"time_window:{mac_address}:{s}-{e}"
        if self._is_in_cooldown(rule_key, now_dt):
            return
        self._last_alerted[rule_key] = now_dt
        self._alert_count += 1
        label = rule.label or f"night_watch({s:02d}:00-{e:02d}:00)"
        logger.warning(
            "Rule [%s]: new %s device %s detected at hour %02d:xx",
            label,
            device_type,
            mac_address,
            now_hour,
        )
        _alert_logger.info("[RULE:%s] New %s device %s at %02d:xx", label, device_type, mac_address, now_hour)

    def check_disappearance(self, last_seen_by_mac: dict[str, datetime]) -> None:
        """Check disappearance rules and fire alerts as needed.

        Args:
            last_seen_by_mac: Mapping of MAC address to the datetime it was last seen.
        """
        now_dt = datetime.now(timezone.utc)
        for rule in self._rules:
            if rule.rule_type != "disappearance" or not rule.mac_address:
                continue
            self._evaluate_disappearance_rule(rule, last_seen_by_mac, now_dt)

    def _evaluate_disappearance_rule(
        self,
        rule: AlertRule,
        last_seen_by_mac: dict[str, datetime],
        now_dt: datetime,
    ) -> None:
        """Evaluate a single disappearance rule and fire alert if threshold exceeded."""
        last_seen = last_seen_by_mac.get(rule.mac_address)
        elapsed_minutes = self._calc_elapsed_minutes(last_seen, now_dt)
        if elapsed_minutes < rule.threshold_minutes:
            return
        rule_key = f"disappearance:{rule.mac_address}"
        if self._is_in_cooldown(rule_key, now_dt):
            return
        self._last_alerted[rule_key] = now_dt
        self._alert_count += 1
        self._fire_disappearance_alert(rule, elapsed_minutes)

    @staticmethod
    def _calc_elapsed_minutes(last_seen: datetime | None, now_dt: datetime) -> float:
        """Return minutes since last_seen, or inf when last_seen is None."""
        if last_seen is None:
            return float("inf")
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        return (now_dt - last_seen).total_seconds() / 60.0

    def _fire_disappearance_alert(self, rule: AlertRule, elapsed_minutes: float) -> None:
        """Log disappearance alert messages."""
        label = rule.label or rule.mac_address
        if elapsed_minutes == float("inf"):
            logger.warning("Rule [%s]: device %s has never been seen", label, rule.mac_address)
            _alert_logger.info("[RULE:%s] Device %s never seen", label, rule.mac_address)
        else:
            logger.warning(
                "Rule [%s]: device %s absent for %.1f min (threshold: %d min)",
                label,
                rule.mac_address,
                elapsed_minutes,
                rule.threshold_minutes,
            )
            _alert_logger.info(
                "[RULE:%s] Device %s absent %.1f min",
                label,
                rule.mac_address,
                elapsed_minutes,
            )

    @property
    def alert_count(self) -> int:
        """Get the total number of alerts raised."""
        return self._alert_count
