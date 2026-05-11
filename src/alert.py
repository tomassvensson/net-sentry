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

        # Deduplication: skip if already alerted within cooldown window
        last = self._last_alerted.get(mac_address)
        if last is not None:
            elapsed = (now_dt - last).total_seconds()
            if elapsed < self._config.cooldown_seconds:
                logger.debug(
                    "Alert suppressed for %s (cooldown: %.0f / %d s)",
                    mac_address,
                    elapsed,
                    self._config.cooldown_seconds,
                )
                return

        self._last_alerted[mac_address] = now_dt
        self._alert_count += 1
        now = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        status = "TRUSTED" if is_whitelisted else "UNKNOWN"

        message = f"[{status}] New {device_type} device detected at {now}"

        if self._config.log_new_devices:
            if is_whitelisted:
                logger.info("New trusted %s device detected.", device_type)
            else:
                logger.warning("New unknown %s device detected.", device_type)

        _alert_logger.info(message)

        # Dispatch webhook notification if configured
        if self._webhook:
            self._webhook.dispatch(message, mac_address=mac_address, device_type=device_type)

        # Check time_window rules
        now_hour = now_dt.hour
        for rule in self._rules:
            if rule.rule_type != "time_window":
                continue
            if rule.device_type_filter and device_type != rule.device_type_filter:
                continue
            s, e = rule.start_hour, rule.end_hour
            in_window = (s <= e and s <= now_hour < e) or (s > e and (now_hour >= s or now_hour < e))
            if not in_window:
                continue
            rule_key = f"time_window:{mac_address}:{s}-{e}"
            last_rule = self._last_alerted.get(rule_key)
            if last_rule is not None and (now_dt - last_rule).total_seconds() < self._config.cooldown_seconds:
                continue
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
            last_seen = last_seen_by_mac.get(rule.mac_address)
            if last_seen is None:
                elapsed_minutes: float = float("inf")
            else:
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now_dt - last_seen).total_seconds() / 60.0

            if elapsed_minutes < rule.threshold_minutes:
                continue

            rule_key = f"disappearance:{rule.mac_address}"
            last_alerted = self._last_alerted.get(rule_key)
            if last_alerted is not None and (now_dt - last_alerted).total_seconds() < self._config.cooldown_seconds:
                continue

            self._last_alerted[rule_key] = now_dt
            self._alert_count += 1
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
