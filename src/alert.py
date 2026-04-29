"""Alert system for new/unknown device detection.

Logs alerts when new devices are discovered that are not in the
whitelist. Optionally writes alerts to a dedicated log file.

Alert deduplication is controlled by ``AlertConfig.cooldown_seconds`` (default
300 s). The same MAC address will not trigger a second alert within that window,
preventing log spam when a device flaps on/off.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from src.config import AlertConfig

logger = logging.getLogger(__name__)

# Dedicated alert logger
_alert_logger = logging.getLogger("net_sentry.alerts")


class AlertManager:
    """Manages alerts for new device discoveries."""

    def __init__(self, config: AlertConfig) -> None:
        """Initialize alert manager from configuration.

        Args:
            config: Alert configuration settings.
        """
        self._config = config
        self._alert_count = 0
        # MAC address -> timestamp of last alert for deduplication
        self._last_alerted: dict[str, datetime] = {}

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

    @property
    def alert_count(self) -> int:
        """Get the total number of alerts raised."""
        return self._alert_count
