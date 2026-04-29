"""Alert system for new/unknown device detection.

Logs alerts when new devices are discovered that are not in the
whitelist. Optionally writes alerts to a dedicated log file.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from src.config import AlertConfig

logger = logging.getLogger(__name__)

# Dedicated alert logger
_alert_logger = logging.getLogger("btwifi.alerts")


class AlertManager:
    """Manages alerts for new device discoveries."""

    def __init__(self, config: AlertConfig) -> None:
        """Initialize alert manager from configuration.

        Args:
            config: Alert configuration settings.
        """
        self._config = config
        self._alert_count = 0

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

        Args:
            mac_address: MAC address of the new device.
            device_type: Type of device (wifi_ap, bluetooth, network, etc.).
            vendor: Vendor name.
            device_name: Human-readable device name.
            is_whitelisted: Whether the device is in the whitelist.
        """
        if not self._config.enabled:
            return

        self._alert_count += 1
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

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
