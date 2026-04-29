"""MQTT publisher for device discovery events.

Publishes device discovery and scan events to an MQTT broker.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Conditional import — paho-mqtt is a required dependency but we
# guard the import so tests can mock it.
try:
    import paho.mqtt.client as mqtt
except ImportError:  # pragma: no cover
    mqtt = None  # type: ignore[assignment]


class MqttPublisher:
    """Publishes BtWiFi events to an MQTT broker."""

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        topic_prefix: str = "net-sentry",
        username: str | None = None,
        password: str | None = None,
        client_id: str = "net-sentry-scanner",
    ) -> None:
        """Initialize MQTT publisher.

        Args:
            broker_host: MQTT broker hostname.
            broker_port: MQTT broker port.
            topic_prefix: Prefix for MQTT topics.
            username: Optional username for authentication.
            password: Optional password for authentication.
            client_id: MQTT client identifier.
        """
        self._broker_host = broker_host
        self._broker_port = broker_port
        self._topic_prefix = topic_prefix
        self._connected = False

        if mqtt is None:
            logger.error("paho-mqtt not installed. MQTT publishing disabled.")
            self._client: mqtt.Client | None = None
            return

        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,  # type: ignore[attr-defined]
            client_id=client_id,
        )
        if username:
            self._client.username_pw_set(username, password)

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect

    def _on_connect(
        self,
        client: "mqtt.Client",
        userdata: object,
        flags: object,
        rc: object,
        properties: object = None,
    ) -> None:
        """Handle MQTT connection."""
        self._connected = True
        logger.info("Connected to MQTT broker %s:%d", self._broker_host, self._broker_port)

    def _on_disconnect(
        self,
        client: "mqtt.Client",
        userdata: object,
        flags: object,
        rc: object,
        properties: object = None,
    ) -> None:
        """Handle MQTT disconnection."""
        self._connected = False
        logger.warning("Disconnected from MQTT broker")

    def connect(self) -> bool:
        """Connect to the MQTT broker.

        Returns:
            True if connection succeeded.
        """
        if self._client is None:
            return False
        try:
            self._client.connect(self._broker_host, self._broker_port, keepalive=60)
            self._client.loop_start()
            return True
        except Exception:
            logger.exception("Failed to connect to MQTT broker %s:%d", self._broker_host, self._broker_port)
            return False

    def disconnect(self) -> None:
        """Disconnect from the MQTT broker."""
        if self._client is not None and self._connected:
            self._client.loop_stop()
            self._client.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if connected to broker."""
        return self._connected

    def publish_device_event(
        self,
        mac_address: str,
        device_type: str,
        event_type: str = "seen",
        vendor: str | None = None,
        device_name: str | None = None,
        signal_dbm: float | None = None,
    ) -> bool:
        """Publish a device event to MQTT.

        Args:
            mac_address: Device MAC address.
            device_type: Type of device.
            event_type: Event type (seen, new, lost).
            vendor: Vendor name.
            device_name: Human-readable name.
            signal_dbm: Signal strength.

        Returns:
            True if published successfully.
        """
        if self._client is None or not self._connected:
            return False

        topic = f"{self._topic_prefix}/devices/{mac_address.replace(':', '')}/{event_type}"
        payload = {
            "mac_address": mac_address,
            "device_type": device_type,
            "event_type": event_type,
            "vendor": vendor,
            "device_name": device_name,
            "signal_dbm": signal_dbm,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            result = self._client.publish(topic, json.dumps(payload), qos=1)
            if result.rc == 0:
                from src.metrics import MQTT_MESSAGES_SENT

                MQTT_MESSAGES_SENT.inc()
                return True
            logger.warning("MQTT publish failed with rc=%s", result.rc)
            return False
        except Exception:
            logger.exception("MQTT publish error for device event")
            from src.metrics import MQTT_ERRORS

            MQTT_ERRORS.inc()
            return False

    def publish_scan_summary(
        self,
        wifi_count: int = 0,
        bluetooth_count: int = 0,
        arp_count: int = 0,
        total_devices: int = 0,
    ) -> bool:
        """Publish a scan summary to MQTT.

        Args:
            wifi_count: WiFi networks found.
            bluetooth_count: Bluetooth devices found.
            arp_count: ARP hosts found.
            total_devices: Total known devices.

        Returns:
            True if published successfully.
        """
        if self._client is None or not self._connected:
            return False

        topic = f"{self._topic_prefix}/scan/summary"
        payload = {
            "wifi_count": wifi_count,
            "bluetooth_count": bluetooth_count,
            "arp_count": arp_count,
            "total_devices": total_devices,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            result = self._client.publish(topic, json.dumps(payload), qos=1)
            return result.rc == 0
        except Exception:
            logger.exception("MQTT scan summary publish error")
            return False
