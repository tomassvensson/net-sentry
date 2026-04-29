"""Tests for MQTT publisher module."""

from unittest.mock import MagicMock, patch

import pytest


class TestMqttPublisherInit:
    """Tests for MqttPublisher initialization."""

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_init_default_params(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        assert pub._broker_host == "localhost"
        assert pub._broker_port == 1883
        assert pub._topic_prefix == "btwifi"
        assert pub._connected is False

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_init_with_auth(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher(username="user", password="pass")  # noqa: F841
        mock_client.username_pw_set.assert_called_once_with("user", "pass")

    @patch("src.mqtt_publisher.mqtt", None)
    @pytest.mark.timeout(30)
    def test_init_without_paho(self) -> None:
        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        assert pub._client is None


class TestMqttConnect:
    """Tests for connect/disconnect."""

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_connect_success(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher(broker_host="broker.test", broker_port=1884)
        result = pub.connect()
        assert result is True
        mock_client.connect.assert_called_once_with("broker.test", 1884, keepalive=60)
        mock_client.loop_start.assert_called_once()

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_connect_failure(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_client.connect.side_effect = ConnectionRefusedError("refused")
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        result = pub.connect()
        assert result is False

    @patch("src.mqtt_publisher.mqtt", None)
    @pytest.mark.timeout(30)
    def test_connect_no_client(self) -> None:
        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        assert pub.connect() is False

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_disconnect(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = True
        pub.disconnect()
        mock_client.loop_stop.assert_called_once()
        mock_client.disconnect.assert_called_once()


class TestMqttCallbacks:
    """Tests for on_connect/on_disconnect callbacks."""

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_on_connect_sets_flag(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._on_connect(mock_client, None, None, 0)
        assert pub._connected is True

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_on_disconnect_clears_flag(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = True
        pub._on_disconnect(mock_client, None, None, 0)
        assert pub._connected is False


class TestPublishDeviceEvent:
    """Tests for publish_device_event."""

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_publish_succeeds(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.rc = 0
        mock_client.publish.return_value = mock_result
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = True
        result = pub.publish_device_event(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            event_type="new",
            vendor="TestVendor",
        )
        assert result is True
        mock_client.publish.assert_called_once()
        topic = mock_client.publish.call_args[0][0]
        assert "AABBCCDDEEFF" in topic
        assert topic.endswith("/new")

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_publish_not_connected(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = False
        result = pub.publish_device_event(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        assert result is False

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_publish_error(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_client.publish.side_effect = RuntimeError("publish failed")
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = True
        result = pub.publish_device_event(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
        assert result is False

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_publish_error_log_redacts_mac_address(self, mock_mqtt, caplog) -> None:
        mock_client = MagicMock()
        mock_client.publish.side_effect = RuntimeError("publish failed")
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = True

        with caplog.at_level("ERROR"):
            result = pub.publish_device_event(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")

        assert result is False
        assert "AA:BB:CC:DD:EE:FF" not in caplog.text


class TestPublishScanSummary:
    """Tests for publish_scan_summary."""

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_scan_summary(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.rc = 0
        mock_client.publish.return_value = mock_result
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher(topic_prefix="test")
        pub._connected = True
        result = pub.publish_scan_summary(wifi_count=5, bluetooth_count=2, arp_count=10)
        assert result is True
        topic = mock_client.publish.call_args[0][0]
        assert topic == "test/scan/summary"

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_scan_summary_not_connected(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        pub._connected = False
        assert pub.publish_scan_summary() is False


class TestIsConnectedProperty:
    """Tests for is_connected property."""

    @patch("src.mqtt_publisher.mqtt")
    @pytest.mark.timeout(30)
    def test_reflects_state(self, mock_mqtt) -> None:
        mock_client = MagicMock()
        mock_mqtt.Client.return_value = mock_client
        mock_mqtt.CallbackAPIVersion.VERSION2 = 2

        from src.mqtt_publisher import MqttPublisher

        pub = MqttPublisher()
        assert pub.is_connected is False
        pub._connected = True
        assert pub.is_connected is True
