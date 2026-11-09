"""
MQTT Publisher Module
Publishes smart meter readings, grid telemetry, and security events
to the Mosquitto MQTT broker, with automatic in-process fallback bus.
"""

import sys
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Callable, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from database.db_connection import execute

logger = logging.getLogger("MQTTPublisher")

# In-memory broker bus for fallback when external Mosquitto is offline
class InMemoryMQTTBroker:
    _instance = None
    _subscribers: Dict[str, List[Callable[[str, Dict[str, Any]], None]]] = {}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = InMemoryMQTTBroker()
        return cls._instance

    def subscribe(self, topic_filter: str, callback: Callable[[str, Dict[str, Any]], None]):
        if topic_filter not in self._subscribers:
            self._subscribers[topic_filter] = []
        self._subscribers[topic_filter].append(callback)

    def publish(self, topic: str, payload: Dict[str, Any]):
        for pattern, callbacks in self._subscribers.items():
            # Match wildcards like "smartgrid/#" or exact topic
            if pattern == topic or pattern == "#" or (pattern.endswith("/#") and topic.startswith(pattern[:-2])):
                for cb in callbacks:
                    try:
                        cb(topic, payload)
                    except Exception as e:
                        logger.error(f"Error in in-memory subscriber callback: {e}")

class SmartGridMQTTPublisher:
    def __init__(self):
        self.broker_host = config.MQTT_BROKER_HOST
        self.broker_port = config.MQTT_BROKER_PORT
        self.connected_to_mosquitto = False
        self.client = None
        self._in_memory_bus = InMemoryMQTTBroker.get_instance()
        self._init_client()

    def _init_client(self):
        try:
            import paho.mqtt.client as mqtt
            # Handle paho-mqtt v2 vs v1 callback API
            try:
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="SmartGridPublisher")
            except AttributeError:
                self.client = mqtt.Client(client_id="SmartGridPublisher")

            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.connect(self.broker_host, self.broker_port, keepalive=config.MQTT_KEEPALIVE)
            self.client.loop_start()
            self.connected_to_mosquitto = True
            logger.info(f"Connected to Mosquitto MQTT broker at {self.broker_host}:{self.broker_port}")
        except Exception as e:
            self.connected_to_mosquitto = False
            logger.warning(
                f"Mosquitto broker unavailable ({e}). Using embedded high-performance MQTT bus."
            )

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.connected_to_mosquitto = True
            logger.info("Successfully connected to Mosquitto MQTT Broker.")
        else:
            self.connected_to_mosquitto = False

    def _on_disconnect(self, client, userdata, rc, properties=None):
        self.connected_to_mosquitto = False

    def publish(self, topic: str, payload: Dict[str, Any], qos: int = 0) -> bool:
        """Publishes a JSON payload to the specified MQTT topic."""
        payload_str = json.dumps(payload)
        
        # Always publish to the in-memory bus so internal subscribers receive it
        self._in_memory_bus.publish(topic, payload)

        # Also publish to real Mosquitto if connected
        if self.connected_to_mosquitto and self.client:
            try:
                self.client.publish(topic, payload_str, qos=qos)
            except Exception as e:
                logger.error(f"Failed to publish to Mosquitto: {e}")
                self.connected_to_mosquitto = False

        # Record network traffic metadata into database
        self._record_traffic(topic, payload, len(payload_str))
        return True

    def publish_meter_reading(self, reading: Dict[str, Any]) -> bool:
        """Helper to publish smart meter data to smartgrid/{home_id}/meter."""
        home_id = reading.get("home_id", "HOME_01")
        topic = config.TOPIC_METER_TEMPLATE.format(home_id=home_id.lower())
        return self.publish(topic, reading)

    def publish_alert(self, alert_payload: Dict[str, Any]) -> bool:
        return self.publish(config.TOPIC_ALERTS, alert_payload)

    def publish_security_event(self, event_payload: Dict[str, Any]) -> bool:
        return self.publish(config.TOPIC_SECURITY_EVENTS, event_payload)

    def _record_traffic(self, topic: str, payload: Dict[str, Any], payload_size: int):
        """Logs network packet metadata into network_traffic table."""
        try:
            source_ip = payload.get("ip_address") or payload.get("source_ip") or "192.168.1.100"
            dest_ip = "192.168.1.1"  # Smart Grid Central SCADA Gateway
            home_id = payload.get("home_id")
            
            sql = """
            INSERT INTO network_traffic (
                source_ip, destination_ip, source_port, destination_port,
                protocol, packet_size, num_packets, traffic_rate_kbps,
                home_id, mqtt_topic, payload_preview
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            preview = json.dumps(payload)[:120]
            execute(sql, (
                source_ip, dest_ip, 1883, 1883,
                "MQTT", payload_size, 1, 0.5,
                home_id, topic, preview
            ))
        except Exception:
            pass

    def stop(self):
        if self.client and self.connected_to_mosquitto:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass

_publisher_instance = None

def get_publisher() -> SmartGridMQTTPublisher:
    global _publisher_instance
    if _publisher_instance is None:
        _publisher_instance = SmartGridMQTTPublisher()
    return _publisher_instance

if __name__ == "__main__":
    pub = get_publisher()
    sample_data = {
        "home_id": "HOME_01",
        "voltage": 230.5,
        "current": 10.2,
        "power_kw": 2.35,
        "is_tampered": False
    }
    pub.publish_meter_reading(sample_data)
    print("[OK] Published test reading to MQTT.")

