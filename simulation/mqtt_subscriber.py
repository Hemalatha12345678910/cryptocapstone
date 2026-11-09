"""
MQTT Subscriber Module
Listens to smart grid MQTT topics (meter readings, alerts, and security telemetry),
persists smart meter data to the database, and forwards traffic to the detection engine.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Callable, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from database.db_connection import execute
from simulation.mqtt_publisher import InMemoryMQTTBroker

logger = logging.getLogger("MQTTSubscriber")

class SmartGridMQTTSubscriber:
    def __init__(self):
        self.broker_host = config.MQTT_BROKER_HOST
        self.broker_port = config.MQTT_BROKER_PORT
        self.client = None
        self.connected_to_mosquitto = False
        self._custom_listeners: List[Callable[[str, Dict[str, Any]], None]] = []

        # Register with internal in-memory broker bus
        InMemoryMQTTBroker.get_instance().subscribe("smartgrid/#", self._process_message)

        # Connect to Mosquitto if available
        self._init_client()

    def _init_client(self):
        try:
            import paho.mqtt.client as mqtt
            try:
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="SmartGridSubscriber")
            except AttributeError:
                self.client = mqtt.Client(client_id="SmartGridSubscriber")

            self.client.on_connect = self._on_connect
            self.client.on_message = self._on_paho_message
            self.client.connect(self.broker_host, self.broker_port, keepalive=config.MQTT_KEEPALIVE)
            self.client.loop_start()
            self.connected_to_mosquitto = True
            logger.info("Subscriber connected to Mosquitto MQTT broker.")
        except Exception as e:
            self.connected_to_mosquitto = False
            logger.info(f"Subscriber listening on embedded MQTT bus ({e}).")

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.connected_to_mosquitto = True
            client.subscribe("smartgrid/#")
            logger.info("Subscribed to 'smartgrid/#' on Mosquitto broker.")

    def _on_paho_message(self, client, userdata, msg):
        try:
            topic = msg.topic
            payload = json.loads(msg.payload.decode("utf-8"))
            self._process_message(topic, payload)
        except Exception as e:
            logger.error(f"Error parsing MQTT message: {e}")

    def add_listener(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Allows external modules (like Streamlit UI or Detection Engine) to listen."""
        self._custom_listeners.append(callback)

    def _process_message(self, topic: str, payload: Dict[str, Any]):
        """Processes incoming MQTT packet according to topic type."""
        # 1. Smart Meter Readings: smartgrid/homeX/meter
        if "/meter" in topic:
            self._handle_meter_reading(payload)

        # 2. Notify custom listeners (e.g. real-time UI charts)
        for listener in self._custom_listeners:
            try:
                listener(topic, payload)
            except Exception as e:
                logger.error(f"Error in subscriber listener callback: {e}")

    def _handle_meter_reading(self, reading: Dict[str, Any]):
        """Stores reading in smart_meter_readings table."""
        try:
            sql = """
            INSERT INTO smart_meter_readings (
                home_id, voltage, current, power_kw,
                reactive_power_kvar, power_factor, frequency_hz,
                energy_kwh, is_tampered
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            execute(sql, (
                reading.get("home_id", "HOME_01"),
                reading.get("voltage", 230.0),
                reading.get("current", 10.0),
                reading.get("power_kw", 2.3),
                reading.get("reactive_power_kvar", 0.0),
                reading.get("power_factor", 0.95),
                reading.get("frequency_hz", 50.0),
                reading.get("energy_kwh", 100.0),
                1 if reading.get("is_tampered") else 0
            ))
        except Exception as e:
            logger.error(f"Failed to persist smart meter reading: {e}")

    def stop(self):
        if self.client and self.connected_to_mosquitto:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass

_subscriber_instance = None

def get_subscriber() -> SmartGridMQTTSubscriber:
    global _subscriber_instance
    if _subscriber_instance is None:
        _subscriber_instance = SmartGridMQTTSubscriber()
    return _subscriber_instance

if __name__ == "__main__":
    sub = get_subscriber()
    print("[OK] Smart Grid MQTT Subscriber active and listening for telemetry.")

