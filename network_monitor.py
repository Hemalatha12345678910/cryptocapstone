"""
Network Packet Monitoring Module (Scapy Integration)
Provides packet inspection, protocol header analysis, and synthetic PCAP generation
for smart grid SCADA and MQTT network traffic.
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Ensure Scapy can be imported safely
try:
    from scapy.all import IP, TCP, UDP, Raw, Ether, wrpcap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("NetworkMonitor")

class ScapyNetworkMonitor:
    def __init__(self, pcap_dir: Path = ROOT_DIR / "logs"):
        self.pcap_dir = pcap_dir
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.captured_packets = []

    def create_synthetic_packet(self, src_ip: str, dst_ip: str, src_port: int, 
                                dst_port: int, payload: str, protocol: str = "TCP"):
        """
        Synthesizes a realistic network packet using Scapy for deep packet inspection.
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            proto_layer = TCP(sport=src_port, dport=dst_port, flags="PA") if protocol == "TCP" else UDP(sport=src_port, dport=dst_port)
            pkt = IP(src=src_ip, dst=dst_ip) / proto_layer / Raw(load=payload.encode("utf-8"))
            self.captured_packets.append(pkt)
            
            # Save periodic sample PCAP
            if len(self.captured_packets) >= 10:
                pcap_file = self.pcap_dir / "smartgrid_traffic.pcap"
                wrpcap(str(pcap_file), self.captured_packets[-50:])
            return pkt
        except Exception as e:
            logger.debug(f"Scapy packet synthesis notice: {e}")
            return None

    def inspect_packet_metadata(self, packet_obj) -> Dict[str, Any]:
        """Extracts deep header metadata from a Scapy packet."""
        if not SCAPY_AVAILABLE or packet_obj is None:
            return {}

        try:
            return {
                "source_ip": packet_obj[IP].src if IP in packet_obj else "unknown",
                "destination_ip": packet_obj[IP].dst if IP in packet_obj else "unknown",
                "packet_length": len(packet_obj),
                "ttl": packet_obj[IP].ttl if IP in packet_obj else 64,
                "protocol": "TCP" if TCP in packet_obj else "UDP",
                "has_payload": Raw in packet_obj,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception:
            return {}

_monitor = None

def get_network_monitor() -> ScapyNetworkMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ScapyNetworkMonitor()
    return _monitor

if __name__ == "__main__":
    monitor = get_network_monitor()
    if SCAPY_AVAILABLE:
        pkt = monitor.create_synthetic_packet(
            src_ip="192.168.1.15",
            dst_ip="192.168.1.1",
            src_port=48210,
            dst_port=1883,
            payload='{"home_id":"HOME_01","voltage":230.1}',
            protocol="TCP"
        )
        meta = monitor.inspect_packet_metadata(pkt)
        print("[OK] Scapy Packet Inspection:", meta)
    else:
        print("[Notice] Scapy not available in current environment.")

