"""
Honeypot Event Processor Module
Orchestrates honeypot log collection, extracts security metrics,
and bridges honeypot telemetry to the AI Intrusion Detection Engine.
"""

import sys
from pathlib import Path
from typing import List, Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from honeypot.cowrie_collector import get_collector
from database.db_connection import fetch_all

class HoneypotEventProcessor:
    def __init__(self):
        self.collector = get_collector()

    def process_pending_events(self) -> int:
        """Collects fresh Cowrie logs and ingests them into the database."""
        return self.collector.ingest_to_database()

    def get_recent_honeypot_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        sql = """
        SELECT event_id, session_id, source_ip, destination_ip,
               service_type, username, password, login_success,
               command_entered, packet_size, network_protocol, timestamp
        FROM honeypot_events
        ORDER BY timestamp DESC
        LIMIT %s
        """
        return fetch_all(sql, (limit,))

    def get_attacker_summary(self) -> Dict[str, Any]:
        """Calculates honeypot metrics for the dashboard."""
        total_attempts = fetch_all("SELECT COUNT(*) as cnt FROM honeypot_events")[0]["cnt"]
        successful_logins = fetch_all("SELECT COUNT(*) as cnt FROM honeypot_events WHERE login_success = 1")[0]["cnt"]
        unique_ips = fetch_all("SELECT COUNT(DISTINCT source_ip) as cnt FROM honeypot_events")[0]["cnt"]
        captured_cmds = fetch_all("SELECT COUNT(*) as cnt FROM honeypot_events WHERE command_entered != ''")[0]["cnt"]

        return {
            "total_attempts": total_attempts,
            "successful_logins": successful_logins,
            "failed_logins": max(0, total_attempts - successful_logins),
            "unique_attacker_ips": unique_ips,
            "captured_commands_count": captured_cmds
        }

_processor = None

def get_event_processor() -> HoneypotEventProcessor:
    global _processor
    if _processor is None:
        _processor = HoneypotEventProcessor()
    return _processor

if __name__ == "__main__":
    proc = get_event_processor()
    summary = proc.get_attacker_summary()
    print("[OK] Honeypot Attacker Summary:", summary)

