"""
Cowrie Honeypot Event Collector
Collects and parses Cowrie JSON log output, extracts attacker IP, credentials,
timestamps, commands, and persists normalized events into the MySQL/SQLite database.
"""

import sys
import json
import uuid
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from database.db_connection import execute, fetch_all, fetch_one

class CowrieCollector:
    def __init__(self, log_path: Path = config.HONEYPOT_LOG_PATH):
        self.log_path = log_path
        self._processed_lines = 0

    def parse_log_file(self) -> List[Dict[str, Any]]:
        """Parses cowrie.json and groups events into coherent honeypot incident records."""
        if not self.log_path.exists():
            return []

        raw_events = []
        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        raw_events.append(json.loads(line))
                    except Exception:
                        pass

        # Group by session ID
        sessions: Dict[str, Dict[str, Any]] = {}
        for ev in raw_events:
            sess_id = ev.get("session", "unknown")
            if sess_id not in sessions:
                sessions[sess_id] = {
                    "session_id": sess_id,
                    "source_ip": ev.get("src_ip", "127.0.0.1"),
                    "destination_ip": ev.get("dst_ip", "192.168.1.1"),
                    "service_type": ev.get("protocol", "SSH").upper(),
                    "username": None,
                    "password": None,
                    "login_success": False,
                    "commands": [],
                    "timestamp": ev.get("timestamp", "")
                }

            ev_id = ev.get("eventid", "")
            if ev_id == "cowrie.login.success":
                sessions[sess_id]["username"] = ev.get("username")
                sessions[sess_id]["password"] = ev.get("password")
                sessions[sess_id]["login_success"] = True
            elif ev_id == "cowrie.login.failed":
                sessions[sess_id]["username"] = ev.get("username")
                sessions[sess_id]["password"] = ev.get("password")
            elif ev_id == "cowrie.command.input":
                cmd = ev.get("input", "")
                if cmd and cmd not in sessions[sess_id]["commands"]:
                    sessions[sess_id]["commands"].append(cmd)

        normalized_records = []
        for sess_id, data in sessions.items():
            cmd_str = "; ".join(data["commands"]) if data["commands"] else ""
            normalized_records.append({
                "event_id": f"HP_{sess_id}",
                "session_id": sess_id,
                "source_ip": data["source_ip"],
                "destination_ip": data["destination_ip"],
                "service_type": data["service_type"],
                "username": data["username"] or "unknown",
                "password": data["password"] or "unknown",
                "login_success": 1 if data["login_success"] else 0,
                "command_entered": cmd_str,
                "packet_size": len(cmd_str) + 128,
                "network_protocol": "TCP",
                "timestamp": data["timestamp"]
            })

        return normalized_records

    def ingest_to_database(self) -> int:
        """Reads honeypot log file and saves new records into honeypot_events table."""
        records = self.parse_log_file()
        inserted_count = 0

        sql = """
        INSERT OR IGNORE INTO honeypot_events (
            event_id, session_id, source_ip, destination_ip,
            service_type, username, password, login_success,
            command_entered, packet_size, network_protocol
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Also support MySQL INSERT IGNORE
        if config.DB_ENGINE == "mysql":
            sql = sql.replace("INSERT OR IGNORE", "INSERT IGNORE")

        for r in records:
            # Check existing
            existing = fetch_one("SELECT event_id FROM honeypot_events WHERE event_id = %s", (r["event_id"],))
            if not existing:
                execute(sql, (
                    r["event_id"],
                    r["session_id"],
                    r["source_ip"],
                    r["destination_ip"],
                    r["service_type"],
                    r["username"],
                    r["password"],
                    r["login_success"],
                    r["command_entered"],
                    r["packet_size"],
                    r["network_protocol"]
                ))
                inserted_count += 1

        return inserted_count

_collector_instance = None

def get_collector() -> CowrieCollector:
    global _collector_instance
    if _collector_instance is None:
        _collector_instance = CowrieCollector()
    return _collector_instance

if __name__ == "__main__":
    collector = get_collector()
    count = collector.ingest_to_database()
    print(f"[OK] Ingested {count} new honeypot events into database.")

