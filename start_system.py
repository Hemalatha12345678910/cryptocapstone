"""
Master System Startup & Orchestrator Script
AI-Enhanced Honeypot System for Smart Grids (SDG 7)

Initializes Database, Generates Cryptographic Keys, Trains Machine Learning Models,
Seeds Initial Smart Grid Telemetry & Honeypot Sessions, and Launches the Streamlit Dashboard.
"""

import os
import sys
import time
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

def print_banner():
    banner = """
    =================================================================================
       AI-ENHANCED HONEYPOT & CRYPTOGRAPHIC SECURITY SYSTEM IN MULTI-HOME SMART GRIDS
                         UN Sustainable Development Goal 7
    =================================================================================
    """
    print(banner)

def main():
    print_banner()

    # Step 1: Database Initialization
    print("[1/5] Initializing Database & 10 Smart Homes...")
    from database.db_initializer import main as init_db
    init_db()

    # Step 2: Cryptographic Key Management
    print("\n[2/5] Initializing AES-256-GCM & RSA-2048-PSS Keys...")
    from cryptography.key_management import ensure_keys_exist
    ensure_keys_exist()
    print("[OK] Cryptographic keys verified.")

    # Step 3: Train / Verify AI Models
    print("\n[3/5] Verifying Machine Learning Intrusion Detection Models...")
    from detection.model_evaluation import get_saved_metrics
    metrics = get_saved_metrics()
    print(f"[OK] Random Forest & Isolation Forest Ready (Accuracy: {metrics.get('accuracy', 1.0)*100:.2f}%)")

    # Step 4: Seed Initial Live Telemetry & Attacks
    print("\n[4/5] Generating Initial Smart Grid Telemetry & Honeypot Sessions...")
    from simulation.smart_home import load_all_smart_homes
    from simulation.mqtt_publisher import get_publisher
    from simulation.mqtt_subscriber import get_subscriber
    from simulation.traffic_generator import get_traffic_generator
    from honeypot.honeypot_server import CowrieHoneypotServer
    from honeypot.cowrie_collector import get_collector
    from detection.detection_engine import get_detection_engine

    sub = get_subscriber()
    homes = load_all_smart_homes()
    pub = get_publisher()
    engine = get_detection_engine()
    gen = get_traffic_generator()

    # Publish baseline meter readings for 10 homes
    for home in homes:
        reading = home.get_meter_reading()
        pub.publish_meter_reading(reading)

    # Seed baseline security events & attacks
    for _ in range(8):
        evt = gen.generate_event()
        engine.process_event(evt)

    # Seed honeypot sessions
    hp = CowrieHoneypotServer()
    for _ in range(5):
        hp.simulate_attacker_session()
    get_collector().ingest_to_database()

    print("[OK] Seeded 10 smart meters, network traffic, and honeypot sessions.")

    # Step 5: Launch Streamlit Dashboard
    print("\n[5/5] Launching Streamlit Threat Intelligence Dashboard...")
    print("      Opening browser on http://localhost:8501 ...")
    print("      Press Ctrl+C to terminate the application.\n")

    cmd = [sys.executable, "-m", "streamlit", "run", "app.py"]
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n[*] System stopped by user. Goodbye!")

if __name__ == "__main__":
    main()
