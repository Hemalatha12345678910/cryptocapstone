"""
Continuous Smart Grid Simulation Daemon
Runs in the background, continuously publishing real-time telemetry for all 10 smart homes
and injecting periodic cyberattack incursions to simulate a live smart grid SCADA control center.
"""

import sys
import time
import random
import logging
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from simulation.smart_home import load_all_smart_homes
from simulation.mqtt_publisher import get_publisher
from simulation.traffic_generator import get_traffic_generator
from honeypot.honeypot_server import CowrieHoneypotServer
from honeypot.cowrie_collector import get_collector
from detection.detection_engine import get_detection_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ContinuousSimulation")

def run_continuous_simulation(interval: float = config.SIMULATION_INTERVAL_SEC, max_cycles: int = None):
    logger.info("=" * 70)
    logger.info("Starting Continuous Smart Grid Simulation Daemon (SDG 7)")
    logger.info(f"Target: 10 Smart Homes | Telemetry Interval: {interval}s")
    logger.info("Press Ctrl+C to terminate.")
    logger.info("=" * 70)

    homes = load_all_smart_homes()
    pub = get_publisher()
    engine = get_detection_engine()
    gen = get_traffic_generator()
    hp = CowrieHoneypotServer()
    collector = get_collector()

    cycle = 0
    try:
        while True:
            cycle += 1
            logger.info(f"--- [Simulation Cycle #{cycle}] ---")

            # 1. Publish Smart Meter Readings for all 10 homes
            for home in homes:
                reading = home.get_meter_reading()
                pub.publish_meter_reading(reading)

            # 2. Network Events & AI Intrusion Detection
            # Normal traffic + periodic attack bursts
            event_count = random.randint(2, 5)
            for _ in range(event_count):
                event = gen.generate_event()
                res = engine.process_event(event)
                if res["final_classification"] != "Normal Traffic":
                    logger.warning(
                        f"🚨 Detected {res['final_classification']} from {res['source_ip']} (Severity: {res['severity']})"
                    )

            # 3. Cowrie Honeypot Intrusion Probes
            if random.random() < 0.6:
                hp.simulate_attacker_session()
                ingested = collector.ingest_to_database()
                if ingested > 0:
                    logger.info(f"🍯 Ingested {ingested} new Cowrie honeypot attacker events.")

            if max_cycles and cycle >= max_cycles:
                logger.info(f"Completed target of {max_cycles} cycles.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info("\n[*] Continuous simulation stopped by user.")

if __name__ == "__main__":
    # If run directly with an argument, use it as max cycles (e.g. for testing)
    cycles = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_continuous_simulation(max_cycles=cycles)

