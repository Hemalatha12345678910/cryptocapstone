"""
Centralized Configuration Module
AI-Enhanced Honeypot System for Smart Grids (SDG 7)
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Ensure local cryptography modules are discoverable alongside library
try:
    import cryptography
    local_crypto = str(BASE_DIR / "cryptography")
    if local_crypto not in cryptography.__path__:
        cryptography.__path__.insert(0, local_crypto)
except Exception:
    pass

# ----------------------------------------------------------------------
# Directories
# ----------------------------------------------------------------------
KEYS_DIR = BASE_DIR / os.getenv("KEY_DIR", "keys")
LOGS_DIR = BASE_DIR / "logs"
MODELS_DIR = BASE_DIR / "models" / "saved_model"
DATABASE_DIR = BASE_DIR / "database"

for d in [KEYS_DIR, LOGS_DIR, MODELS_DIR, DATABASE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ----------------------------------------------------------------------
# Database Configuration
# ----------------------------------------------------------------------
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").lower()  # 'mysql' or 'sqlite'
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "root")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "smartgrid_honeypot")

SQLITE_PATH = BASE_DIR / os.getenv("SQLITE_PATH", "smartgrid_honeypot.db")

# ----------------------------------------------------------------------
# MQTT Configuration
# ----------------------------------------------------------------------
MQTT_BROKER_HOST = os.getenv("MQTT_BROKER_HOST", "localhost")
MQTT_BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", 1883))
MQTT_KEEPALIVE = int(os.getenv("MQTT_KEEPALIVE", 60))
MQTT_FALLBACK_SIMULATION = os.getenv("MQTT_FALLBACK_SIMULATION", "true").lower() == "true"

# MQTT Topics
TOPIC_BASE = "smartgrid"
TOPIC_METER_TEMPLATE = "smartgrid/{home_id}/meter"
TOPIC_ALERTS = "smartgrid/alerts"
TOPIC_SECURITY_EVENTS = "smartgrid/security/events"

# ----------------------------------------------------------------------
# Smart Homes Simulation
# ----------------------------------------------------------------------
NUM_SMART_HOMES = int(os.getenv("NUM_SMART_HOMES", 10))
SIMULATION_INTERVAL_SEC = float(os.getenv("SIMULATION_INTERVAL_SEC", 2.0))

SMART_HOMES_CONFIG = [
    {
        "home_id": f"HOME_{i+1:02d}",
        "owner_name": name,
        "base_voltage": 230.0,
        "base_current": current,
        "has_solar": solar,
        "has_ev": ev,
        "energy_budget_kwh": budget,
        "ip_address": f"192.168.1.{10 + i}"
    }
    for i, (name, current, solar, ev, budget) in enumerate([
        ("Residential Alpha", 10.5, True, False, 25.0),
        ("Eco Villa Beta", 8.0, True, True, 35.0),
        ("Smart Duplex Gamma", 15.2, False, False, 30.0),
        ("Solar Heights Delta", 9.0, True, False, 22.0),
        ("Urban Microgrid Epsilon", 18.5, True, True, 45.0),
        ("Suburban Haven Zeta", 12.0, False, True, 32.0),
        ("Green Haven Eta", 7.5, True, False, 20.0),
        ("Civic Point Theta", 14.0, False, False, 28.0),
        ("Apex Smart Residence Iota", 11.2, True, True, 38.0),
        ("Sustainable Cottage Kappa", 6.8, True, False, 18.0),
    ])
]

# ----------------------------------------------------------------------
# Honeypot Configuration
# ----------------------------------------------------------------------
HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", "127.0.0.1")
HONEYPOT_SSH_PORT = int(os.getenv("HONEYPOT_SSH_PORT", 2222))
HONEYPOT_TELNET_PORT = int(os.getenv("HONEYPOT_TELNET_PORT", 2223))
HONEYPOT_LOG_PATH = BASE_DIR / os.getenv("HONEYPOT_LOG_PATH", "logs/cowrie.json")

# ----------------------------------------------------------------------
# Machine Learning & Threat Classification
# ----------------------------------------------------------------------
ATTACK_CATEGORIES = [
    "Normal Traffic",
    "Brute Force Attack",
    "Denial of Service (DoS)",
    "MQTT Unauthorized Access",
    "Suspicious Login",
    "Port Scanning",
    "Data Injection Attack"
]

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

RF_MODEL_PATH = MODELS_DIR / "random_forest.joblib"
IF_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"
METRICS_PATH = MODELS_DIR / "model_metrics.json"

# ----------------------------------------------------------------------
# Cryptography Configuration
# ----------------------------------------------------------------------
RSA_PRIVATE_KEY_PATH = BASE_DIR / os.getenv("RSA_PRIVATE_KEY_PATH", "keys/threat_intel_private.pem")
RSA_PUBLIC_KEY_PATH = BASE_DIR / os.getenv("RSA_PUBLIC_KEY_PATH", "keys/threat_intel_public.pem")
AES_KEY_FILE = KEYS_DIR / "aes_master.key"
AES_MASTER_KEY_HEX = os.getenv("AES_MASTER_KEY_HEX", "")
