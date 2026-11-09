"""
Master Streamlit Application
AI-Enhanced Honeypot System for Cyber Threat Intelligence and Cryptographic Security
in Multi-Home Smart Grids (SDG 7)
"""

import sys
import time
import random
from pathlib import Path
import streamlit as st

# Configure page
st.set_page_config(
    page_title="AI Smart Grid Honeypot (SDG 7)",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Project path resolution
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from database.db_connection import get_db, execute, fetch_one
from simulation.smart_home import load_all_smart_homes
from simulation.mqtt_publisher import get_publisher
from simulation.mqtt_subscriber import get_subscriber
from simulation.traffic_generator import get_traffic_generator
from honeypot.honeypot_server import CowrieHoneypotServer
from honeypot.cowrie_collector import get_collector
from detection.detection_engine import get_detection_engine
from cryptography.key_management import ensure_keys_exist

# Import dashboard sections
from dashboard.overview import render_overview
from dashboard.smart_grid import render_smart_grid
from dashboard.honeypot import render_honeypot
from dashboard.attack_detection import render_attack_detection
from dashboard.threat_intelligence import render_threat_intelligence
from dashboard.security_alerts import render_security_alerts

# Custom Dark Cybersecurity CSS Theme
st.markdown(
    """
    <style>
    /* Dark Cybersecurity Background & Containers */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Top Banner / Header Card */
    .main-header {
        background: linear-gradient(135deg, #10172a 0%, #1e1b4b 50%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 18px 24px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0, 255, 204, 0.08);
    }
    .main-title {
        color: #38bdf8;
        font-size: 24px;
        font-weight: 700;
        margin: 0;
        letter-spacing: 0.5px;
    }
    .main-subtitle {
        color: #94a3b8;
        font-size: 14px;
        margin-top: 4px;
    }

    /* Metric cards styling */
    div[data-testid="stMetric"] {
        background-color: #131c2e;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 12px 16px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    }
    div[data-testid="stMetric"]:hover {
        border-color: #00ffcc;
        box-shadow: 0 4px 15px rgba(0, 255, 204, 0.15);
        transition: all 0.3s ease;
    }
    div[data-testid="stMetricLabel"] {
        color: #94a3b8;
        font-size: 13px;
        font-weight: 500;
    }
    div[data-testid="stMetricValue"] {
        color: #f8fafc;
        font-size: 24px;
        font-weight: 700;
    }

    /* Streamlit DataFrame styling */
    div[data-testid="stDataFrame"] {
        background-color: #101726;
        border: 1px solid #1e293b;
        border-radius: 8px;
    }

    /* Sidebar Styling & High-Contrast Navigation */
    section[data-testid="stSidebar"] {
        background-color: #0b1120 !important;
        border-right: 1px solid #1e293b;
    }

    section[data-testid="stSidebar"] * {
        color: #f1f5f9;
    }

    /* Headings in Sidebar */
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3,
    section[data-testid="stSidebar"] h4,
    section[data-testid="stSidebar"] h5 {
        color: #38bdf8 !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px;
    }

    /* Navigation Radio Group Options - Crisp & High Contrast */
    div[data-testid="stRadio"] label {
        color: #cbd5e1 !important;
        font-weight: 600 !important;
        font-size: 14px !important;
    }

    div[data-testid="stRadio"] div[role="radiogroup"] {
        gap: 6px !important;
    }

    div[data-testid="stRadio"] div[role="radiogroup"] label {
        background-color: #131c2e !important;
        border: 1px solid #1e293b !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
        margin-bottom: 4px !important;
        transition: all 0.2s ease-in-out !important;
        cursor: pointer !important;
    }

    div[data-testid="stRadio"] div[role="radiogroup"] label:hover {
        background-color: #1e293b !important;
        border-color: #38bdf8 !important;
    }

    /* Pure white, high-visibility text for navigation options */
    div[data-testid="stRadio"] div[role="radiogroup"] label p,
    div[data-testid="stRadio"] div[role="radiogroup"] label span,
    div[data-testid="stRadio"] div[role="radiogroup"] label div {
        color: #ffffff !important;
        font-size: 15px !important;
        font-weight: 600 !important;
        letter-spacing: 0.3px !important;
    }

    /* Selected Navigation Item: Glowing Cyber Cyan Accent */
    div[data-testid="stRadio"] div[role="radiogroup"] label[data-checked="true"],
    div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
        background: linear-gradient(90deg, #1e293b 0%, #0f2744 100%) !important;
        border-color: #00ffcc !important;
        box-shadow: 0 0 10px rgba(0, 255, 204, 0.25) !important;
    }

    div[data-testid="stRadio"] div[role="radiogroup"] label[data-checked="true"] p,
    div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) p {
        color: #00ffcc !important;
        font-weight: 700 !important;
    }

    /* Sidebar Selectbox & Inputs */
    section[data-testid="stSidebar"] div[data-testid="stSelectbox"] label p {
        color: #e2e8f0 !important;
        font-weight: 600 !important;
    }

    /* Sidebar Captions & Diagnostics */
    section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
        color: #cbd5e1 !important;
        font-size: 13px !important;
    }

    /* Universal Input & Textarea Styling for High Visibility */
    div[data-testid="stTextInput"] input:disabled,
    div[data-testid="stTextArea"] textarea:disabled {
        background-color: #131c2e !important;
        color: #00ffcc !important;
        -webkit-text-fill-color: #00ffcc !important;
        border: 1px solid #334155 !important;
        font-family: 'Consolas', 'Courier New', monospace !important;
        font-weight: 500 !important;
    }

    div[data-testid="stTextInput"] label,
    div[data-testid="stTextArea"] label,
    div[data-testid="stSelectbox"] label {
        color: #cbd5e1 !important;
        font-weight: 600 !important;
    }

    /* Glowing Accent Badges */
    .sdg-badge {
        display: inline-block;
        background: linear-gradient(90deg, #059669, #10b981);
        color: white;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        margin-bottom: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

def run_simulation_step():
    """Generates 1 cycle of smart meter readings, honeypot events, and AI threat detection."""
    homes = load_all_smart_homes()
    pub = get_publisher()
    engine = get_detection_engine()
    gen = get_traffic_generator()

    # 1. Publish Smart Meter Readings for all 10 homes
    for home in homes:
        reading = home.get_meter_reading()
        pub.publish_meter_reading(reading)

    # 2. Generate and process a mix of normal and attack network events
    for _ in range(random.randint(2, 4)):
        event = gen.generate_event()
        engine.process_event(event)

    # 3. Honeypot probe
    hp = CowrieHoneypotServer()
    hp.simulate_attacker_session()
    collector = get_collector()
    collector.ingest_to_database()

def inject_specific_attack(attack_type: str):
    """Directly triggers a specific cyberattack scenario."""
    gen = get_traffic_generator()
    engine = get_detection_engine()
    pub = get_publisher()

    # If Data Injection Attack, tamper a smart meter
    if attack_type == "Data Injection Attack":
        homes = load_all_smart_homes()
        target_home = random.choice(homes)
        target_home.trigger_tamper_attack(True)
        reading = target_home.get_meter_reading()
        pub.publish_meter_reading(reading)

    event = gen.generate_event(attack_type=attack_type)
    result = engine.process_event(event)
    return result

# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------
st.markdown(
    """
    <div class="main-header">
        <span class="sdg-badge">⚡ UN SDG 7: Affordable & Clean Energy</span>
        <h1 class="main-title">AI-Enhanced Honeypot & Cryptographic Security System</h1>
        <div class="main-subtitle">
            Autonomous Intrusion Detection, Cowrie Threat Telemetry, and Cryptographic Protection for Multi-Home Smart Grids
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# ----------------------------------------------------------------------
# Sidebar Navigation & Live Controls
# ----------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🧭 Navigation")
    menu = st.radio(
        "Select Module:",
        [
            "🌐 Overview Dashboard",
            "⚡ Smart Grid Monitoring",
            "🍯 Honeypot Monitoring",
            "🧠 AI-Based Attack Detection",
            "🔐 Threat Intelligence",
            "🚨 Security Alerts"
        ]
    )

    st.markdown("---")
    st.markdown("### 🕹️ Live Simulation Controls")

    if st.button("⚡ Step Simulation Cycle", use_container_width=True):
        with st.spinner("Generating smart meter telemetry & inspecting network..."):
            run_simulation_step()
            st.success("Simulation cycle processed!")
            st.rerun()

    st.markdown("##### 🚨 Attack Injection Laboratory")
    selected_attack = st.selectbox(
        "Select Attack Scenario:",
        [
            "Brute Force Attack",
            "Denial of Service (DoS)",
            "MQTT Unauthorized Access",
            "Suspicious Login",
            "Port Scanning",
            "Data Injection Attack"
        ]
    )

    if st.button("🎯 Inject Selected Attack", use_container_width=True):
        with st.spinner(f"Injecting {selected_attack}..."):
            res = inject_specific_attack(selected_attack)
            st.error(f"Injected {selected_attack} -> Severity: {res['severity']}")
            st.rerun()

    if st.button("🍯 Trigger Honeypot Attacker Probe", use_container_width=True):
        hp = CowrieHoneypotServer()
        for _ in range(3):
            hp.simulate_attacker_session()
        get_collector().ingest_to_database()
        st.warning("Simulated 3 attacker intrusions into Cowrie SSH/Telnet trap!")
        st.rerun()

    st.markdown("---")
    st.markdown("### 🔌 System Diagnostics")
    db = get_db()
    st.caption(f"**Database**: {db.active_engine.upper()}")
    st.caption(f"**MQTT Broker**: {config.MQTT_BROKER_HOST}:{config.MQTT_BROKER_PORT} (Embedded Fallback Active)")
    st.caption(f"**Honeypot Trap**: Ports {config.HONEYPOT_SSH_PORT} (SSH) / {config.HONEYPOT_TELNET_PORT} (Telnet)")
    st.caption(f"**Cryptography**: AES-256-GCM / SHA-256 / RSA-2048-PSS Active")

    auto_refresh = st.checkbox("Auto-refresh (5s)", value=False)
    if auto_refresh:
        time.sleep(5)
        st.rerun()

# ----------------------------------------------------------------------
# Module Rendering
# ----------------------------------------------------------------------
# Ensure cryptographic keys & MQTT subscriber are active
ensure_keys_exist()
get_subscriber()

if menu == "🌐 Overview Dashboard":
    render_overview()
elif menu == "⚡ Smart Grid Monitoring":
    render_smart_grid()
elif menu == "🍯 Honeypot Monitoring":
    render_honeypot()
elif menu == "🧠 AI-Based Attack Detection":
    render_attack_detection()
elif menu == "🔐 Threat Intelligence":
    render_threat_intelligence()
elif menu == "🚨 Security Alerts":
    render_security_alerts()
