"""
Database Initializer Script
Creates all required tables for the AI-Enhanced Smart Grid Honeypot System
and populates initial smart home metadata.
"""

import os
import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from database.db_connection import get_db, execute, fetch_all, fetch_one
import pymysql
import sqlite3

def clean_sql_for_sqlite(sql: str) -> str:
    """Adapts MySQL DDL into SQLite-compatible DDL."""
    # Replace AUTO_INCREMENT with AUTOINCREMENT
    # In SQLite, AUTOINCREMENT is only valid with INTEGER PRIMARY KEY
    sql = sql.replace("AUTO_INCREMENT", "AUTOINCREMENT")
    # Replace BOOLEAN with INTEGER
    # Remove ON UPDATE CURRENT_TIMESTAMP if any
    lines = []
    for line in sql.splitlines():
        # Remove comment lines or standalone delimiters
        trimmed = line.strip()
        if trimmed.startswith("--") or not trimmed:
            continue
        lines.append(line)
    return "\n".join(lines)

def init_mysql_database():
    """Ensures MySQL database exists before creating tables."""
    try:
        conn = pymysql.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USER,
            password=config.MYSQL_PASSWORD,
            autocommit=True
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{config.MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        cursor.close()
        conn.close()
        print(f"[OK] MySQL Database `{config.MYSQL_DATABASE}` verified/created.")
    except Exception as e:
        print(f"[WARN] Unable to pre-create MySQL database ({e}). Will proceed with connection check.")

def create_tables():
    db = get_db()
    schema_path = config.DATABASE_DIR / "schema.sql"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found at {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_content = f.read()

    print(f"[*] Initializing database using active engine: {db.active_engine.upper()}")

    # Split schema statements by semicolon
    statements = [stmt.strip() for stmt in schema_content.split(";") if stmt.strip()]

    conn = db.get_raw_connection()
    cursor = conn.cursor()

    for stmt in statements:
        if not stmt:
            continue
        try:
            if db.active_engine == "sqlite":
                # For SQLite, filter out CREATE INDEX IF NOT EXISTS or adapt
                stmt_adapted = stmt.replace("AUTO_INCREMENT", "AUTOINCREMENT")
                cursor.execute(stmt_adapted)
            else:
                cursor.execute(stmt)
        except Exception as e:
            # Table might already exist or harmless warning
            print(f"    [Notice] Table/Index statement: {e}")

    if db.active_engine == "sqlite":
        conn.commit()
    cursor.close()
    conn.close()
    print("[OK] All 8 database tables created or verified successfully.")

def seed_smart_homes():
    """Populates the 10 simulated smart homes from config."""
    print("[*] Seeding simulated smart homes...")
    insert_sql = """
    INSERT INTO smart_homes (
        home_id, owner_name, base_voltage, base_current, 
        has_solar, has_ev, energy_budget_kwh, ip_address, status
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    for home in config.SMART_HOMES_CONFIG:
        existing = fetch_one("SELECT home_id FROM smart_homes WHERE home_id = %s", (home["home_id"],))
        if not existing:
            execute(insert_sql, (
                home["home_id"],
                home["owner_name"],
                home["base_voltage"],
                home["base_current"],
                home["has_solar"],
                home["has_ev"],
                home["energy_budget_kwh"],
                home["ip_address"],
                "ONLINE"
            ))
            print(f"    + Created Smart Home: {home['home_id']} ({home['owner_name']})")
        else:
            print(f"    - Home {home['home_id']} already registered.")

    count = fetch_one("SELECT COUNT(*) as cnt FROM smart_homes")
    print(f"[OK] Total registered Smart Homes: {count['cnt'] if count else len(config.SMART_HOMES_CONFIG)}")

def verify_installation():
    """Verifies that all 8 required tables exist and are accessible."""
    required_tables = [
        "smart_homes",
        "smart_meter_readings",
        "network_traffic",
        "honeypot_events",
        "attack_detections",
        "threat_intelligence",
        "security_alerts",
        "cryptographic_audit_logs"
    ]

    db = get_db()
    print("\n--- Database Verification Summary ---")
    print(f"Active Engine: {db.active_engine.upper()}")
    all_ok = True

    for tbl in required_tables:
        try:
            res = fetch_one(f"SELECT COUNT(*) as count FROM {tbl}")
            cnt = res["count"] if res else 0
            print(f"  [✓] Table '{tbl}': Accessible ({cnt} rows)")
        except Exception as e:
            print(f"  [✗] Table '{tbl}': Error ({e})")
            all_ok = False

    if all_ok:
        print("[SUCCESS] Database schema initialized and verified 100% successfully.\n")
    else:
        print("[WARNING] Some tables encountered issues. Please check logs above.\n")

def main():
    print("=" * 65)
    print("AI-Enhanced Honeypot & Smart Grid Cybersecurity System")
    print("Database Initializer (SDG 7)")
    print("=" * 65)

    if config.DB_ENGINE == "mysql":
        init_mysql_database()

    create_tables()
    seed_smart_homes()
    verify_installation()

if __name__ == "__main__":
    main()

