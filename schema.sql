-- AI-Enhanced Honeypot System for Smart Grids (SDG 7)
-- Complete Database Schema (MySQL & SQLite compatible)

-- 1. smart_homes table
CREATE TABLE IF NOT EXISTS smart_homes (
    home_id VARCHAR(32) PRIMARY KEY,
    owner_name VARCHAR(128) NOT NULL,
    base_voltage DECIMAL(6, 2) DEFAULT 230.00,
    base_current DECIMAL(6, 2) DEFAULT 10.00,
    has_solar BOOLEAN DEFAULT FALSE,
    has_ev BOOLEAN DEFAULT FALSE,
    energy_budget_kwh DECIMAL(8, 2) DEFAULT 30.00,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(32) DEFAULT 'ONLINE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. smart_meter_readings table
CREATE TABLE IF NOT EXISTS smart_meter_readings (
    reading_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    home_id VARCHAR(32) NOT NULL,
    voltage DECIMAL(6, 2) NOT NULL,
    current DECIMAL(6, 2) NOT NULL,
    power_kw DECIMAL(8, 3) NOT NULL,
    reactive_power_kvar DECIMAL(8, 3) DEFAULT 0.00,
    power_factor DECIMAL(4, 3) DEFAULT 0.95,
    frequency_hz DECIMAL(5, 2) DEFAULT 50.00,
    energy_kwh DECIMAL(10, 3) NOT NULL,
    is_tampered BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (home_id) REFERENCES smart_homes(home_id) ON DELETE CASCADE
);

-- 3. network_traffic table
CREATE TABLE IF NOT EXISTS network_traffic (
    traffic_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INTEGER NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol VARCHAR(16) NOT NULL,
    packet_size INTEGER NOT NULL,
    num_packets INTEGER DEFAULT 1,
    traffic_rate_kbps DECIMAL(10, 2) DEFAULT 0.00,
    home_id VARCHAR(32),
    mqtt_topic VARCHAR(128),
    payload_preview TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. honeypot_events table
CREATE TABLE IF NOT EXISTS honeypot_events (
    event_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    service_type VARCHAR(16) NOT NULL, -- 'SSH' or 'Telnet'
    username VARCHAR(64),
    password VARCHAR(64),
    login_success BOOLEAN DEFAULT FALSE,
    command_entered TEXT,
    packet_size INTEGER DEFAULT 0,
    network_protocol VARCHAR(16) DEFAULT 'TCP',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. attack_detections table
CREATE TABLE IF NOT EXISTS attack_detections (
    detection_id VARCHAR(64) PRIMARY KEY,
    event_ref_id VARCHAR(64),
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    rf_predicted_attack VARCHAR(64) NOT NULL,
    rf_confidence DECIMAL(5, 4) NOT NULL,
    if_anomaly_score DECIMAL(7, 4) NOT NULL,
    if_is_anomaly BOOLEAN NOT NULL,
    final_classification VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    detection_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. threat_intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    threat_id VARCHAR(64) PRIMARY KEY,
    detection_ref_id VARCHAR(64) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    attack_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    -- Cryptographic Protection Fields
    encrypted_payload TEXT NOT NULL, -- Base64 AES-256-GCM ciphertext
    encryption_nonce VARCHAR(64) NOT NULL, -- Base64 12-byte GCM nonce
    encryption_tag VARCHAR(64) NOT NULL, -- Base64 16-byte GCM authentication tag
    sha256_hash VARCHAR(64) NOT NULL, -- 64-char Hex SHA-256 integrity hash
    rsa_signature TEXT NOT NULL, -- Base64 RSA-PSS-2048 digital signature
    verification_status VARCHAR(32) DEFAULT 'VERIFIED_VALID',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (detection_ref_id) REFERENCES attack_detections(detection_id) ON DELETE CASCADE
);

-- 7. security_alerts table
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id VARCHAR(64) PRIMARY KEY,
    threat_ref_id VARCHAR(64),
    severity VARCHAR(16) NOT NULL,
    attack_type VARCHAR(64) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_asset VARCHAR(64) NOT NULL,
    description TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE', -- 'ACTIVE', 'ACKNOWLEDGED', 'RESOLVED'
    alert_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. cryptographic_audit_logs table
CREATE TABLE IF NOT EXISTS cryptographic_audit_logs (
    log_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    threat_id VARCHAR(64),
    operation VARCHAR(32) NOT NULL, -- 'ENCRYPT', 'DECRYPT', 'HASH', 'SIGN', 'VERIFY'
    algorithm VARCHAR(32) NOT NULL, -- 'AES-256-GCM', 'SHA-256', 'RSA-2048-PSS'
    status VARCHAR(16) NOT NULL, -- 'SUCCESS', 'FAILED', 'TAMPER_DETECTED'
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_meter_home ON smart_meter_readings(home_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_src ON network_traffic(source_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON honeypot_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_detection_class ON attack_detections(final_classification, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON security_alerts(severity, status);

