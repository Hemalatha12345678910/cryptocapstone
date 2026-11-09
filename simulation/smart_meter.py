"""
Smart Meter Simulation Module
Simulates accurate electrical physics for residential and microgrid smart meters:
Voltage, Current, Active Power (kW), Reactive Power (kVAR), Power Factor,
Frequency (Hz), and Cumulative Energy (kWh).
Supports normal operation and simulated Data Injection Attacks.
"""

import math
import random
import time
from datetime import datetime
from typing import Dict, Any

class SmartMeter:
    def __init__(self, home_id: str, base_voltage: float = 230.0, base_current: float = 10.0,
                 has_solar: bool = False, has_ev: bool = False):
        self.home_id = home_id
        self.nominal_voltage = base_voltage
        self.base_current = base_current
        self.has_solar = has_solar
        self.has_ev = has_ev
        self.cumulative_energy_kwh = random.uniform(150.0, 500.0)
        self.last_reading_time = time.time()
        self.tamper_mode = False

    def toggle_tamper(self, enable: bool = True):
        """Enables or disables data injection tampering on this meter."""
        self.tamper_mode = enable

    def generate_reading(self) -> Dict[str, Any]:
        """
        Generates realistic electrical measurement.
        If tampered, injects anomalies (extreme voltage spikes/drops, negative power, or false zeros).
        """
        now = time.time()
        elapsed_hours = max((now - self.last_reading_time) / 3600.0, 0.0005)
        self.last_reading_time = now

        # Normal fluctuations
        voltage = self.nominal_voltage + random.gauss(0, 1.8)
        frequency = 50.00 + random.gauss(0, 0.05)
        power_factor = min(max(0.92 + random.gauss(0, 0.02), 0.85), 0.99)

        # Current calculation based on base profile, solar, and EV load
        current_load = max(0.5, self.base_current + random.gauss(0, 2.0))
        
        # EV charging spikes
        if self.has_ev and random.random() < 0.25:
            current_load += random.uniform(12.0, 24.0)

        # Solar deduction (during daytime)
        solar_generation_kw = 0.0
        if self.has_solar:
            # Solar generation peak
            hour = datetime.now().hour
            if 7 <= hour <= 18:
                solar_factor = math.sin((hour - 7) / 11.0 * math.pi)
                solar_generation_kw = max(0.0, solar_factor * random.uniform(2.0, 5.0))
                solar_offset_current = (solar_generation_kw * 1000.0) / voltage
                current_load = max(0.2, current_load - solar_offset_current)

        # Active Power P = V * I * PF / 1000 (kW)
        power_kw = (voltage * current_load * power_factor) / 1000.0

        # Reactive Power Q = V * I * sin(acos(PF)) / 1000 (kVAR)
        sin_phi = math.sqrt(max(0.0, 1.0 - (power_factor ** 2)))
        reactive_power_kvar = (voltage * current_load * sin_phi) / 1000.0

        is_tampered = False

        # Injected Cyber Attack Simulation (Data Injection Attack)
        if self.tamper_mode:
            is_tampered = True
            attack_variant = random.choice(["voltage_sag", "voltage_swell", "negative_power", "zero_injection"])
            if attack_variant == "voltage_sag":
                voltage = random.uniform(140.0, 175.0)  # Severe brownout injection
            elif attack_variant == "voltage_swell":
                voltage = random.uniform(285.0, 340.0)  # Severe overvoltage injection
            elif attack_variant == "negative_power":
                power_kw = -abs(power_kw * random.uniform(1.5, 4.0))  # Electricity theft / reverse flow
            elif attack_variant == "zero_injection":
                power_kw = 0.001
                current_load = 0.001

        # Accumulate energy
        if not is_tampered and power_kw > 0:
            self.cumulative_energy_kwh += power_kw * elapsed_hours

        return {
            "home_id": self.home_id,
            "voltage": round(float(voltage), 2),
            "current": round(float(current_load), 2),
            "power_kw": round(float(power_kw), 3),
            "reactive_power_kvar": round(float(reactive_power_kvar), 3),
            "power_factor": round(float(power_factor), 3),
            "frequency_hz": round(float(frequency), 2),
            "energy_kwh": round(float(self.cumulative_energy_kwh), 3),
            "solar_generation_kw": round(float(solar_generation_kw), 3),
            "is_tampered": bool(is_tampered),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

if __name__ == "__main__":
    meter = SmartMeter("HOME_01", 230.0, 10.5, has_solar=True, has_ev=True)
    reading = meter.generate_reading()
    print("[OK] Smart Meter Normal Reading:", reading)
    meter.toggle_tamper(True)
    tampered_reading = meter.generate_reading()
    print("[OK] Smart Meter Tampered Reading:", tampered_reading)

