"""
Smart Home Entity Module
Represents individual smart homes in the multi-home smart grid network.
Each home contains unique properties, appliances, smart meter, and network identities.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config
from simulation.smart_meter import SmartMeter

class SmartHome:
    def __init__(self, home_id: str, owner_name: str, base_voltage: float,
                 base_current: float, has_solar: bool, has_ev: bool,
                 energy_budget_kwh: float, ip_address: str):
        self.home_id = home_id
        self.owner_name = owner_name
        self.has_solar = has_solar
        self.has_ev = has_ev
        self.energy_budget_kwh = energy_budget_kwh
        self.ip_address = ip_address
        self.status = "ONLINE"
        self.meter = SmartMeter(
            home_id=home_id,
            base_voltage=base_voltage,
            base_current=base_current,
            has_solar=has_solar,
            has_ev=has_ev
        )

    def get_meter_reading(self) -> Dict[str, Any]:
        """Collects current reading from the home's smart meter."""
        reading = self.meter.generate_reading()
        reading["owner_name"] = self.owner_name
        reading["ip_address"] = self.ip_address
        return reading

    def trigger_tamper_attack(self, enable: bool = True):
        """Simulates data injection cyberattack targeting this smart home's meter."""
        self.meter.toggle_tamper(enable)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "home_id": self.home_id,
            "owner_name": self.owner_name,
            "has_solar": self.has_solar,
            "has_ev": self.has_ev,
            "energy_budget_kwh": self.energy_budget_kwh,
            "ip_address": self.ip_address,
            "status": self.status
        }

def load_all_smart_homes() -> List[SmartHome]:
    """Loads all 10 configured smart homes."""
    homes = []
    for cfg in config.SMART_HOMES_CONFIG:
        home = SmartHome(
            home_id=cfg["home_id"],
            owner_name=cfg["owner_name"],
            base_voltage=cfg["base_voltage"],
            base_current=cfg["base_current"],
            has_solar=cfg["has_solar"],
            has_ev=cfg["has_ev"],
            energy_budget_kwh=cfg["energy_budget_kwh"],
            ip_address=cfg["ip_address"]
        )
        homes.append(home)
    return homes

if __name__ == "__main__":
    homes = load_all_smart_homes()
    print(f"[OK] Successfully initialized {len(homes)} smart homes.")
    for h in homes[:3]:
        r = h.get_meter_reading()
        print(f"    - {h.home_id} ({h.owner_name}): {r['power_kw']} kW @ {r['voltage']} V")

