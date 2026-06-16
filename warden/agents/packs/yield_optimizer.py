"""
warden/agents/packs/yield_optimizer.py
─────────────────────────────────────────
Yield Optimizer — optimal irrigation schedule from soil/weather data.

Required sensors: soil_moisture, temperature_c, humidity_pct, crop_type
Output: irrigation_schedule (list of time windows + durations), yield_risk
"""
from __future__ import annotations

from warden.agents.packs.base import EdgeAgentPack, register

# Simple lookup: optimal soil moisture range per crop type
_CROP_MOISTURE = {
    "wheat":   (0.30, 0.55),
    "corn":    (0.45, 0.65),
    "soybean": (0.40, 0.60),
    "cotton":  (0.35, 0.55),
    "rice":    (0.70, 0.90),
    "default": (0.40, 0.60),
}


@register
class YieldOptimizer(EdgeAgentPack):
    name             = "yield_optimizer"
    description      = "Soil-weather yield optimizer: computes optimal irrigation schedule and yield risk index."
    required_sensors = ["soil_moisture", "temperature_c", "humidity_pct", "crop_type"]
    version          = "1.0.0"

    async def analyze(self, sensor_data: dict) -> dict:
        sm        = float(sensor_data.get("soil_moisture", 0.5))
        temp      = float(sensor_data.get("temperature_c", 20.0))
        humidity  = float(sensor_data.get("humidity_pct", 50.0))
        crop      = str(sensor_data.get("crop_type", "default")).lower()

        low, high = _CROP_MOISTURE.get(crop, _CROP_MOISTURE["default"])

        evapotranspiration = round(0.0023 * (temp + 17.8) * (high - humidity / 100) * 25.4, 2)
        deficit            = max(0.0, low - sm)
        surplus            = max(0.0, sm - high)

        # Yield risk: 0.0 (none) → 1.0 (severe)
        yield_risk = min(1.0, deficit * 3 + (max(0.0, temp - 35) * 0.04))

        schedule = []
        if deficit > 0.05:
            duration_h = round(deficit * 10, 1)
            schedule = [
                {"window": "06:00–07:00", "duration_h": min(duration_h, 1.0)},
                {"window": "19:00–20:00", "duration_h": min(max(0.0, duration_h - 1.0), 1.0)},
            ]

        return {
            "crop_type":           crop,
            "soil_moisture":       sm,
            "moisture_range":      [low, high],
            "evapotranspiration_mm": evapotranspiration,
            "moisture_deficit":    round(deficit, 3),
            "moisture_surplus":    round(surplus, 3),
            "yield_risk":          round(yield_risk, 3),
            "irrigation_schedule": schedule,
            "missing_sensors":     self.validate_sensors(sensor_data),
        }

    async def recommend_action(self, analysis: dict) -> str:
        risk    = analysis.get("yield_risk", 0.0)
        deficit = analysis.get("moisture_deficit", 0.0)
        sched   = analysis.get("irrigation_schedule", [])
        crop    = analysis.get("crop_type", "crop")

        if risk > 0.7:
            return (
                f"HIGH yield risk for {crop} (risk={risk:.2f}). "
                f"Irrigate immediately: {sched[0]['window'] if sched else 'ASAP'} "
                f"({sched[0]['duration_h']:.1f}h). Check for heat stress."
            )
        if deficit > 0.05:
            sched_str = "; ".join(f"{s['window']} ({s['duration_h']:.1f}h)" for s in sched)
            return f"Scheduled irrigation for {crop}: {sched_str}."
        return f"{crop.capitalize()} moisture is optimal. No irrigation needed. Yield risk: {risk:.2f}."
