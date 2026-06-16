"""
warden/agents/packs/crop_health_monitor.py
────────────────────────────────────────────
Crop Health Monitor — multispectral NDVI analysis.

Required sensors: ndvi, red_edge, soil_moisture
Output: health_score (0.0–1.0), stress_level, recommendation
"""
from __future__ import annotations

from warden.agents.packs.base import EdgeAgentPack, register


@register
class CropHealthMonitor(EdgeAgentPack):
    name             = "crop_health_monitor"
    description      = "Multispectral NDVI crop health analysis with stress detection and irrigation advisory."
    required_sensors = ["ndvi", "red_edge", "soil_moisture"]
    version          = "1.0.0"

    # NDVI thresholds
    _HEALTHY   = 0.6
    _STRESSED  = 0.3

    async def analyze(self, sensor_data: dict) -> dict:
        ndvi          = float(sensor_data.get("ndvi", 0.0))
        red_edge      = float(sensor_data.get("red_edge", 0.0))
        soil_moisture = float(sensor_data.get("soil_moisture", 0.0))

        health_score  = max(0.0, min(1.0, (ndvi * 0.6 + red_edge * 0.3 + soil_moisture * 0.1)))

        if ndvi >= self._HEALTHY:
            stress_level = "none"
        elif ndvi >= self._STRESSED:
            stress_level = "moderate"
        else:
            stress_level = "severe"

        chlorophyll_index = round(red_edge / max(ndvi, 0.01), 3)

        return {
            "health_score":      round(health_score, 3),
            "stress_level":      stress_level,
            "ndvi":              ndvi,
            "red_edge":          red_edge,
            "soil_moisture":     soil_moisture,
            "chlorophyll_index": chlorophyll_index,
            "missing_sensors":   self.validate_sensors(sensor_data),
        }

    async def recommend_action(self, analysis: dict) -> str:
        stress = analysis.get("stress_level", "none")
        score  = analysis.get("health_score", 1.0)
        sm     = analysis.get("soil_moisture", 1.0)

        if stress == "severe":
            return (
                f"URGENT: Crop health critical (score={score:.2f}). "
                "Immediate irrigation and disease inspection recommended. "
                "Consider foliar nitrogen application."
            )
        if stress == "moderate":
            parts = ["Moderate stress detected."]
            if sm < 0.35:
                parts.append("Soil moisture low — schedule irrigation within 24 h.")
            parts.append(f"Monitor NDVI daily (current={analysis.get('ndvi', 0):.2f}).")
            return " ".join(parts)
        return f"Crop health is good (score={score:.2f}, NDVI={analysis.get('ndvi', 0):.2f}). No immediate action required."
