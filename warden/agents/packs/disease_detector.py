"""
warden/agents/packs/disease_detector.py
─────────────────────────────────────────
Disease/Pest Detector — image-based crop disease identification.

Required sensors: image_base64 (JPEG/PNG), crop_type
Optional: location, ndvi

Calls Claude Vision (via ANTHROPIC_API_KEY) if available.
Falls back to NDVI-based heuristic when Vision is unavailable.
"""
from __future__ import annotations

import logging
import os

from warden.agents.packs.base import EdgeAgentPack, register

log = logging.getLogger("warden.agents.packs.disease_detector")

_ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
_MODEL         = "claude-haiku-4-5-20251001"

_KNOWN_DISEASES = [
    "rust", "blight", "mildew", "mosaic_virus", "leaf_spot",
    "aphids", "whitefly", "mites", "stem_borer",
]


@register
class DiseaseDetector(EdgeAgentPack):
    name             = "disease_detector"
    description      = "AI-powered crop disease and pest detection from field images using Claude Vision."
    required_sensors = ["image_base64", "crop_type"]
    version          = "1.0.0"

    async def analyze(self, sensor_data: dict) -> dict:
        img_b64  = str(sensor_data.get("image_base64", ""))
        crop     = str(sensor_data.get("crop_type", "unknown"))
        ndvi     = float(sensor_data.get("ndvi", 1.0))
        location = str(sensor_data.get("location", ""))

        if _ANTHROPIC_KEY and img_b64:
            return await self._claude_vision_analysis(img_b64, crop, location)

        # Heuristic fallback: infer disease risk from NDVI
        return self._heuristic_analysis(ndvi, crop, sensor_data)

    async def _claude_vision_analysis(self, img_b64: str, crop: str, location: str) -> dict:
        try:
            import anthropic  # noqa: PLC0415
            client = anthropic.AsyncAnthropic(api_key=_ANTHROPIC_KEY)
            prompt = (
                f"You are an agricultural AI expert. Analyze this {crop} field image for diseases and pests. "
                f"Location context: {location or 'not provided'}. "
                "List: detected diseases/pests (if any), confidence (0-100), severity (none/low/moderate/high/severe), "
                "and specific crop area affected (%). Respond as JSON only."
            )
            msg = await client.messages.create(
                model=_MODEL,
                max_tokens=512,
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": img_b64}},
                        {"type": "text",  "text": prompt},
                    ],
                }],
            )
            import json  # noqa: PLC0415
            try:
                raw   = msg.content[0].text  # type: ignore[union-attr]
                start = raw.find("{")
                end   = raw.rfind("}") + 1
                data  = json.loads(raw[start:end])
            except Exception:
                data = {"raw": msg.content[0].text}  # type: ignore[union-attr]
            data["source"] = "claude_vision"
            data["missing_sensors"] = self.validate_sensors({"image_base64": img_b64, "crop_type": crop})
            return data
        except Exception as exc:
            log.warning("DiseaseDetector: Claude Vision failed: %s", exc)
            return self._heuristic_analysis(1.0, crop, {})

    def _heuristic_analysis(self, ndvi: float, crop: str, sensor_data: dict) -> dict:
        if ndvi < 0.2:
            severity, detected = "severe", ["leaf_blight", "root_rot"]
            confidence = 60
        elif ndvi < 0.4:
            severity, detected = "moderate", ["powdery_mildew"]
            confidence = 45
        elif ndvi < 0.6:
            severity, detected = "low", []
            confidence = 30
        else:
            severity, detected = "none", []
            confidence = 20

        return {
            "source":            "heuristic_ndvi",
            "crop_type":         crop,
            "detected_issues":   detected,
            "severity":          severity,
            "confidence":        confidence,
            "area_affected_pct": max(0, int((1.0 - ndvi) * 100)),
            "ndvi":              ndvi,
            "missing_sensors":   self.validate_sensors(sensor_data),
        }

    async def recommend_action(self, analysis: dict) -> str:
        severity  = analysis.get("severity", "none")
        detected  = analysis.get("detected_issues", []) or analysis.get("detected", [])
        crop      = analysis.get("crop_type", "crop")
        area      = analysis.get("area_affected_pct", 0)

        if severity in ("severe", "high"):
            issues = ", ".join(detected) if detected else "unknown issue"
            return (
                f"URGENT: {crop} has {severity} {issues} affecting ~{area}% of field. "
                "Apply appropriate fungicide/pesticide immediately. "
                "Isolate affected area to prevent spread."
            )
        if severity == "moderate":
            return (
                f"Moderate disease/pest pressure detected in {crop} ({', '.join(detected)}). "
                "Schedule treatment within 48 h and monitor spread."
            )
        if severity == "low":
            return f"Low pest/disease risk in {crop}. Continue monitoring — no immediate treatment required."
        return f"No disease or pest issues detected in {crop}. Field appears healthy."
