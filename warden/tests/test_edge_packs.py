"""Tests for ARC Edge Agent Packs (MKT-14)."""
from __future__ import annotations

import asyncio

import pytest

# Import packs so they self-register
import warden.agents.packs.crop_health_monitor
import warden.agents.packs.disease_detector
import warden.agents.packs.yield_optimizer  # noqa: F401
from warden.agents.packs.base import get_pack, list_packs


class TestPackRegistry:

    def test_packs_registered(self):
        names = {p["name"] for p in list_packs()}
        assert "crop_health_monitor" in names
        assert "yield_optimizer" in names
        assert "disease_detector" in names

    def test_get_pack_returns_class(self):
        cls = get_pack("crop_health_monitor")
        assert cls is not None
        assert hasattr(cls, "analyze")

    def test_get_missing_pack_returns_none(self):
        assert get_pack("nonexistent_pack_xyz") is None

    def test_list_packs_has_required_fields(self):
        for p in list_packs():
            assert "name" in p
            assert "description" in p
            assert "required_sensors" in p
            assert "version" in p


class TestCropHealthMonitor:

    def _run(self, coro):
        return asyncio.run(coro)

    def test_healthy_crop(self):
        cls = get_pack("crop_health_monitor")
        pack = cls()
        analysis = self._run(pack.analyze({"ndvi": 0.8, "red_edge": 0.7, "soil_moisture": 0.5}))
        assert analysis["stress_level"] == "none"
        assert analysis["health_score"] > 0.5

    def test_severely_stressed_crop(self):
        cls = get_pack("crop_health_monitor")
        pack = cls()
        analysis = self._run(pack.analyze({"ndvi": 0.1, "red_edge": 0.1, "soil_moisture": 0.1}))
        assert analysis["stress_level"] == "severe"

    def test_recommend_action_urgent_on_severe(self):
        cls = get_pack("crop_health_monitor")
        pack = cls()
        action = self._run(pack.recommend_action({"stress_level": "severe", "health_score": 0.1, "ndvi": 0.1, "soil_moisture": 0.1}))
        assert "URGENT" in action

    def test_validate_sensors_missing(self):
        cls = get_pack("crop_health_monitor")
        pack = cls()
        missing = pack.validate_sensors({"ndvi": 0.5})  # missing red_edge, soil_moisture
        assert "red_edge" in missing
        assert "soil_moisture" in missing


class TestYieldOptimizer:

    def _run(self, coro):
        return asyncio.run(coro)

    def test_optimal_moisture_no_schedule(self):
        cls = get_pack("yield_optimizer")
        pack = cls()
        analysis = self._run(pack.analyze({
            "soil_moisture": 0.52, "temperature_c": 22.0,
            "humidity_pct": 60.0, "crop_type": "wheat",
        }))
        assert analysis["moisture_deficit"] == pytest.approx(0.0, abs=0.05)
        assert analysis["irrigation_schedule"] == []

    def test_drought_generates_schedule(self):
        cls = get_pack("yield_optimizer")
        pack = cls()
        analysis = self._run(pack.analyze({
            "soil_moisture": 0.1, "temperature_c": 38.0,
            "humidity_pct": 20.0, "crop_type": "corn",
        }))
        assert len(analysis["irrigation_schedule"]) > 0
        assert analysis["yield_risk"] > 0.5


class TestDiseaseDetector:

    def _run(self, coro):
        return asyncio.run(coro)

    def test_heuristic_healthy_ndvi(self):
        cls = get_pack("disease_detector")
        pack = cls()
        analysis = self._run(pack.analyze({"ndvi": 0.8, "crop_type": "wheat"}))
        assert analysis["severity"] == "none"

    def test_heuristic_severe_ndvi(self):
        cls = get_pack("disease_detector")
        pack = cls()
        analysis = self._run(pack.analyze({"ndvi": 0.15, "crop_type": "corn"}))
        assert analysis["severity"] in ("severe", "high")
        assert len(analysis["detected_issues"]) > 0

    def test_recommend_urgent_for_severe(self):
        cls = get_pack("disease_detector")
        pack = cls()
        action = self._run(pack.recommend_action({
            "severity": "severe",
            "detected_issues": ["leaf_blight"],
            "crop_type": "corn",
            "area_affected_pct": 40,
        }))
        assert "URGENT" in action
