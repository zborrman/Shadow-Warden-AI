"""Tests for warden/marketplace/model_router.py — Dynamic Model Router."""
from __future__ import annotations

import pytest

from warden.marketplace.model_router import (
    MODEL_HAIKU,
    MODEL_OPUS,
    MODEL_SONNET,
    model_for_action,
    route,
    route_for_sova_tool,
    score_action,
)


class TestScoring:
    def test_search_is_low_complexity(self):
        score, _ = score_action("search")
        assert score < 0.35

    def test_dispute_is_high_complexity(self):
        score, _ = score_action("raise_dispute")
        assert score >= 0.65

    def test_payload_length_increases_score(self):
        short_score, _ = score_action("negotiate", payload="x")
        long_score, _  = score_action("negotiate", payload="x" * 3000)
        assert long_score > short_score

    def test_round_count_increases_score(self):
        s0, _ = score_action("send_offer", round_count=0)
        s5, _ = score_action("send_offer", round_count=5)
        assert s5 > s0

    def test_round_bonus_caps_at_0_15(self):
        _, bd = score_action("search", round_count=100)
        assert bd["round_count"] <= 0.15

    def test_payload_bonus_caps_at_0_20(self):
        _, bd = score_action("search", payload="x" * 100_000)
        assert bd["payload_length"] <= 0.20

    def test_maestro_high_adds_0_25(self):
        _, bd_none = score_action("search", maestro_risk="NONE")
        _, bd_high = score_action("search", maestro_risk="HIGH")
        assert bd_high["maestro_risk"] == pytest.approx(0.25)
        assert bd_none["maestro_risk"] == pytest.approx(0.0)

    def test_total_never_exceeds_1(self):
        score, _ = score_action("raise_dispute", payload="x" * 100_000,
                                round_count=100, maestro_risk="HIGH")
        assert score <= 1.0

    def test_unknown_action_uses_default_base(self):
        score, bd = score_action("nonexistent_action_xyz")
        assert bd["base"] == pytest.approx(0.40)

    def test_breakdown_keys_present(self):
        _, bd = score_action("search")
        assert set(bd.keys()) == {"base", "payload_length", "round_count", "maestro_risk", "total"}


class TestRouting:
    def test_search_routes_to_haiku(self):
        d = route("search")
        assert d.model == MODEL_HAIKU
        assert d.tier  == "haiku"

    def test_dispute_routes_to_opus(self):
        d = route("raise_dispute")
        assert d.model == MODEL_OPUS
        assert d.tier  == "opus"

    def test_negotiate_routes_to_sonnet_by_default(self):
        d = route("negotiate")
        assert d.model == MODEL_SONNET
        assert d.tier  == "sonnet"

    def test_high_maestro_escalates_search_to_sonnet(self):
        d = route("search", maestro_risk="HIGH")
        # base 0.10 + maestro 0.25 = 0.35, sits on the boundary
        # with default HAIKU_THRESHOLD=0.35 this is NOT < threshold → sonnet
        assert d.model in (MODEL_SONNET, MODEL_OPUS)

    def test_route_decision_has_breakdown(self):
        d = route("negotiate", payload={"price": 10})
        assert isinstance(d.breakdown, dict)
        assert "total" in d.breakdown

    def test_reason_contains_action_and_score(self):
        d = route("search")
        assert "search" in d.reason
        assert "score=" in d.reason

    def test_force_model_env_haiku(self, monkeypatch):
        monkeypatch.setenv("ROUTER_FORCE_MODEL", "haiku")
        # reload module to pick up env change
        import importlib

        import warden.marketplace.model_router as mr
        importlib.reload(mr)
        d = mr.route("raise_dispute")  # would normally be opus
        assert d.tier == "haiku"
        monkeypatch.delenv("ROUTER_FORCE_MODEL")
        importlib.reload(mr)

    def test_force_model_invalid_ignored(self, monkeypatch):
        monkeypatch.setenv("ROUTER_FORCE_MODEL", "invalid_model")
        import importlib

        import warden.marketplace.model_router as mr
        importlib.reload(mr)
        # should fall through to normal scoring
        d = mr.route("search")
        assert d.model == MODEL_HAIKU  # normal routing still works
        monkeypatch.delenv("ROUTER_FORCE_MODEL")
        importlib.reload(mr)


class TestConvenienceFunctions:
    def test_model_for_action_returns_string(self):
        m = model_for_action("search")
        assert isinstance(m, str)
        assert m.startswith("claude-")

    def test_route_for_sova_known_tool(self):
        m = route_for_sova_tool("acp_search_catalog", {"q": "security rules"})
        assert m == MODEL_HAIKU  # search → haiku

    def test_route_for_sova_unknown_tool_defaults_sonnet(self):
        m = route_for_sova_tool("some_unknown_tool_xyz", {})
        assert m == MODEL_SONNET


class TestThresholdConfiguration:
    def test_custom_haiku_threshold(self, monkeypatch):
        monkeypatch.setenv("ROUTER_HAIKU_THRESHOLD", "0.99")
        import importlib

        import warden.marketplace.model_router as mr
        importlib.reload(mr)
        # Everything except very high scores should be haiku now
        d = mr.route("negotiate")
        assert d.tier == "haiku"
        monkeypatch.delenv("ROUTER_HAIKU_THRESHOLD")
        importlib.reload(mr)
