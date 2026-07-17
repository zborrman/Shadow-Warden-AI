"""
Unit tests for the SOVA modernization helpers (phases 1-4).

All pure / offline — no live Anthropic API, no Redis, no pgvector required.
Covers: tools prompt-cache helper, cache-safe tool profiles, adaptive model
routing, semantic-memory fail-open, and the streaming offline path.
"""
from __future__ import annotations

import asyncio

import pytest

from warden.agent import sova
from warden.agent import tools as _tools

_CORE = {"get_health", "get_stats", "filter_request"}


class TestCachedTools:
    def test_cache_control_on_last_only(self):
        cached = sova._cached_tools(_tools.TOOLS)
        assert cached[-1]["cache_control"] == {"type": "ephemeral"}
        assert "cache_control" not in cached[0]

    def test_does_not_mutate_shared_list(self):
        sova._cached_tools(_tools.TOOLS)
        assert "cache_control" not in _tools.TOOLS[-1]

    def test_empty_input(self):
        assert sova._cached_tools([]) == []


class TestSelectTools:
    def test_full_offers_every_tool(self):
        assert len(sova._select_tools(_tools.TOOLS, "full")) == len(_tools.TOOLS)

    def test_unknown_profile_offers_every_tool(self):
        assert len(sova._select_tools(_tools.TOOLS, "does-not-exist")) == len(_tools.TOOLS)

    @pytest.mark.parametrize("profile", ["ops", "community", "compliance"])
    def test_profile_is_proper_subset_with_core(self, profile):
        sub = sova._select_tools(_tools.TOOLS, profile)
        names = {t["name"] for t in sub}
        assert 0 < len(sub) < len(_tools.TOOLS)
        assert names >= _CORE
        assert sub[-1]["cache_control"] == {"type": "ephemeral"}

    def test_profile_preserves_tools_order(self):
        sub = sova._select_tools(_tools.TOOLS, "ops")
        names = [t["name"] for t in sub]
        allowed = set(names)
        expected = [t["name"] for t in _tools.TOOLS if t["name"] in allowed]
        assert names == expected


class TestRouteGeneric:
    def test_simple_query_routes_sonnet(self):
        _, tier, _ = sova._route_generic("list all monitors", "NONE")
        assert tier == "sonnet"

    def test_high_maestro_risk_forces_opus(self):
        _, tier, _ = sova._route_generic("quick stats", "HIGH")
        assert tier == "opus"

    def test_force_model_override(self, monkeypatch):
        monkeypatch.setenv("ROUTER_FORCE_MODEL", "sonnet")
        _, tier, _ = sova._route_generic("investigate breach root cause now", "HIGH")
        assert tier == "sonnet"


class TestResolveModel:
    def test_marketplace_dispute_uses_m2m_router(self):
        _, tier, _ = sova._resolve_model("raise a dispute", "raise_dispute", "NONE", 0)
        assert tier == "opus"

    def test_generic_query_uses_adaptive_routing(self):
        _, tier, _ = sova._resolve_model("show health", None, "NONE", 0)
        assert tier in ("sonnet", "opus")

    def test_adaptive_disabled_falls_back_to_opus(self, monkeypatch):
        monkeypatch.setattr(sova, "_GENERIC_ROUTING", False)
        model, tier, score = sova._resolve_model("show health", None, "NONE", 0)
        assert tier == "opus"
        assert score == 1.0
        assert model == sova._MODEL


class TestSemanticMemoryFailOpen:
    def test_recall_empty_without_pgvector(self):
        assert sova._recall_context("anything at all") == ""

    def test_store_is_noop_without_pgvector(self):
        sova._store_memory("some-session", "an assistant answer")


class TestStreamOffline:
    def test_stream_yields_error_when_offline(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        async def _collect():
            return [event async for event in sova.stream_query("hello")]

        events = asyncio.run(_collect())
        assert events
        assert events[0]["type"] == "error"
