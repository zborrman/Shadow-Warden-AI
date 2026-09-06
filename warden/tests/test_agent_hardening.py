"""
warden/tests/test_agent_hardening.py
─────────────────────────────────────
Covers the PR-1..PR-5 SOVA hardening:
  • request-bound tenant_id (no model override)
  • read-only vs operator tool surface split
  • human-in-the-loop approval gate (fail-closed)
  • tier / feature gate on POST /agent/sova
  • LLM spend accounting
  • loop budget / deadline plumbing
"""
from __future__ import annotations

import os
import types

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


# ── Fake Anthropic client ────────────────────────────────────────────────────

class _Usage:
    def __init__(self, i=10, o=5):
        self.input_tokens = i
        self.output_tokens = o
        self.cache_read_input_tokens = 0


class _TextBlock:
    type = "text"
    def __init__(self, text):
        self.text = text


class _ToolBlock:
    type = "tool_use"
    def __init__(self, name, tool_input, _id="tu_1"):
        self.name = name
        self.input = tool_input
        self.id = _id


class _Resp:
    def __init__(self, stop_reason, content):
        self.stop_reason = stop_reason
        self.content = content
        self.usage = _Usage()


class _FakeMessages:
    def __init__(self, script):
        self._script = list(script)
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._script.pop(0)


class _FakeClient:
    def __init__(self, script):
        self.messages = _FakeMessages(script)


def _install_fake_anthropic(monkeypatch, script):
    holder = {}

    class _FakeAsyncAnthropic:
        def __init__(self, **_kw):
            holder["client"] = _FakeClient(script)
            self.messages = holder["client"].messages

    fake_mod = types.SimpleNamespace(AsyncAnthropic=_FakeAsyncAnthropic)
    monkeypatch.setitem(__import__("sys").modules, "anthropic", fake_mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    return holder


# ── Tool-surface split (PR-1) ────────────────────────────────────────────────

def test_read_surface_excludes_operator_tools():
    from warden.agent import tools as t
    read = t.handlers_for(operator=False)
    for name in t.OPERATOR_TOOLS:
        assert name not in read, f"operator tool {name} leaked into read surface"
    assert "get_stats" in read
    # tool defs match
    read_defs = {d["name"] for d in t.tools_for(operator=False)}
    assert read_defs.isdisjoint(t.OPERATOR_TOOLS)


def test_operator_surface_wraps_gated_tools():
    from warden.agent import tools as t
    ops = t.handlers_for(operator=True, auto_approve=False)
    assert ops["update_config"].__name__ == "gated_update_config"
    # read tools are passed through unwrapped
    assert ops["get_stats"] is t.TOOL_HANDLERS["get_stats"]


# ── Approval gate (PR-2) ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gated_tool_requires_approval(monkeypatch):
    from warden.agent import approval
    from warden.agent import tools as t

    store: dict = {}
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis(store))

    called = {"n": 0}

    async def _fake_update(**kw):
        called["n"] += 1
        return {"ok": True}

    gated = t._gated("update_config", _fake_update, auto_approve=False)
    out = await gated(tenant_id="acme", changes={"strict_mode": False})
    assert out["status"] == "approval_required"
    assert called["n"] == 0
    assert out["token"].startswith("appr-")

    # Approve it, then a second call with the token executes exactly once.
    assert approval.resolve(out["token"], True) is True
    out2 = await gated(tenant_id="acme", changes={"strict_mode": False}, approval_token=out["token"])
    assert out2 == {"ok": True}
    assert called["n"] == 1


@pytest.mark.asyncio
async def test_gated_tool_auto_approve_executes():
    from warden.agent import tools as t
    called = {"n": 0}

    async def _fake(**kw):
        called["n"] += 1
        return {"ok": True}

    gated = t._gated("rotate_community_key", _fake, auto_approve=True)
    out = await gated(tenant_id="acme", community_id="c1")
    assert out == {"ok": True}
    assert called["n"] == 1


def test_issue_fails_closed_without_redis(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "memory://")
    from warden.agent import approval
    with pytest.raises(approval.ApprovalStoreUnavailableError):
        approval.issue("update_config", "ctx", "acme")


class _MemRedis:
    def __init__(self, store):
        self._s = store
    def setex(self, k, _ttl, v):
        self._s[k] = v
    def get(self, k):
        return self._s.get(k)
    def delete(self, k):
        self._s.pop(k, None)
    def ping(self):
        return True
    def incr(self, k):
        self._s[k] = int(self._s.get(k, 0)) + 1
        return self._s[k]
    def expire(self, k, _ttl):
        return True


# ── tenant binding (PR-1) ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_id_is_request_bound(monkeypatch):
    script = [
        _Resp("tool_use", [_ToolBlock("get_stats", {"tenant_id": "VICTIM-TENANT"})]),
        _Resp("end_turn", [_TextBlock("done")]),
    ]
    _install_fake_anthropic(monkeypatch, script)

    seen = {}
    from warden.agent import tools as t

    async def _fake_get_stats(**kw):
        seen.update(kw)
        return {"ok": True}

    monkeypatch.setitem(t.TOOL_HANDLERS, "get_stats", _fake_get_stats)

    from warden.agent import memory, sova
    monkeypatch.setattr(memory, "load_history", lambda _s: [])
    monkeypatch.setattr(memory, "save_history", lambda *_a: None)

    out = await sova.run_query("show stats", tenant_id="real-tenant")
    assert seen.get("tenant_id") == "real-tenant"
    assert out["status"] == "ok"
    assert "get_stats" in out["tools_used"]


# ── accounting (PR-3) ────────────────────────────────────────────────────────

def test_accounting_never_undercounts_unknown_model():
    from warden.agent import accounting
    known = accounting.estimate_usd("claude-opus-4-6", {"input_tokens": 1_000_000, "output_tokens": 0})
    unknown = accounting.estimate_usd("some-future-model", {"input_tokens": 1_000_000, "output_tokens": 0})
    assert unknown >= known > 0


def test_record_llm_spend_writes_row(tmp_path, monkeypatch):
    db = str(tmp_path / "costs.db")
    monkeypatch.setenv("COST_ALLOC_DB_PATH", db)
    import importlib

    from warden.financial import cost_allocation
    importlib.reload(cost_allocation)
    from warden.agent import accounting
    importlib.reload(accounting)

    amount = accounting.record_llm_spend("acme", "sova", "claude-opus-4-6",
                                         {"input_tokens": 50_000, "output_tokens": 8_000})
    assert amount > 0
    summary = cost_allocation.get_monthly_summary("acme")
    assert summary["total_usd"] > 0
    assert summary["by_vendor"].get("anthropic", 0) > 0


# ── feature gate (PR-3) ──────────────────────────────────────────────────────

def test_sova_feature_key_present_all_tiers():
    from warden.billing.feature_gate import TIER_LIMITS
    for tier in ("starter", "individual", "community_business", "pro", "enterprise"):
        assert "sova_agent_enabled" in TIER_LIMITS[tier]
    assert TIER_LIMITS["starter"]["sova_agent_enabled"] is False
    assert TIER_LIMITS["community_business"]["sova_agent_enabled"] is True
    assert TIER_LIMITS["pro"]["sova_agent_enabled"] is True


def test_sova_endpoint_gated_for_starter():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.api.agent import router

    app = FastAPI()
    app.include_router(router)
    c = TestClient(app)
    r = c.post("/agent/sova", json={"query": "hi"})   # no tier header → starter
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "feature_gated"


def test_sova_endpoint_allowed_for_pro(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.api.agent import router

    app = FastAPI()
    app.include_router(router)
    c = TestClient(app)
    # Pro tier via header, no ANTHROPIC key → SOVA replies "offline" but 200.
    r = c.post("/agent/sova", json={"query": "hi"}, headers={"X-Tenant-Tier": "pro"})
    assert r.status_code == 200
    assert r.json()["status"] in ("offline", "ok")


def test_operator_mode_needs_pro():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.api.agent import router

    app = FastAPI()
    app.include_router(router)
    c = TestClient(app)
    r = c.post("/agent/sova", json={"query": "hi", "operator_mode": True},
               headers={"X-Tenant-Tier": "community_business"})
    assert r.status_code == 403
