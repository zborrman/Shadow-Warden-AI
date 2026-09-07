"""
warden/tests/test_agent_hardening.py
─────────────────────────────────────
SOVA hardening (v2) — tenant binding, tier gate, and the human-in-the-loop
approval gate on state-changing tools.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


class _MemRedis:
    """Minimal in-memory stand-in for the approval store."""

    def __init__(self, store: dict) -> None:
        self._s = store

    def setex(self, k, _ttl, v):
        self._s[k] = v

    def set(self, k, v, nx=False, ex=None):
        if nx and k in self._s:
            return None
        self._s[k] = v
        return True

    def get(self, k):
        return self._s.get(k)

    def delete(self, k):
        self._s.pop(k, None)

    def ping(self):
        return True


# ── Tool-surface split ───────────────────────────────────────────────────────

def test_read_surface_excludes_operator_tools():
    from warden.agent import tools as t
    read_defs = {d["name"] for d in t.tools_for(operator=False)}
    assert read_defs.isdisjoint(t.OPERATOR_TOOLS)
    assert "get_stats" in read_defs
    assert t.OPERATOR_TOOLS, "no operator tools registered"


def test_operator_surface_includes_them():
    from warden.agent import tools as t
    op_defs = {d["name"] for d in t.tools_for(operator=True)}
    assert t.OPERATOR_TOOLS & op_defs == t.OPERATOR_TOOLS & {d["name"] for d in t.TOOLS}


def test_known_mutators_are_gated():
    from warden.agent import tools as t
    for name in ("update_config", "rotate_community_key", "revoke_agent", "block_ip_range"):
        assert name in t.OPERATOR_TOOLS, f"{name} is not approval-gated"


# ── Approval gate ────────────────────────────────────────────────────────────

def test_approval_check_issues_token_and_blocks(monkeypatch):
    from warden.agent import approval
    from warden.agent import tools as t
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis({}))

    out = t._approval_check("update_config", {"changes": {"strict_mode": False}}, "acme")
    assert out is not None
    assert out["status"] == "approval_required"
    assert out["token"].startswith("appr-")


def test_approval_check_lets_approved_token_through(monkeypatch):
    from warden.agent import approval
    from warden.agent import tools as t
    store: dict = {}
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis(store))

    issued = t._approval_check("update_config", {"changes": {}}, "acme")
    tok = issued["token"]
    assert approval.resolve(tok, True) is True

    inp = {"changes": {}, "approval_token": tok}
    assert t._approval_check("update_config", inp, "acme") is None   # proceeds
    assert "approval_token" not in inp                               # popped before dispatch


def test_issue_fails_closed_without_redis(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "memory://")
    from warden.agent import approval
    with pytest.raises(approval.ApprovalStoreUnavailableError):
        approval.issue("update_config", "ctx", "acme")


def test_try_consume_is_single_use(monkeypatch):
    from warden.agent import approval
    store: dict = {}
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis(store))
    tok = approval.issue("update_config", "ctx", "acme", params={"changes": {}})
    approval.resolve(tok, True)
    assert approval.try_consume(tok) is True
    assert approval.try_consume(tok) is False
    assert approval.try_consume(tok) is False


@pytest.mark.asyncio
async def test_gated_tool_does_not_execute(monkeypatch):
    """traced_dispatch must NOT reach the handler for an ungated mutator."""
    from warden.agent import approval
    from warden.agent import tools as t
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis({}))

    called = {"n": 0}

    async def _fake(**_kw):
        called["n"] += 1
        return {"ok": True}

    monkeypatch.setitem(t.TOOL_HANDLERS, "update_config", _fake)
    out = await t.traced_dispatch("update_config", {"tenant_id": "acme", "changes": {}})
    assert isinstance(out, dict)
    assert out.get("status") in ("approval_required", "error")
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_auto_approve_bypasses_gate(monkeypatch):
    """Trusted scheduled callers (approval_gate=False) execute directly."""
    from warden.agent import tools as t
    called = {"n": 0}

    async def _fake(**_kw):
        called["n"] += 1
        return {"ok": True}

    monkeypatch.setitem(t.TOOL_HANDLERS, "update_config", _fake)
    out = await t.traced_dispatch(
        "update_config", {"tenant_id": "acme", "changes": {}}, approval_gate=False)
    assert called["n"] == 1
    assert out == {"ok": True}


# ── Tier gate ────────────────────────────────────────────────────────────────

def test_sova_feature_key_present_all_tiers():
    from warden.billing.feature_gate import TIER_LIMITS
    for tier in ("starter", "individual", "community_business", "pro", "enterprise"):
        assert "sova_agent_enabled" in TIER_LIMITS[tier]
    assert TIER_LIMITS["starter"]["sova_agent_enabled"] is False
    assert TIER_LIMITS["community_business"]["sova_agent_enabled"] is True
    assert TIER_LIMITS["pro"]["sova_agent_enabled"] is True


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.api.agent import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_sova_endpoint_gated_for_starter():
    r = _client().post("/agent/sova", json={"query": "hi"})   # no tier header → starter
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "feature_gated"


def test_sova_endpoint_allowed_for_pro():
    r = _client().post("/agent/sova", json={"query": "hi"}, headers={"X-Tenant-Tier": "pro"})
    assert r.status_code == 200


def test_operator_mode_needs_pro():
    r = _client().post("/agent/sova", json={"query": "hi", "operator_mode": True},
                       headers={"X-Tenant-Tier": "community_business"})
    assert r.status_code == 403


def test_master_request_rejects_auto_approve():
    from warden.api.agent import MasterRequest
    assert "auto_approve" not in MasterRequest.model_fields
