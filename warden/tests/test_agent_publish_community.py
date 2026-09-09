"""
warden/tests/test_agent_publish_community.py
─────────────────────────────────────────────
PR-9 — publish_to_community, previously a hard-coded "not implemented" stub.

It now stores the incident as a PUBLIC community entity and indexes it in the
SEP UECIID feed. It stays approval-gated: SOVA's loop reaches it only through
traced_dispatch after a human resolves the token.
"""
from __future__ import annotations

import base64
import json
import os

import httpx
import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


def _status_error(code: int, detail: str = "nope") -> httpx.HTTPStatusError:
    req = httpx.Request("POST", "http://localhost:8001/x")
    resp = httpx.Response(code, json={"detail": detail}, request=req)
    return httpx.HTTPStatusError("err", request=req, response=resp)


# ── gating ───────────────────────────────────────────────────────────────────

def test_publish_to_community_is_approval_gated():
    from warden.agent import tools as t
    assert "publish_to_community" in t._approval.GATED_ACTIONS
    assert "publish_to_community" in t.OPERATOR_TOOLS
    assert "publish_to_community" not in {d["name"] for d in t.tools_for(operator=False)}


@pytest.mark.asyncio
async def test_dispatch_returns_token_not_execution(monkeypatch):
    from warden.agent import approval
    from warden.agent import tools as t
    from warden.tests.test_agent_hardening import _MemRedis
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis({}))

    called = {"n": 0}

    async def _fake(**_kw):
        called["n"] += 1
        return {"published": True}

    monkeypatch.setitem(t.TOOL_HANDLERS, "publish_to_community", _fake)
    out = await t.traced_dispatch("publish_to_community", {
        "tenant_id": "acme", "verdict": "BLOCK", "rule_id": "jb_v3",
        "risk_level": "HIGH", "evidence_summary": "clean",
    })
    assert out["status"] == "approval_required"
    assert called["n"] == 0


# ── behaviour ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_happy_path_stores_and_indexes(monkeypatch):
    from warden.agent import tools as t
    posts: list[tuple[str, dict]] = []

    async def _fake_post(path, body, tenant="default"):
        posts.append((path, body))
        if path == "/filter":
            return {"secrets_found": []}
        if path == "/communities/c-1/entities":
            return {"entity_id": "e-9", "byte_size": 123}
        if path == "/sep/register":
            return {"ueciid": "SEP-0ABC", "entity_id": "e-9"}
        raise AssertionError(path)

    monkeypatch.setattr(t, "_post", _fake_post)
    out = await t.publish_to_community(
        verdict="BLOCK", rule_id="jb_v3", risk_level="HIGH",
        evidence_summary="prompt tried to override the system role",
        tenant_id="acme", community_id="c-1",
    )
    assert out == {
        "published": True, "indexed": True, "ueciid": "SEP-0ABC",
        "entity_id": "e-9", "community_id": "c-1",
        "display_name": "[HIGH] jb_v3 — BLOCK",
    }
    # the entity payload is base64 JSON carrying the incident, not raw text
    entity_body = dict(posts)["/communities/c-1/entities"]
    assert entity_body["clearance"] == "PUBLIC"
    record = json.loads(base64.b64decode(entity_body["content_b64"]))
    assert record["rule_id"] == "jb_v3"
    assert record["published_by"] == t._SOVA_SENDER_MID
    assert dict(posts)["/sep/register"]["byte_size"] == 123


@pytest.mark.asyncio
async def test_pii_in_evidence_aborts_before_any_write(monkeypatch):
    from warden.agent import tools as t
    posts: list[str] = []

    async def _fake_post(path, body, tenant="default"):
        posts.append(path)
        if path == "/filter":
            return {"secrets_found": ["AWS_KEY"]}
        raise AssertionError("must not write after PII detected")

    monkeypatch.setattr(t, "_post", _fake_post)
    out = await t.publish_to_community(
        verdict="BLOCK", rule_id="r", risk_level="HIGH",
        evidence_summary="key AKIA...", tenant_id="acme", community_id="c-1",
    )
    assert out["published"] is False
    assert out["secrets_found"] == ["AWS_KEY"]
    assert posts == ["/filter"]


@pytest.mark.asyncio
async def test_ambiguous_community_is_refused(monkeypatch):
    from warden.agent import tools as t

    async def _fake_post(path, body, tenant="default"):
        return {"secrets_found": []}

    async def _fake_get(path, tenant="default", params=None):
        return [
            {"community_id": "c-1", "status": "ACTIVE"},
            {"community_id": "c-2", "status": "ACTIVE"},
        ]

    monkeypatch.setattr(t, "_post", _fake_post)
    monkeypatch.setattr(t, "_get", _fake_get)
    out = await t.publish_to_community(
        verdict="BLOCK", rule_id="r", risk_level="HIGH",
        evidence_summary="clean", tenant_id="acme",
    )
    assert out["published"] is False
    assert "ambiguous" in out["error"]


@pytest.mark.asyncio
async def test_single_community_is_auto_resolved(monkeypatch):
    from warden.agent import tools as t

    async def _fake_post(path, body, tenant="default"):
        if path == "/filter":
            return {"secrets_found": []}
        if path == "/communities/c-only/entities":
            return {"entity_id": "e-1", "byte_size": 10}
        if path == "/sep/register":
            return {"ueciid": "SEP-1"}
        raise AssertionError(path)

    async def _fake_get(path, tenant="default", params=None):
        return [{"community_id": "c-only", "status": "ACTIVE"},
                {"community_id": "c-old", "status": "REMOVED"}]

    monkeypatch.setattr(t, "_post", _fake_post)
    monkeypatch.setattr(t, "_get", _fake_get)
    out = await t.publish_to_community(
        verdict="ALLOW", rule_id="r", risk_level="LOW",
        evidence_summary="clean", tenant_id="acme",
    )
    assert out["published"] is True
    assert out["community_id"] == "c-only"


@pytest.mark.asyncio
async def test_tier_gate_surfaces_as_readable_error(monkeypatch):
    from warden.agent import tools as t

    async def _fake_post(path, body, tenant="default"):
        if path == "/filter":
            return {"secrets_found": []}
        raise _status_error(403)

    monkeypatch.setattr(t, "_post", _fake_post)
    out = await t.publish_to_community(
        verdict="BLOCK", rule_id="r", risk_level="HIGH",
        evidence_summary="clean", tenant_id="acme", community_id="c-1",
    )
    assert out["published"] is False
    assert "Community Business" in out["error"]


@pytest.mark.asyncio
async def test_index_failure_reports_partial_write(monkeypatch):
    from warden.agent import tools as t

    async def _fake_post(path, body, tenant="default"):
        if path == "/filter":
            return {"secrets_found": []}
        if path.endswith("/entities"):
            return {"entity_id": "e-7", "byte_size": 5}
        raise _status_error(500, "sep down")

    monkeypatch.setattr(t, "_post", _fake_post)
    out = await t.publish_to_community(
        verdict="BLOCK", rule_id="r", risk_level="HIGH",
        evidence_summary="clean", tenant_id="acme", community_id="c-1",
    )
    assert out["published"] is True
    assert out["indexed"] is False
    assert out["entity_id"] == "e-7"
