"""
Anonymous subversion of security controls (2026-07-29).

Follow-on to the write-method audit in test_write_method_audit.py. That sweep
sent empty bodies, so 78 routes answered 422 — validation rejecting the payload
before the handler ran, which proves nothing either way. Re-probing those routes
with a MINIMAL VALID body synthesised from each route's own OpenAPI schema found
26 that execute fully for an anonymous caller.

This file pins the four that let an unauthenticated caller weaken the product's
own protection. The money and tenant-data writes from the same sweep are
separate follow-ups.

  POST /api/settings                  writes semantic_threshold into the RUNNING
                                      SemanticGuard — the /api/config hole of
                                      PR #244, one router along
  POST /marketplace/autonomy/{id}     sets the autonomy level authorize_payment()
                                      consults; L3 + a high cap disables the
                                      approval gate on money movement
  POST /sep/federation/ingest         verdicts feed get_score_boost() and the
                                      agent deny list — detection poisoning
  POST /auth/fido/register/*          enrols a passkey against any tenant_id

The FIDO finding is two defects. The endpoints were open, and the verifier itself
failed OPEN in three places: an unparseable credential, a missing py_webauthn,
and — worst — an assertion naming a credential that was never registered.
"""

from __future__ import annotations

import uuid

import pytest


@pytest.fixture
def _client(monkeypatch, tmp_path):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "control-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    monkeypatch.setenv("FIDO_DB_PATH", str(tmp_path / "fido.db"))

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


KEY = {"X-API-Key": "control-key"}

# (verb, path, body) — each ran to completion anonymously before this change.
GATED = [
    ("post", "/api/settings", {"changes": {}}),
    ("get", "/api/settings", None),
    ("post", "/marketplace/autonomy/agent-1", {"level": 3}),
    ("delete", "/marketplace/autonomy/agent-1", None),
    (
        "post",
        "/sep/federation/ingest",
        {"community_id": "c", "threat_hash": "h", "verdict": "BLOCK", "score": 1.0},
    ),
    ("post", "/auth/fido/register/begin", {"tenant_id": "victim"}),
    ("post", "/auth/fido/register/complete", {"tenant_id": "victim", "credential": {}}),
]


@pytest.mark.parametrize("verb,path,body", GATED)
def test_security_control_writes_require_auth(_client, verb, path, body):
    kwargs = {"json": body} if body is not None else {}
    assert getattr(_client, verb)(path, **kwargs).status_code == 401, (
        f"{verb.upper()} {path} executed without credentials."
    )


def test_detector_cannot_be_disabled_anonymously(_client):
    """
    The concrete attack: lift semantic_threshold toward 1.0 so the ML jailbreak
    detector stops flagging. /api/settings applies it to the live guard object.
    """
    resp = _client.post(
        "/api/settings", json={"changes": {"semantic_threshold": 0.99}}
    )
    assert resp.status_code == 401


def test_autonomy_l3_cannot_be_granted_anonymously(_client):
    """L3 with a high cap removes the human from the loop on agent spending."""
    resp = _client.post(
        "/marketplace/autonomy/victim-agent",
        json={"level": 3, "max_spend_usd": 1e6, "require_approval_above_usd": 1e6},
    )
    assert resp.status_code == 401


def test_autonomy_attribution_comes_from_the_key_not_a_header(_client):
    """
    `created_by` is attribution on a security policy. It used to fall back to a
    caller-supplied X-Tenant-ID header, which the caller could set to anything.
    """
    resp = _client.post(
        "/marketplace/autonomy/agent-attrib",
        json={"level": 1},
        headers={**KEY, "X-Tenant-ID": "spoofed-tenant"},
    )
    assert resp.status_code == 201
    assert resp.json().get("created_by") != "spoofed-tenant"


def test_authenticated_callers_still_work(_client):
    assert _client.post("/api/settings", json={"changes": {}}, headers=KEY).status_code == 200
    assert (
        _client.post(
            "/sep/federation/ingest",
            json={"community_id": "c", "threat_hash": "h", "verdict": "LOW", "score": 0.1},
            headers=KEY,
        ).status_code
        == 200
    )


# ── FIDO2: the verifier itself ────────────────────────────────────────────────


def test_passkey_login_stays_open(_client):
    """
    A caller proving possession of a passkey has no API key yet — that is the
    point of the flow. Gating this would make the feature unusable.
    """
    assert (
        _client.post("/auth/fido/authenticate/begin", json={"tenant_id": "t"}).status_code
        == 200
    )


def test_assertion_for_unregistered_credential_is_rejected(_client):
    """
    The sharpest edge: verify_authentication returned verified=True when the
    tenant had no such credential, so any tenant_id authenticated with any
    assertion and no enrolment at all.
    """
    _client.post("/auth/fido/authenticate/begin", json={"tenant_id": "victim"})
    resp = _client.post(
        "/auth/fido/authenticate/complete",
        json={"tenant_id": "victim", "assertion": {}},
    )
    assert resp.status_code == 401


def test_unverifiable_credential_is_not_enrolled(_client):
    """
    An unparseable credential fell through to the scaffolding path and was stored
    as a real passkey. An auth primitive must fail closed.
    """
    # Unique tenant: warden/auth/fido.py snapshots _DB_PATH at import, so the
    # FIDO_DB_PATH fixture does not really repoint the DB and rows persist.
    tenant = f"victim-{uuid.uuid4().hex[:8]}"
    _client.post("/auth/fido/register/begin", json={"tenant_id": tenant}, headers=KEY)
    resp = _client.post(
        "/auth/fido/register/complete",
        json={"tenant_id": tenant, "credential": {}},
        headers=KEY,
    )
    assert resp.status_code == 400
    assert "webauthn_unavailable" in str(resp.json())

    listed = _client.get(
        "/auth/fido/credentials", params={"tenant_id": tenant}, headers=KEY
    )
    assert listed.json()["count"] == 0, "an unverified credential was persisted"


def test_stub_is_never_honoured_in_production(monkeypatch):
    """
    The scaffolding path is opt-in for local work and must stay off in prod
    regardless of the flag. Read per call — an import-time snapshot would capture
    the value before the environment is populated.
    """
    from warden.auth import fido

    monkeypatch.setenv("FIDO_ALLOW_STUB", "true")

    monkeypatch.setattr(type(fido.settings), "is_prod", property(lambda self: True))
    assert fido._stub_allowed() is False

    monkeypatch.setattr(type(fido.settings), "is_prod", property(lambda self: False))
    assert fido._stub_allowed() is True

    monkeypatch.setenv("FIDO_ALLOW_STUB", "false")
    assert fido._stub_allowed() is False
