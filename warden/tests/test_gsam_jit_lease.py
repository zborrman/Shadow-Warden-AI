"""GSAM PR 5 — JIT credential lease (GSAM-05).

Fail-CLOSED credential path: no signing secret → 503. Full lifecycle + replay /
expiry / tamper rejection, and the invariant that the raw secret never appears
in any response body.
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.gsam import jit_lease as _jl

_SECRET = "unit-test-lease-secret-DO-NOT-LEAK"


@pytest.fixture()
def lease_env(tmp_path, monkeypatch):
    db = tmp_path / "gsam.db"
    monkeypatch.setattr(settings, "gsam_db_path", str(db))
    monkeypatch.setattr(settings, "gsam_lease_secret", _SECRET)
    monkeypatch.setattr(settings, "gsam_lease_ttl_s", 900)
    monkeypatch.setattr(settings, "slack_webhook_url", "")  # no Slack in tests
    _jl._mem_tokens.clear()
    yield str(db)
    _jl._mem_tokens.clear()


# ── happy-path lifecycle ─────────────────────────────────────────────────────────

def test_full_lifecycle(lease_env) -> None:
    req = _jl.request_lease("agent-1", "t-1", "read:catalog")
    assert req.status == "PENDING"
    assert req.lease_id.startswith("lease-")

    approved = _jl.approve(req.approval_token)
    assert approved is not None
    assert approved["status"] == "APPROVED"
    sig = approved["signature"]

    redeemed = _jl.redeem(req.lease_id, sig)
    assert redeemed["redeemed"] is True
    assert redeemed["scope"] == "read:catalog"


def test_status_transitions(lease_env) -> None:
    req = _jl.request_lease("agent-2", "t-1", "scope:x")
    assert _jl.get_status(req.lease_id)["status"] == "PENDING"
    approved = _jl.approve(req.approval_token)
    assert _jl.get_status(req.lease_id)["status"] == "APPROVED"
    _jl.redeem(req.lease_id, approved["signature"])
    st = _jl.get_status(req.lease_id)
    assert st["status"] == "REDEEMED"
    assert st["redeemed"] is True


# ── single-use / replay ──────────────────────────────────────────────────────────

def test_redeem_is_single_use(lease_env) -> None:
    req = _jl.request_lease("agent-3", "t-1", "scope:y")
    sig = _jl.approve(req.approval_token)["signature"]
    assert _jl.redeem(req.lease_id, sig)["redeemed"] is True
    replay = _jl.redeem(req.lease_id, sig)
    assert replay["redeemed"] is False
    assert replay["reason"] == "already_used"


def test_approval_token_single_use(lease_env) -> None:
    req = _jl.request_lease("agent-4", "t-1", "scope:z")
    assert _jl.approve(req.approval_token) is not None
    # Token consumed on first approve
    assert _jl.approve(req.approval_token) is None


# ── tamper / expiry / unknown ────────────────────────────────────────────────────

def test_tampered_signature_rejected(lease_env) -> None:
    req = _jl.request_lease("agent-5", "t-1", "scope:a")
    _jl.approve(req.approval_token)
    bad = _jl.redeem(req.lease_id, "deadbeef" * 8)
    assert bad["redeemed"] is False
    assert bad["reason"] == "bad_signature"


def test_expired_lease_rejected(lease_env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "gsam_lease_ttl_s", -1)  # already expired on approve
    req = _jl.request_lease("agent-6", "t-1", "scope:b")
    sig = _jl.approve(req.approval_token)["signature"]
    res = _jl.redeem(req.lease_id, sig)
    assert res["redeemed"] is False
    assert res["reason"] == "expired"


def test_redeem_unknown_lease(lease_env) -> None:
    res = _jl.redeem("lease-does-not-exist", "x")
    assert res["redeemed"] is False
    assert res["reason"] == "not_found"


def test_redeem_before_approval(lease_env) -> None:
    req = _jl.request_lease("agent-7", "t-1", "scope:c")
    res = _jl.redeem(req.lease_id, "anything")
    assert res["redeemed"] is False
    assert res["reason"] == "not_approved"


def test_deny_blocks_approval(lease_env) -> None:
    req = _jl.request_lease("agent-8", "t-1", "scope:d")
    assert _jl.deny(req.approval_token) is True
    # Token consumed by deny → approve can't resolve it
    assert _jl.approve(req.approval_token) is None
    assert _jl.get_status(req.lease_id)["status"] == "DENIED"


# ── fail-CLOSED on empty secret ──────────────────────────────────────────────────

def test_request_fail_closed_without_secret(lease_env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "gsam_lease_secret", "")
    with pytest.raises(_jl.LeaseUnavailableError):
        _jl.request_lease("agent-9", "t-1", "scope:e")


def test_redeem_fail_closed_without_secret(lease_env, monkeypatch) -> None:
    req = _jl.request_lease("agent-10", "t-1", "scope:f")
    sig = _jl.approve(req.approval_token)["signature"]
    monkeypatch.setattr(settings, "gsam_lease_secret", "")
    with pytest.raises(_jl.LeaseUnavailableError):
        _jl.redeem(req.lease_id, sig)


# ── secret never leaks ───────────────────────────────────────────────────────────

def test_secret_never_in_responses(lease_env) -> None:
    req = _jl.request_lease("agent-11", "t-1", "scope:g")
    approved = _jl.approve(req.approval_token)
    status = _jl.get_status(req.lease_id)
    for payload in (str(req), str(approved), str(status)):
        assert _SECRET not in payload


# ── REST surface ─────────────────────────────────────────────────────────────────

def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.gsam.api import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


_PRO = {"X-Tenant-Tier": "pro"}


def test_api_lease_request_hides_token(lease_env) -> None:
    resp = _client().post(
        "/gsam/lease/request",
        json={"agent_id": "api-agent", "tenant_id": "t-1", "scope": "read:x"},
        headers=_PRO,
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "PENDING"
    assert "approval_token" not in data
    assert _SECRET not in resp.text


def test_api_request_503_without_secret(lease_env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "gsam_lease_secret", "")
    resp = _client().post(
        "/gsam/lease/request",
        json={"agent_id": "api-agent", "scope": "read:x"},
        headers=_PRO,
    )
    assert resp.status_code == 503


def test_api_approve_requires_admin(lease_env, monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_KEY", "admin-xyz")
    req = _jl.request_lease("api-agent-2", "t-1", "read:y")
    client = _client()

    bad = client.post(f"/gsam/lease/approve/{req.approval_token}", headers=_PRO)
    assert bad.status_code == 403

    ok = client.post(
        f"/gsam/lease/approve/{req.approval_token}",
        headers={**_PRO, "X-Admin-Key": "admin-xyz"},
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "APPROVED"
    assert "signature" in ok.json()
