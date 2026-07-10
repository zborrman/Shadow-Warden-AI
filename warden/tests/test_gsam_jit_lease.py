"""
GSAM Hermes JIT credential lease tests.

Covers: no-secret issuance, single-use redemption, rejection of
expired/agent-mismatch/revoked/unknown leases, and fail-CLOSED signing-key
resolution.

Uses a per-test tmp SQLite DB (VAULT_MASTER_KEY is set in conftest so
resolve_key derives a key; the fail-CLOSED path is exercised by monkeypatching
resolve_key to raise).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from warden.gsam import jit_lease as jl
from warden.secret_keys import InsecureKeyError


@pytest.fixture
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(jl.settings, "gsam_db_path", str(tmp_path / "gsam.db"))
    monkeypatch.setattr(jl.settings, "gsam_enabled", True)
    yield


def test_issue_returns_no_secret(_db):
    lease = jl.issue_lease("agent-1", "tenant-x", "github:repo:read")
    assert lease["status"] == "ACTIVE"
    assert lease["agent_id"] == "agent-1"
    assert "credential" not in lease
    assert "secret" not in lease
    assert "hmac_sig" not in lease  # signature never leaves the DB


def test_redeem_once_then_single_use(_db):
    lease = jl.issue_lease("agent-1", "t", "scope-a")
    out = jl.redeem_lease(lease["lease_id"], "agent-1")
    assert out["scope"] == "scope-a"
    assert out["credential"].startswith("gsam_cap_")
    # Second redeem is rejected — single use.
    with pytest.raises(jl.LeaseError, match="already used"):
        jl.redeem_lease(lease["lease_id"], "agent-1")
    # Metadata reflects consumption.
    meta = jl.get_lease(lease["lease_id"])
    assert meta["status"] == "USED" and meta["used_at"]


def test_agent_mismatch_rejected(_db):
    lease = jl.issue_lease("agent-1", "t", "scope-a")
    with pytest.raises(jl.LeaseError, match="agent mismatch"):
        jl.redeem_lease(lease["lease_id"], "attacker")


def test_unknown_lease_rejected(_db):
    with pytest.raises(jl.LeaseError, match="not found"):
        jl.redeem_lease("gsam_lease_deadbeef", "agent-1")


def test_revoked_lease_rejected(_db):
    lease = jl.issue_lease("agent-1", "t", "scope-a")
    assert jl.revoke_lease(lease["lease_id"]) is True
    with pytest.raises(jl.LeaseError, match="revoked"):
        jl.redeem_lease(lease["lease_id"], "agent-1")


def test_expired_lease_rejected(_db):
    lease = jl.issue_lease("agent-1", "t", "scope-a", ttl_s=1)
    # Force expiry by rewriting expires_at in the past (bypasses waiting).
    with jl._conn() as con:
        past = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
        # Re-sign so only expiry (not the signature) is what fails.
        sig = jl._sign(lease["lease_id"], "agent-1", "t", "scope-a", past)
        con.execute(
            "UPDATE gsam_leases SET expires_at=?, hmac_sig=? WHERE lease_id=?",
            (past, sig, lease["lease_id"]),
        )
        con.commit()
    with pytest.raises(jl.LeaseError, match="expired"):
        jl.redeem_lease(lease["lease_id"], "agent-1")


def test_tampered_signature_rejected(_db):
    lease = jl.issue_lease("agent-1", "t", "scope-a")
    with jl._conn() as con:
        con.execute(
            "UPDATE gsam_leases SET scope='escalated:admin' WHERE lease_id=?",
            (lease["lease_id"],),
        )
        con.commit()
    # scope changed but signature was over the original scope → invalid.
    with pytest.raises(jl.LeaseError, match="signature invalid"):
        jl.redeem_lease(lease["lease_id"], "agent-1")


def test_fail_closed_without_key(_db, monkeypatch):
    def _no_key(*a, **k):
        raise InsecureKeyError("no key")

    monkeypatch.setattr(jl, "resolve_key", _no_key)
    with pytest.raises(InsecureKeyError):
        jl.issue_lease("agent-1", "t", "scope-a")


def test_disabled_gsam_blocks_issue(_db, monkeypatch):
    monkeypatch.setattr(jl.settings, "gsam_enabled", False)
    with pytest.raises(jl.LeaseError, match="disabled"):
        jl.issue_lease("agent-1", "t", "scope-a")
