"""Tests for warden/marketplace/kya.py — KYA (Know Your Agent) framework."""
import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_kya(tmp_path):
    """Each test gets its own SQLite DB and no Redis."""
    os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "kya_test.db")
    os.environ["REDIS_URL"] = "memory://"
    yield
    os.environ.pop("MARKETPLACE_DB_PATH", None)
    os.environ.pop("REDIS_URL", None)


class TestKYARegistration:
    def test_register_creates_pending_record(self):
        from warden.marketplace.kya import register_agent
        rec = register_agent("did:shadow:agent001", "tenant-A")
        assert rec.agent_id == "did:shadow:agent001"
        assert rec.owner_tenant_id == "tenant-A"
        assert rec.kya_status == "PENDING"
        assert rec.risk_score == 0.5

    def test_register_idempotent(self):
        from warden.marketplace.kya import get_kya_record, register_agent
        register_agent("did:shadow:agent002", "tenant-B")
        register_agent("did:shadow:agent002", "tenant-B")   # second call should not raise
        rec = get_kya_record("did:shadow:agent002")
        assert rec is not None
        assert rec.kya_status == "PENDING"

    def test_register_returns_correct_owner(self):
        from warden.marketplace.kya import register_agent
        rec = register_agent("did:shadow:agent003", "owner-X")
        assert rec.owner_tenant_id == "owner-X"

    def test_get_kya_record_unknown_returns_none(self):
        from warden.marketplace.kya import get_kya_record
        assert get_kya_record("did:shadow:nonexistent") is None

    def test_get_kya_status_unknown_returns_pending(self):
        from warden.marketplace.kya import get_kya_status
        assert get_kya_status("did:shadow:unknown") == "PENDING"


class TestKYAScreening:
    def test_screen_low_risk_auto_verifies(self):
        """Default ERS = none → risk 0.1 ≤ threshold 0.3 → VERIFIED."""
        from warden.marketplace.kya import register_agent, screen_agent
        register_agent("did:shadow:low-risk-agent", "tenant-safe")
        rec = screen_agent("did:shadow:low-risk-agent")
        assert rec.kya_status == "VERIFIED"
        assert rec.risk_score <= 0.3

    def test_screen_updates_status_in_db(self):
        from warden.marketplace.kya import get_kya_status, register_agent, screen_agent
        register_agent("did:shadow:update-test", "tenant-T")
        screen_agent("did:shadow:update-test")
        status = get_kya_status("did:shadow:update-test")
        assert status in ("VERIFIED", "FLAGGED", "PENDING")

    def test_screen_without_prior_register_is_failopen(self):
        """screen_agent without a prior register() call must not raise."""
        from warden.marketplace.kya import screen_agent
        rec = screen_agent("did:shadow:no-register")
        assert rec.kya_status in ("VERIFIED", "FLAGGED", "PENDING")

    def test_screen_sets_screened_at(self):
        from warden.marketplace.kya import register_agent, screen_agent
        register_agent("did:shadow:ts-agent", "tenant-TS")
        rec = screen_agent("did:shadow:ts-agent")
        assert rec.screened_at
        assert "T" in rec.screened_at   # ISO format

    def test_screen_respects_custom_threshold(self, monkeypatch):
        """Setting threshold to 0.0 forces all agents to FLAGGED."""
        monkeypatch.setenv("KYA_AUTO_VERIFY_SCORE_THRESHOLD", "0.0")
        import importlib

        import warden.marketplace.kya as kya_mod
        importlib.reload(kya_mod)
        kya_mod.register_agent("did:shadow:strict-agent", "tenant-S")
        rec = kya_mod.screen_agent("did:shadow:strict-agent")
        assert rec.kya_status == "FLAGGED"


class TestKYARevoke:
    def test_revoke_sets_revoked_status(self):
        from warden.marketplace.kya import get_kya_status, register_agent, revoke_agent
        register_agent("did:shadow:revoke-me", "tenant-R")
        revoke_agent("did:shadow:revoke-me", reason="test_revoke")
        status = get_kya_status("did:shadow:revoke-me")
        assert status == "REVOKED"

    def test_revoke_after_verify_overrides(self):
        from warden.marketplace.kya import (
            get_kya_status,
            register_agent,
            revoke_agent,
            screen_agent,
        )
        register_agent("did:shadow:verified-then-revoked", "tenant-V")
        screen_agent("did:shadow:verified-then-revoked")
        revoke_agent("did:shadow:verified-then-revoked", reason="security_incident")
        assert get_kya_status("did:shadow:verified-then-revoked") == "REVOKED"

    def test_revoke_nonexistent_is_failopen(self):
        from warden.marketplace.kya import revoke_agent
        revoke_agent("did:shadow:ghost-agent", reason="does_not_exist")   # must not raise


class TestKybEscalation:
    """FT-5: a FLAGGED agent escalates KYB onto its owning tenant.

    `importlib.reload()` is needed to force FLAGGED via the module-level
    `_AUTO_VERIFY_THRESHOLD` (bound at import time from the env var) — but a
    bare reload leaks that threshold into every later test sharing this
    process. `test_screen_respects_custom_threshold` above does exactly this
    with no cleanup, so `kya._AUTO_VERIFY_THRESHOLD` can already be stale by
    the time this class's tests start (the env var itself reverts via
    monkeypatch, but nothing re-reloads the module to match). This fixture
    reloads to the true default *before* each test (so this class doesn't
    inherit contamination) and again *after* (so it doesn't leave any).
    """

    @pytest.fixture(autouse=True)
    def _reset_kya_module(self):
        import importlib

        import warden.marketplace.kya as kya_mod
        original = os.environ.get("KYA_AUTO_VERIFY_SCORE_THRESHOLD")
        os.environ.pop("KYA_AUTO_VERIFY_SCORE_THRESHOLD", None)
        importlib.reload(kya_mod)  # start every test from the true default
        yield
        if original is None:
            os.environ.pop("KYA_AUTO_VERIFY_SCORE_THRESHOLD", None)
        else:
            os.environ["KYA_AUTO_VERIFY_SCORE_THRESHOLD"] = original
        importlib.reload(kya_mod)

    def test_flagged_agent_triggers_kyb(self, monkeypatch):
        import importlib

        import warden.marketplace.kya as kya

        calls: list[tuple] = []
        monkeypatch.setenv("KYA_AUTO_VERIFY_SCORE_THRESHOLD", "0.0")  # force FLAGGED
        importlib.reload(kya)
        monkeypatch.setattr(
            "warden.marketplace.kyb.require_kyb",
            lambda tenant_id, reason: calls.append((tenant_id, reason)),
        )

        kya.register_agent("did:shadow:flag-escalate", "tenant-escalate")
        rec = kya.screen_agent("did:shadow:flag-escalate")

        assert rec.kya_status == "FLAGGED"
        assert len(calls) == 1
        assert calls[0][0] == "tenant-escalate"
        assert "kya_flagged" in calls[0][1]

    def test_verified_agent_does_not_trigger_kyb(self, monkeypatch):
        import warden.marketplace.kya as kya

        calls: list[tuple] = []
        monkeypatch.setattr(
            "warden.marketplace.kyb.require_kyb",
            lambda tenant_id, reason: calls.append((tenant_id, reason)),
        )

        kya.register_agent("did:shadow:no-escalate", "tenant-clean")
        rec = kya.screen_agent("did:shadow:no-escalate")

        assert rec.kya_status == "VERIFIED"
        assert calls == []

    def test_kyb_failure_does_not_break_screening(self, monkeypatch):
        import importlib

        import warden.marketplace.kya as kya

        monkeypatch.setenv("KYA_AUTO_VERIFY_SCORE_THRESHOLD", "0.0")  # force FLAGGED
        importlib.reload(kya)

        def _boom(tenant_id, reason):
            raise RuntimeError("kyb db down")
        monkeypatch.setattr("warden.marketplace.kyb.require_kyb", _boom)

        kya.register_agent("did:shadow:kyb-down", "tenant-resilient")
        rec = kya.screen_agent("did:shadow:kyb-down")  # must not raise
        assert rec.kya_status == "FLAGGED"

    def test_no_owner_tenant_skips_escalation(self, monkeypatch):
        import importlib

        import warden.marketplace.kya as kya

        calls: list[tuple] = []
        monkeypatch.setenv("KYA_AUTO_VERIFY_SCORE_THRESHOLD", "0.0")  # force FLAGGED
        importlib.reload(kya)
        monkeypatch.setattr(
            "warden.marketplace.kyb.require_kyb",
            lambda tenant_id, reason: calls.append((tenant_id, reason)),
        )

        # No register_agent() call — screen_agent on an unknown agent has no owner.
        rec = kya.screen_agent("did:shadow:never-registered")
        assert rec.kya_status == "FLAGGED"
        assert calls == []


class TestKYAToDict:
    def test_to_dict_returns_dict(self):
        from warden.marketplace.kya import register_agent
        rec = register_agent("did:shadow:dict-test", "tenant-D")
        d = rec.to_dict()
        assert isinstance(d, dict)
        assert "agent_id" in d
        assert "kya_status" in d
        assert "risk_score" in d
        assert "flags" in d
