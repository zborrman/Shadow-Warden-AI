"""
warden/tests/test_onboarding.py
Tests for AI-assisted onboarding wizard (ONB-01).
"""
from __future__ import annotations

import os
import uuid

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")


from warden.integrations.onboarding import OnboardingWizard, _load


def _wizard() -> OnboardingWizard:
    return OnboardingWizard()


class TestStartOnboarding:
    def test_returns_onboarding_id(self):
        result = _wizard().start_onboarding("tenant-x")
        assert result["onboarding_id"]
        assert len(result["onboarding_id"]) == 36  # UUID4

    def test_initial_step_is_community(self):
        result = _wizard().start_onboarding("tenant-y")
        assert result["current_step"] == "community"

    def test_stores_state_in_fallback(self):
        result = _wizard().start_onboarding("tenant-z")
        oid = result["onboarding_id"]
        state = _load(oid)
        assert state is not None
        assert state["tenant_id"] == "tenant-z"


class TestGetStatus:
    def test_returns_progress_info(self):
        oid = _wizard().start_onboarding("t1")["onboarding_id"]
        status = _wizard().get_status(oid)
        assert status["current_step"] == "community"
        assert status["progress"]["total"] == 5
        assert status["progress"]["done"] == 0

    def test_missing_session_returns_error(self):
        status = _wizard().get_status("nonexistent-id-" + str(uuid.uuid4()))
        assert "error" in status


class TestExecuteStep:
    def test_community_step_advances_to_members(self):
        oid = _wizard().start_onboarding("t2")["onboarding_id"]
        result = _wizard().execute_step(oid, "community", {"name": "Test Corp"})
        assert result["ok"] is True
        assert result["next_step"] == "members"

    def test_community_step_requires_name(self):
        oid = _wizard().start_onboarding("t3")["onboarding_id"]
        result = _wizard().execute_step(oid, "community", {"name": ""})
        assert result["ok"] is False
        assert "required" in result["error"].lower()

    def test_full_onboarding_flow_completes(self):
        w   = _wizard()
        oid = w.start_onboarding("t4")["onboarding_id"]
        w.execute_step(oid, "community", {"name": "Acme"})
        w.execute_step(oid, "members", {"emails": ["alice@acme.com"], "role": "admin"})
        w.execute_step(oid, "marketplace", {"enabled": True, "chain": "sepolia"})
        w.execute_step(oid, "compliance", {"frameworks": ["gdpr", "soc2"]})
        last = w.execute_step(oid, "integrations", {"evolution_enabled": True})
        assert last["ok"] is True
        assert last.get("summary", {}).get("community") == "Acme"
        state = _load(oid)
        assert state["completed"] is True

    def test_state_persisted_after_step(self):
        w   = _wizard()
        oid = w.start_onboarding("t5")["onboarding_id"]
        w.execute_step(oid, "community", {"name": "PersistCo", "visibility": "private"})
        state = _load(oid)
        assert state["community_name"] == "PersistCo"
        assert state["current_step"] == "members"

    def test_invalid_step_returns_error(self):
        oid = _wizard().start_onboarding("t6")["onboarding_id"]
        result = _wizard().execute_step(oid, "unknown_step", {})
        assert "error" in result
