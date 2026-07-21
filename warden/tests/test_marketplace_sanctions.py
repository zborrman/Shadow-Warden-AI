"""Tests for warden/marketplace/sanctions.py — sanctions screening at settlement (FT-5)."""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "mkt.db")
    os.environ["REDIS_URL"] = "memory://"

    import warden.communities.incident_register as incident_mod
    import warden.staff.tools.compliance_kyc as kyc_mod
    monkeypatch.setattr(kyc_mod, "_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setattr(incident_mod, "_DB_PATH", str(tmp_path / "sep.db"))
    yield
    os.environ.pop("MARKETPLACE_DB_PATH", None)
    os.environ.pop("REDIS_URL", None)


class TestScreeningEnabledFlag:
    def test_disabled_by_default(self):
        from warden.marketplace.sanctions import screening_enabled
        assert screening_enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        from warden.marketplace.sanctions import screening_enabled
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        assert screening_enabled() is True


class TestScreenSettlementParty:
    @pytest.mark.asyncio
    async def test_noop_when_disabled(self):
        from warden.marketplace.sanctions import screen_settlement_party
        result = await screen_settlement_party("agent-1", "clear-1")
        assert result == {"screened": False}

    @pytest.mark.asyncio
    async def test_noop_on_empty_agent_id(self, monkeypatch):
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        from warden.marketplace.sanctions import screen_settlement_party
        result = await screen_settlement_party("", "clear-1")
        assert result == {"screened": False}

    @pytest.mark.asyncio
    async def test_clean_subject_no_incident(self, monkeypatch):
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        from warden.marketplace.sanctions import screen_settlement_party
        result = await screen_settlement_party("agent-clean", "clear-1")
        assert result["screened"] is True
        assert result["result"]["hit"] is False

    @pytest.mark.asyncio
    async def test_hit_opens_incident(self, monkeypatch):
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        from warden.marketplace.kya import register_agent
        from warden.marketplace.kyb import submit_for_review
        from warden.marketplace.sanctions import screen_settlement_party

        register_agent("agent-sanctioned", "tenant-bad")
        submit_for_review("tenant-bad", business_name="ofac_test_entity")

        incidents = []
        import warden.marketplace.sanctions as sanctions_mod
        monkeypatch.setattr(
            sanctions_mod, "_open_incident",
            lambda tenant_id, subject, clearing_id, result: incidents.append(
                (tenant_id, subject, clearing_id, result)
            ),
        )

        result = await screen_settlement_party("agent-sanctioned", "clear-hit")
        assert result["result"]["hit"] is True
        assert len(incidents) == 1
        assert incidents[0][0] == "tenant-bad"

    @pytest.mark.asyncio
    async def test_uses_kyb_business_name_when_available(self, monkeypatch):
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        from warden.marketplace.kya import register_agent
        from warden.marketplace.kyb import submit_for_review
        from warden.marketplace.sanctions import screen_settlement_party

        register_agent("agent-named", "tenant-named")
        submit_for_review("tenant-named", business_name="Acme Corp")

        result = await screen_settlement_party("agent-named", "clear-2")
        assert result["result"]["subject"] == "Acme Corp"

    @pytest.mark.asyncio
    async def test_falls_back_to_tenant_id_without_kyb(self, monkeypatch):
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        from warden.marketplace.kya import register_agent
        from warden.marketplace.sanctions import screen_settlement_party

        register_agent("agent-no-kyb", "tenant-no-kyb")
        result = await screen_settlement_party("agent-no-kyb", "clear-3")
        assert result["result"]["subject"] == "tenant-no-kyb"

    @pytest.mark.asyncio
    async def test_falls_back_to_agent_id_without_kya(self, monkeypatch):
        """No KYA registration at all → owner unknown → screen the raw agent id."""
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        from warden.marketplace.sanctions import screen_settlement_party

        result = await screen_settlement_party("agent-unregistered", "clear-4")
        assert result["result"]["subject"] == "agent-unregistered"

    @pytest.mark.asyncio
    async def test_fail_soft_on_screening_error(self, monkeypatch):
        monkeypatch.setenv("SANCTIONS_SCREENING_ENABLED", "true")
        import warden.staff.tools.compliance_kyc as kyc_mod
        from warden.marketplace.sanctions import screen_settlement_party

        async def _boom(**kwargs):
            raise RuntimeError("screening backend down")

        monkeypatch.setattr(kyc_mod, "screen_sanctions_list", _boom)
        result = await screen_settlement_party("agent-boom", "clear-5")
        assert result["screened"] is False
        assert "error" in result
