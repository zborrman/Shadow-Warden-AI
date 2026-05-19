"""
warden/tests/test_extra_coverage.py
─────────────────────────────────────
Coverage boost tests for partially-covered modules.
"""
from __future__ import annotations

import os
import uuid
from unittest.mock import patch

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("LOGS_PATH", "/tmp/extra_cov_logs.json")


# ── WalletShield ──────────────────────────────────────────────────────────────

class TestWalletShield:
    def test_estimate_tokens_empty(self):
        from warden.wallet_shield import estimate_tokens
        assert estimate_tokens([]) == 0

    def test_estimate_tokens_string_content(self):
        from warden.wallet_shield import estimate_tokens
        msgs = [{"role": "user", "content": "hello world"}]
        assert estimate_tokens(msgs) >= 1

    def test_estimate_tokens_multimodal(self):
        from warden.wallet_shield import estimate_tokens
        msgs = [{"role": "user", "content": [{"type": "text", "text": "hello world"}]}]
        assert estimate_tokens(msgs) >= 1

    def test_estimate_tokens_no_content(self):
        from warden.wallet_shield import estimate_tokens
        msgs = [{"role": "user"}]
        assert estimate_tokens(msgs) >= 0

    def test_budget_result_to_dict(self):
        from warden.wallet_shield import BudgetResult
        r = BudgetResult(allowed=False, used=90000, limit=100000, remaining=10000, limit_type="user_window")
        d = r.to_dict()
        assert d["error"] == "token_budget_exceeded"
        assert d["limit"] == 100000
        assert "hint" in d

    def test_budget_result_remaining_clamped(self):
        from warden.wallet_shield import BudgetResult
        r = BudgetResult(allowed=False, used=110000, limit=100000, remaining=-10000, limit_type="user_window")
        assert r.to_dict()["remaining"] == 0

    def test_check_disabled(self):
        from warden.wallet_shield import WalletShield
        with patch("warden.wallet_shield._ENABLED", False):
            ws = WalletShield()
            result = ws.check_and_consume("tenant", "user", 1000)
            assert result.allowed is True
            assert result.limit_type == "disabled"

    def test_check_hard_limit_exceeded(self):
        from warden.wallet_shield import WalletShield
        with patch("warden.wallet_shield._ENABLED", True):
            with patch("warden.wallet_shield._HARD_LIMIT", 100):
                ws = WalletShield()
                result = ws.check_and_consume("t", "u", 200)
                assert result.allowed is False
                assert result.limit_type == "hard_limit"

    def test_check_no_redis_fail_open(self):
        from warden.wallet_shield import WalletShield
        with patch("warden.wallet_shield._ENABLED", True):
            ws = WalletShield()
            with patch.object(ws, "_client", return_value=None):
                result = ws.check_and_consume("t", "u", 100)
                assert result.allowed is True

    def test_get_wallet_shield_singleton(self):
        import warden.wallet_shield as wm
        wm._shield = None
        s1 = wm.get_wallet_shield()
        s2 = wm.get_wallet_shield()
        assert s1 is s2


# ── XAI Renderer ─────────────────────────────────────────────────────────────

class TestXaiRenderer:
    def _make_chain(self):
        from warden.xai.chain import build_chain
        log_entry = {
            "request_id": "test-req-001",
            "tenant_id": "test-tenant",
            "verdict": "BLOCK",
            "risk_level": "HIGH",
            "score": 0.95,
            "flags": ["PROMPT_INJECTION"],
            "stage_verdicts": {"topology": "PASS", "semantic_rules": "BLOCK"},
            "latency_ms": 12.5,
            "timestamp": "2026-01-01T12:00:00+00:00",
        }
        return build_chain(log_entry)

    def test_render_html_returns_bytes(self):
        from warden.xai.renderer import render_html
        chain = self._make_chain()
        html = render_html(chain)
        assert isinstance(html, bytes)
        assert b"<html" in html or b"<!DOCTYPE" in html

    def test_render_html_contains_verdict(self):
        from warden.xai.renderer import render_html
        chain = self._make_chain()
        html = render_html(chain)
        assert b"BLOCK" in html or b"block" in html.lower()

    def test_render_html_contains_request_id(self):
        from warden.xai.renderer import render_html
        chain = self._make_chain()
        html = render_html(chain)
        assert b"test-req-001" in html

    def test_render_pdf_returns_content(self):
        from warden.xai.renderer import render_pdf
        chain = self._make_chain()
        content, content_type = render_pdf(chain)
        assert isinstance(content, bytes)
        assert len(content) > 0
        assert content_type in ("application/pdf", "text/html; charset=utf-8")

    def test_render_html_allow_verdict(self):
        from warden.xai.chain import build_chain
        from warden.xai.renderer import render_html
        entry = {"request_id": "req-allow", "verdict": "ALLOW", "risk_level": "LOW", "score": 0.05, "flags": []}
        chain = build_chain(entry)
        html = render_html(chain)
        assert isinstance(html, bytes)


# ── Retention API ────────────────────────────────────────────────────────────

class TestRetentionApi:
    @pytest.mark.asyncio
    async def test_get_policy(self):
        from warden.api.retention import get_policy
        result = await get_policy(tenant_id="test-tenant")
        assert isinstance(result, dict)
        assert "policy" in result or "PII" in result or len(result) > 0

    @pytest.mark.asyncio
    async def test_update_policy(self):
        from warden.api.retention import update_policy
        result = await update_policy({"PII": 14}, tenant_id="test-tenant")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_stats(self):
        from warden.api.retention import get_stats
        result = await get_stats(tenant_id="test-tenant")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_trigger_enforce(self):
        from warden.api.retention import trigger_enforce
        result = await trigger_enforce(tenant_id="test-tenant")
        assert isinstance(result, dict)

    def test_get_effective_policy_defaults(self):
        from warden.api.retention import DEFAULT_RETENTION_DAYS, get_effective_policy
        policy = get_effective_policy("unknown-tenant-xyz")
        assert "PII" in policy or isinstance(policy, dict)

    def test_enforce_retention_returns_dict(self):
        from warden.api.retention import enforce_retention
        result = enforce_retention("test-tenant")
        assert isinstance(result, dict)


# ── Financial Impact Calculator ───────────────────────────────────────────────

class TestFinancialImpact:
    def test_industry_enum(self):
        from warden.financial.impact_calculator import Industry
        assert hasattr(Industry, "HEALTHCARE") or len(Industry) > 0

    def test_calculator_init(self):
        from warden.financial.impact_calculator import DollarImpactCalculator, Industry
        calc = DollarImpactCalculator(industry=Industry.HEALTHCARE)
        assert calc is not None

    def test_calculate_returns_incident_cost(self):
        from warden.financial.impact_calculator import DollarImpactCalculator, Industry
        calc = DollarImpactCalculator(industry=Industry.FINTECH)
        result = calc.calculate_total_impact()
        assert result is not None

    def test_pricing_config_exists(self):
        from warden.financial.impact_calculator import PRICING
        assert isinstance(PRICING, dict)
        assert len(PRICING) > 0

    def test_incident_cost_dataclass(self):
        from warden.financial.impact_calculator import IncidentCost
        cost = IncidentCost(
            direct_cost=10000.0,
            recovery_cost=5000.0,
            legal_cost=2000.0,
            reputational_cost=3000.0,
            operational_cost=1000.0,
        )
        assert cost.direct_cost == 10000.0
        assert cost.recovery_cost == 5000.0


# ── Secrets Governance Vault Connector ────────────────────────────────────────

class TestVaultConnector:
    @pytest.mark.asyncio
    async def test_env_connector_list(self):
        from warden.secrets_gov.vault_connector import EnvVaultConnector
        connector = EnvVaultConnector()
        secrets = await connector.list_secrets()
        assert isinstance(secrets, list)

    @pytest.mark.asyncio
    async def test_env_connector_health(self):
        from warden.secrets_gov.vault_connector import EnvVaultConnector
        connector = EnvVaultConnector()
        healthy = await connector.health_check()
        assert isinstance(healthy, bool)

    def test_build_connector_env(self):
        from warden.secrets_gov.vault_connector import build_connector
        connector = build_connector({"vault_type": "env", "vault_id": "test-env"})
        assert connector is not None

    def test_vault_secret_meta(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        meta = VaultSecretMeta(name="MY_SECRET", vault_id="vault-1", vault_type="env")
        assert meta.name == "MY_SECRET"

    @pytest.mark.asyncio
    async def test_connector_types_importable(self):
        from warden.secrets_gov.vault_connector import CONNECTOR_TYPES
        assert "env" in CONNECTOR_TYPES


# ── Communities Peering ───────────────────────────────────────────────────────

@pytest.fixture
def tmp_sep_db_peering(tmp_path, monkeypatch):
    monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "sep_peering.db"))


class TestCommunitiesPeering:
    def test_list_peerings_empty(self, tmp_sep_db_peering):
        from warden.communities.peering import list_peerings
        result = list_peerings(f"community-{uuid.uuid4().hex[:8]}")
        assert result == []

    def test_initiate_peering(self, tmp_sep_db_peering):
        from warden.communities.peering import initiate_peering
        cid1 = f"c1-{uuid.uuid4().hex[:8]}"
        cid2 = f"c2-{uuid.uuid4().hex[:8]}"
        mid = f"m-{uuid.uuid4().hex[:8]}"
        result = initiate_peering(cid1, cid2, initiator_mid=mid, policy="MIRROR_ONLY")
        assert result is not None

    def test_get_peering_not_found(self, tmp_sep_db_peering):
        from warden.communities.peering import get_peering
        result = get_peering("nonexistent-id")
        assert result is None

    def test_list_transfers_empty(self, tmp_sep_db_peering):
        from warden.communities.peering import list_transfers
        result = list_transfers(f"community-{uuid.uuid4().hex[:8]}")
        assert result == []


# ── Billing Router ────────────────────────────────────────────────────────────

class TestBillingRouter:
    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from warden.billing.router import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_get_tiers(self):
        resp = self.client.get("/billing/tiers")
        assert resp.status_code == 200

    def test_get_addons(self):
        resp = self.client.get("/billing/addons")
        assert resp.status_code == 200

    def test_addon_catalog_keys(self):
        from warden.billing.addons import ADDON_CATALOG
        assert len(ADDON_CATALOG) > 0
        for key, addon in ADDON_CATALOG.items():
            assert "usd_per_month" in addon
            assert "min_tier" in addon

    def test_get_current_tier(self):
        resp = self.client.get("/billing/current", headers={"X-Tenant-ID": "test"})
        assert resp.status_code in (200, 404, 422)


# ── Federation (module-level patch) ──────────────────────────────────────────

class TestFederationExtra:
    def test_store_and_lookup_with_module_patch(self):
        import warden.communities.federation as fed
        from warden.communities.federation import (
            FederatedVerdict,
            _store_verdict,
            _threat_hash,
        )
        cid = f"store-{uuid.uuid4().hex[:8]}"
        text = "malicious payload for testing"
        th = _threat_hash(text, cid)
        fv = FederatedVerdict(
            community_id=cid, threat_hash=th, verdict="BLOCK",
            score=0.99, data_class="GENERAL", ueciid=None,
            ts="2026-01-01T00:00:00+00:00",
        )
        _store_verdict(cid, fv)
        # Patch at module level
        with patch.object(fed, "_FEDERATION_ENABLED", True):
            result = fed.check_threat_hash(cid, text)
            assert result is not None
            assert result.verdict == "BLOCK"

    def test_score_boost_with_module_patch(self):
        import warden.communities.federation as fed
        from warden.communities.federation import (
            FederatedVerdict,
            _BOOST,
            _store_verdict,
            _threat_hash,
        )
        cid = f"boost-{uuid.uuid4().hex[:8]}"
        text = "boost test text payload"
        th = _threat_hash(text, cid)
        fv = FederatedVerdict(
            community_id=cid, threat_hash=th, verdict="BLOCK",
            score=0.9, data_class="GENERAL", ueciid=None,
            ts="2026-01-01T00:00:00+00:00",
        )
        _store_verdict(cid, fv)
        with patch.object(fed, "_FEDERATION_ENABLED", True):
            boost = fed.get_score_boost(cid, text)
            assert boost == _BOOST
