"""
warden/tests/test_hub_marketplace_flow.py
──────────────────────────────────────────
Integration tests for the end-to-end flow:
  Create Community → Hub readiness → Marketplace agent + asset → Escrow lifecycle
  Voice session creation · DAO governance · Compliance evidence bundle
"""
from __future__ import annotations

import base64
import os
import uuid

import pytest

_SUFFIX   = uuid.uuid4().hex[:8]
_MKT_DB   = f"/tmp/test_hub_mkt_{_SUFFIX}.db"
_COMM_DB  = f"/tmp/test_hub_comm_{_SUFFIX}.db"
_SEP_DB   = f"/tmp/test_hub_sep_{_SUFFIX}.db"
_LOGS     = f"/tmp/test_hub_logs_{_SUFFIX}.json"

os.environ.setdefault("MARKETPLACE_DB_PATH",   _MKT_DB)
os.environ.setdefault("COMM_DB_PATH",           _COMM_DB)
os.environ.setdefault("SEP_DB_PATH",            _SEP_DB)
os.environ.setdefault("LOGS_PATH",              _LOGS)
os.environ.setdefault("ALLOW_UNAUTHENTICATED",  "true")
os.environ.setdefault("WARDEN_API_KEY",         "")
os.environ.setdefault("MODEL_CACHE_DIR",        "/tmp/warden_test_models")
os.environ.setdefault("DYNAMIC_RULES_PATH",     "/tmp/warden_test_dynamic_rules.json")
os.environ.setdefault("SEMANTIC_THRESHOLD",     "0.72")
os.environ.setdefault("STRICT_MODE",            "false")
os.environ.setdefault("REDIS_URL",              "memory://")
os.environ.setdefault("WAT_SIMULATE",           "true")
os.environ.setdefault("USDC_SIMULATE",          "true")

TENANT_ID  = f"hub-test-tenant-{_SUFFIX}"
COMM_NAME  = f"Hub Test Community {_SUFFIX}"
FAKE_PUBKEY = base64.b64encode(b"fake-ed25519-pubkey-32bytes-paddd").decode()


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from warden.main import app
    return TestClient(app)


# ── 1. Community creation ─────────────────────────────────────────────────────

class TestCreateCommunity:
    def test_create_community_returns_id(self, client):
        resp = client.post("/communities", json={
            "display_name": COMM_NAME,
            "description":  "Integration test community",
        }, headers={"X-Tenant-ID": TENANT_ID, "X-Tenant-Tier": "business"})
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "community_id" in data or "id" in data
        cid = data.get("community_id") or data.get("id")
        assert cid
        # store for subsequent tests
        TestCreateCommunity.community_id = cid

    def test_get_created_community(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.get(f"/communities/{cid}", headers={"X-Tenant-ID": TENANT_ID, "X-Tenant-Tier": "business"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("name") == COMM_NAME or data.get("community_id") == cid


# ── 2. Marketplace readiness ──────────────────────────────────────────────────

class TestMarketplaceReadiness:
    def test_readiness_after_creation(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.get(f"/marketplace/readiness/{cid}")
        assert resp.status_code == 200
        data = resp.json()
        assert "ready_to_trade" in data
        assert "community_exists" in data
        assert data["community_exists"] is True

    def test_readiness_missing_community(self, client):
        resp = client.get("/marketplace/readiness/does-not-exist-xyz")
        assert resp.status_code == 200
        assert resp.json()["community_exists"] is False


# ── 3. Agent registration ─────────────────────────────────────────────────────

class TestAgentRegistration:
    def test_register_agent(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.post("/marketplace/agents/register", json={
            "tenant_id":    TENANT_ID,
            "community_id": cid,
            "public_key":   FAKE_PUBKEY,
            "capabilities": ["marketplace_sell", "marketplace_buy"],
        })
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "agent_id" in data
        assert data["agent_id"].startswith("did:shadow:")
        TestAgentRegistration.agent_id = data["agent_id"]

    def test_list_agents_contains_registered(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.get(f"/marketplace/agents?community_id={cid}")
        assert resp.status_code == 200
        agents = resp.json()
        ids = [a.get("agent_id") for a in agents]
        assert TestAgentRegistration.agent_id in ids


# ── 4. Asset tokenization ─────────────────────────────────────────────────────

class TestAssetTokenization:
    def test_tokenize_rule_asset(self, client):
        resp = client.post("/marketplace/assets", json={
            "tenant_id":       TENANT_ID,
            "seller_agent_id": TestAgentRegistration.agent_id,
            "asset_type":      "rule",
            "raw_data":        {
                "name":        "Jailbreak Filter v1",
                "description": "Pattern: ignore previous instructions",
                "content":     "^ignore (all )?(previous|above) instructions",
                "price_usd":   9.99,
            },
        })
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "asset_id" in data
        assert data["asset_id"].startswith("SEP-")
        TestAssetTokenization.asset_id = data["asset_id"]

    def test_asset_has_ueciid_prefix(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.get(f"/marketplace/assets?community_id={cid}")
        assert resp.status_code == 200
        assets = resp.json()
        assert any(a.get("asset_id") == TestAssetTokenization.asset_id for a in assets)


# ── 5. Listing + buy flow ─────────────────────────────────────────────────────

class TestListingFlow:
    def test_create_listing(self, client):
        resp = client.post("/marketplace/listings", json={
            "asset_id":        TestAssetTokenization.asset_id,
            "seller_agent_id": TestAgentRegistration.agent_id,
            "community_id":    TestCreateCommunity.community_id,
            "tenant_id":       TENANT_ID,
            "price_usd":       9.99,
        })
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "listing_id" in data
        TestListingFlow.listing_id = data["listing_id"]

    def test_list_listings_contains_created(self, client):
        resp = client.get("/marketplace/listings")
        assert resp.status_code == 200
        ids = [item.get("listing_id") for item in resp.json()]
        assert TestListingFlow.listing_id in ids

    def test_buy_listing_creates_escrow(self, client):
        # FT-3: /purchase now requires an Idempotency-Key header.
        resp = client.post(f"/marketplace/listings/{TestListingFlow.listing_id}/purchase", json={
            "buyer_agent_id": TestAgentRegistration.agent_id,
        }, headers={"Idempotency-Key": "hub-flow-test-buy-1"})
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "escrow_id" in data
        TestListingFlow.escrow_id = data["escrow_id"]


# ── 6. Escrow lifecycle ───────────────────────────────────────────────────────

class TestEscrowLifecycle:
    def test_fund_escrow(self, client):
        eid = TestListingFlow.escrow_id
        resp = client.post(f"/marketplace/escrow/{eid}/fund")
        assert resp.status_code in (200, 201, 204), resp.text

    def test_deliver_asset(self, client):
        eid = TestListingFlow.escrow_id
        resp = client.post(f"/marketplace/escrow/{eid}/deliver", json={
            "asset_hash": "sha256:abc123def456",
        })
        assert resp.status_code in (200, 201, 204), resp.text

    def test_confirm_receipt(self, client):
        eid = TestListingFlow.escrow_id
        resp = client.post(f"/marketplace/escrow/{eid}/confirm")
        assert resp.status_code in (200, 201, 204), resp.text

    def test_escrow_status_after_confirm(self, client):
        eid = TestListingFlow.escrow_id
        resp = client.get(f"/marketplace/escrow/{eid}")
        assert resp.status_code == 200
        data = resp.json()
        status = data.get("status", "")
        assert status in ("confirmed", "completed", "released")

    def test_fund_unknown_escrow_returns_404(self, client):
        """FT-3: nonexistent escrow_id is a 404, distinct from an illegal
        state transition (409) on a real escrow."""
        resp = client.post("/marketplace/escrow/ESC-DOES-NOT-EXIST/fund")
        assert resp.status_code == 404

    def test_refund_already_confirmed_escrow_returns_409(self, client):
        """FT-3: re-funding an escrow already in 'confirmed' state is a
        state conflict (409), not a generic 400."""
        eid = TestListingFlow.escrow_id
        resp = client.post(f"/marketplace/escrow/{eid}/fund")
        assert resp.status_code == 409


# ── 7. Readiness after setup ──────────────────────────────────────────────────

class TestReadinessAfterSetup:
    def test_readiness_agents_registered(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.get(f"/marketplace/readiness/{cid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agents_registered"] is True


# ── 8. Voice session ──────────────────────────────────────────────────────────

class TestVoiceSession:
    def test_create_voice_session(self, client):
        resp = client.post("/voice/session", json={
            "community_id": TestCreateCommunity.community_id,
            "mode": "commerce",
        })
        # Voice module may not be installed in test env; accept 404/503 as skip
        if resp.status_code in (404, 503, 501):
            pytest.skip("Voice module not available in test environment")
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "session_id" in data
        TestVoiceSession.session_id = data["session_id"]

    def test_voice_session_transcribe(self, client):
        if not hasattr(TestVoiceSession, "session_id"):
            pytest.skip("Voice session not created")
        resp = client.post("/voice/transcribe", json={
            "session_id": TestVoiceSession.session_id,
            "audio_b64":  "UklGRiQAAABXQVZFZm10IBAAAA==",  # minimal WAV stub
        })
        if resp.status_code in (404, 503, 501):
            pytest.skip("Voice transcribe not available")
        assert resp.status_code in (200, 422), resp.text


# ── 9. DAO governance ─────────────────────────────────────────────────────────

class TestDAOGovernance:
    def test_create_proposal(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.post("/marketplace/proposals", json={
            "community_id":  cid,
            "proposer_id":   TestAgentRegistration.agent_id,
            "proposal_type": "parameter_change",
            "target_id":     cid,
            "title":         "Add price floor rule",
            "description":   "Minimum listing price $0.99 to reduce spam.",
        })
        if resp.status_code in (404, 503):
            pytest.skip("Governance not available")
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert "proposal_id" in data
        TestDAOGovernance.proposal_id = data["proposal_id"]

    def test_vote_on_proposal(self, client):
        if not hasattr(TestDAOGovernance, "proposal_id"):
            pytest.skip("No proposal created")
        resp = client.post(
            f"/marketplace/proposals/{TestDAOGovernance.proposal_id}/vote",
            json={"voter_id": TestAgentRegistration.agent_id, "choice": 0},
        )
        if resp.status_code in (404, 503):
            pytest.skip("Governance voting not available")
        assert resp.status_code in (200, 201, 204), resp.text

    def test_list_proposals(self, client):
        cid = TestCreateCommunity.community_id
        resp = client.get(f"/marketplace/proposals?community_id={cid}")
        if resp.status_code in (404, 503):
            pytest.skip("Governance not available")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ── 10. Compliance evidence bundle ────────────────────────────────────────────

class TestComplianceEvidence:
    def test_evidence_bundle_endpoint_exists(self, client):
        resp = client.post("/compliance/evidence-bundle", json={
            "tenant_id": TENANT_ID,
        })
        if resp.status_code in (404, 503):
            pytest.skip("Evidence bundle endpoint not available")
        assert resp.status_code in (200, 201, 202), resp.text
        data = resp.json()
        assert "key" in data or "url" in data or "size" in data

    def test_trust_center_subprocessors(self, client):
        resp = client.get("/compliance/subprocessors")
        if resp.status_code in (404, 503):
            pytest.skip("Subprocessors endpoint not available")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
