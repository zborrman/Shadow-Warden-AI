"""
warden/tests/test_hub_marketplace_flow.py
──────────────────────────────────────────
Integration tests for the end-to-end flow:
  Create Community → Hub readiness → Marketplace agent + asset → Escrow lifecycle
  Voice session creation · DAO governance · Compliance evidence bundle

**Why fixtures and not class attributes.** This file used to hand state between
tests by writing it onto the test classes — ``TestCreateCommunity.community_id``
set by one test and read by eight others, then ``agent_id``, ``asset_id``,
``listing_id``, ``escrow_id`` in a chain five deep. Twenty-five tests were
really one test with twenty-five assertion points, and they only worked when the
whole file ran in file order.

Measured 2026-08-19: running this file alongside a ``-k`` selection produced

    AttributeError: type object 'TestAssetTokenization' has no attribute 'asset_id'

for three tests, because the selection filtered out the test that assigns it.
The same breaks under ``--lf``, ``-x``, ``-p xdist`` and any random ordering —
every workflow you would use to debug one endpoint. And when a step genuinely
regresses, the tests after it fail with AttributeError rather than pointing at
the failure, so the real cause arrives buried in a cascade.

The dependency ladder below is the same flow expressed so pytest can resolve it:
each fixture is module-scoped (the flow still runs once, not per test) and each
test declares only what it needs. Any single test can now be run on its own.

The escrow lifecycle is a state machine, so its steps remain ordered — but the
ordering is carried by fixture dependencies (``funded_escrow`` →
``delivered_escrow`` → ``confirmed_escrow``) rather than by luck, which is what
makes a single step runnable in isolation.
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

_TENANT_HEADERS = {"X-Tenant-ID": TENANT_ID, "X-Tenant-Tier": "business"}


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from warden.main import app
    return TestClient(app)


# ── Dependency ladder ─────────────────────────────────────────────────────────
# Module-scoped: the flow is set up once for the file, as before. What changed is
# that the order is declared, so pytest builds only what a selected test needs.

@pytest.fixture(scope="module")
def community_id(client) -> str:
    resp = client.post("/communities", json={
        "display_name": COMM_NAME,
        "description":  "Integration test community",
    }, headers=_TENANT_HEADERS)
    assert resp.status_code in (200, 201), resp.text
    data = resp.json()
    cid = data.get("community_id") or data.get("id")
    assert cid, f"no community id in {data}"
    return str(cid)


@pytest.fixture(scope="module")
def agent_id(client, community_id) -> str:
    resp = client.post("/marketplace/agents/register", json={
        "tenant_id":    TENANT_ID,
        "community_id": community_id,
        "public_key":   FAKE_PUBKEY,
        "capabilities": ["marketplace_sell", "marketplace_buy"],
    })
    assert resp.status_code in (200, 201), resp.text
    aid = resp.json()["agent_id"]
    assert aid.startswith("did:shadow:")
    return str(aid)


@pytest.fixture(scope="module")
def asset_id(client, agent_id) -> str:
    resp = client.post("/marketplace/assets", json={
        "tenant_id":       TENANT_ID,
        "seller_agent_id": agent_id,
        "asset_type":      "rule",
        "raw_data":        {
            "name":        "Jailbreak Filter v1",
            "description": "Pattern: ignore previous instructions",
            "content":     "^ignore (all )?(previous|above) instructions",
            "price_usd":   9.99,
        },
    })
    assert resp.status_code in (200, 201), resp.text
    aid = resp.json()["asset_id"]
    assert aid.startswith("SEP-")
    return str(aid)


@pytest.fixture(scope="module")
def listing_id(client, asset_id, agent_id, community_id) -> str:
    resp = client.post("/marketplace/listings", json={
        "asset_id":        asset_id,
        "seller_agent_id": agent_id,
        "community_id":    community_id,
        "tenant_id":       TENANT_ID,
        "price_usd":       9.99,
    })
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["listing_id"])


@pytest.fixture(scope="module")
def escrow_id(client, listing_id, agent_id) -> str:
    # FT-3: /purchase requires an Idempotency-Key header.
    resp = client.post(f"/marketplace/listings/{listing_id}/purchase", json={
        "buyer_agent_id": agent_id,
    }, headers={"Idempotency-Key": f"hub-flow-test-buy-{_SUFFIX}"})
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["escrow_id"])


# The escrow state machine, one rung per transition. A test that needs a
# delivered escrow asks for `delivered_escrow` and gets one, whether or not the
# tests for the earlier transitions were selected to run.

@pytest.fixture(scope="module")
def funded_escrow(client, escrow_id) -> str:
    resp = client.post(f"/marketplace/escrow/{escrow_id}/fund")
    assert resp.status_code in (200, 201, 204), resp.text
    return escrow_id


@pytest.fixture(scope="module")
def delivered_escrow(client, funded_escrow) -> str:
    resp = client.post(f"/marketplace/escrow/{funded_escrow}/deliver", json={
        "asset_hash": "sha256:abc123def456",
    })
    assert resp.status_code in (200, 201, 204), resp.text
    return funded_escrow


@pytest.fixture(scope="module")
def confirmed_escrow(client, delivered_escrow) -> str:
    resp = client.post(f"/marketplace/escrow/{delivered_escrow}/confirm")
    assert resp.status_code in (200, 201, 204), resp.text
    return delivered_escrow


# Optional subsystems: skip rather than fail when the module is absent from the
# test image, exactly as the class-attribute version did via hasattr guards.

@pytest.fixture(scope="module")
def voice_session_id(client, community_id) -> str:
    resp = client.post("/voice/session", json={
        "community_id": community_id,
        "mode": "commerce",
    })
    if resp.status_code in (404, 503, 501):
        pytest.skip("Voice module not available in test environment")
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["session_id"])


@pytest.fixture(scope="module")
def proposal_id(client, community_id, agent_id) -> str:
    resp = client.post("/marketplace/proposals", json={
        "community_id":  community_id,
        "proposer_id":   agent_id,
        "proposal_type": "parameter_change",
        "target_id":     community_id,
        "title":         "Add price floor rule",
        "description":   "Minimum listing price $0.99 to reduce spam.",
    })
    if resp.status_code in (404, 503):
        pytest.skip("Governance not available")
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["proposal_id"])


# ── 1. Community creation ─────────────────────────────────────────────────────

class TestCreateCommunity:
    def test_create_community_returns_id(self, community_id):
        assert community_id

    def test_get_created_community(self, client, community_id):
        resp = client.get(f"/communities/{community_id}", headers=_TENANT_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("name") == COMM_NAME or data.get("community_id") == community_id


# ── 2. Marketplace readiness ──────────────────────────────────────────────────

class TestMarketplaceReadiness:
    def test_readiness_after_creation(self, client, community_id):
        resp = client.get(f"/marketplace/readiness/{community_id}")
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
    def test_register_agent(self, agent_id):
        assert agent_id.startswith("did:shadow:")

    def test_list_agents_contains_registered(self, client, community_id, agent_id):
        resp = client.get(f"/marketplace/agents?community_id={community_id}")
        assert resp.status_code == 200
        ids = [a.get("agent_id") for a in resp.json()]
        assert agent_id in ids


# ── 4. Asset tokenization ─────────────────────────────────────────────────────

class TestAssetTokenization:
    def test_tokenize_rule_asset(self, asset_id):
        assert asset_id.startswith("SEP-")

    def test_asset_has_ueciid_prefix(self, client, community_id, asset_id):
        resp = client.get(f"/marketplace/assets?community_id={community_id}")
        assert resp.status_code == 200
        assert any(a.get("asset_id") == asset_id for a in resp.json())


# ── 5. Listing + buy flow ─────────────────────────────────────────────────────

class TestListingFlow:
    def test_create_listing(self, listing_id):
        assert listing_id

    def test_list_listings_contains_created(self, client, listing_id):
        resp = client.get("/marketplace/listings")
        assert resp.status_code == 200
        ids = [item.get("listing_id") for item in resp.json()]
        assert listing_id in ids

    def test_buy_listing_creates_escrow(self, escrow_id):
        assert escrow_id


# ── 6. Escrow lifecycle ───────────────────────────────────────────────────────

class TestEscrowLifecycle:
    def test_fund_escrow(self, funded_escrow):
        assert funded_escrow

    def test_deliver_asset(self, delivered_escrow):
        assert delivered_escrow

    def test_confirm_receipt(self, confirmed_escrow):
        assert confirmed_escrow

    def test_escrow_status_after_confirm(self, client, confirmed_escrow):
        resp = client.get(f"/marketplace/escrow/{confirmed_escrow}")
        assert resp.status_code == 200
        status = resp.json().get("status", "")
        assert status in ("confirmed", "completed", "released")

    def test_fund_unknown_escrow_returns_404(self, client):
        """FT-3: nonexistent escrow_id is a 404, distinct from an illegal
        state transition (409) on a real escrow."""
        resp = client.post("/marketplace/escrow/ESC-DOES-NOT-EXIST/fund")
        assert resp.status_code == 404

    def test_refund_already_confirmed_escrow_returns_409(self, client, confirmed_escrow):
        """FT-3: re-funding an escrow already in 'confirmed' state is a
        state conflict (409), not a generic 400."""
        resp = client.post(f"/marketplace/escrow/{confirmed_escrow}/fund")
        assert resp.status_code == 409


# ── 7. Readiness after setup ──────────────────────────────────────────────────

class TestReadinessAfterSetup:
    def test_readiness_agents_registered(self, client, community_id, agent_id):
        resp = client.get(f"/marketplace/readiness/{community_id}")
        assert resp.status_code == 200
        assert resp.json()["agents_registered"] is True


# ── 8. Voice session ──────────────────────────────────────────────────────────

class TestVoiceSession:
    def test_create_voice_session(self, voice_session_id):
        assert voice_session_id

    def test_voice_session_transcribe(self, client, voice_session_id):
        resp = client.post("/voice/transcribe", json={
            "session_id": voice_session_id,
            "audio_b64":  "UklGRiQAAABXQVZFZm10IBAAAA==",  # minimal WAV stub
        })
        if resp.status_code in (404, 503, 501):
            pytest.skip("Voice transcribe not available")
        assert resp.status_code in (200, 422), resp.text


# ── 9. DAO governance ─────────────────────────────────────────────────────────

class TestDAOGovernance:
    def test_create_proposal(self, proposal_id):
        assert proposal_id

    def test_vote_on_proposal(self, client, proposal_id, agent_id):
        resp = client.post(
            f"/marketplace/proposals/{proposal_id}/vote",
            json={"voter_id": agent_id, "choice": 0},
        )
        if resp.status_code in (404, 503):
            pytest.skip("Governance voting not available")
        assert resp.status_code in (200, 201, 204), resp.text

    def test_list_proposals(self, client, community_id):
        resp = client.get(f"/marketplace/proposals?community_id={community_id}")
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
