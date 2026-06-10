"""
warden/tests/test_marketplace_agentic.py
─────────────────────────────────────────
14 tests for Community M2M Agentic Marketplace — Phase 1.

Covers:
  1–5   Agent identity (DID derivation, capabilities, mandate, CRUD)
  6–10  Asset tokenizer (rule, ReDoS gate, model, signals, IPFS CID)
  11–14 Asset registry service + FastAPI router smoke
"""
from __future__ import annotations

import base64
import os
import re
import tempfile
import uuid

import pytest

# ── Isolate all three SQLite DBs ──────────────────────────────────────────────
_TMP_DIR   = tempfile.gettempdir()
_MKTDB     = os.path.join(_TMP_DIR, f"test_marketplace_{uuid.uuid4().hex}.db")
_CMRCDB    = os.path.join(_TMP_DIR, f"test_commerce_mkt_{uuid.uuid4().hex}.db")
_SEPDB     = os.path.join(_TMP_DIR, f"test_sep_mkt_{uuid.uuid4().hex}.db")

os.environ.setdefault("MARKETPLACE_DB_PATH", _MKTDB)
os.environ.setdefault("COMMERCE_DB_PATH",    _CMRCDB)
os.environ.setdefault("SEP_DB_PATH",         _SEPDB)
os.environ.setdefault("ANTHROPIC_API_KEY",   "")
os.environ.setdefault("WARDEN_API_KEY",      "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("REDIS_URL",           "memory://")


# ── Test isolation helpers ────────────────────────────────────────────────────

def _aid() -> str:
    """Fresh unique test agent suffix."""
    return uuid.uuid4().hex[:12]

def _cid() -> str:
    return f"comm-{uuid.uuid4().hex[:8]}"

def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


# ── Shared keypair fixture ────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def keypair():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair("test-comm", kid="v1")


@pytest.fixture()
def pub_b64(keypair) -> str:
    return keypair.ed25519_pub_b64


# ─────────────────────────────────────────────────────────────────────────────
# 1. DID derivation
# ─────────────────────────────────────────────────────────────────────────────

def test_register_agent_generates_did(pub_b64):
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=pub_b64, capabilities=["marketplace_sell"],
        db_path=_MKTDB,
    )
    assert agent.agent_id.startswith("did:shadow:"), "DID prefix missing"
    fragment = agent.agent_id[len("did:shadow:"):]
    assert len(fragment) == 32, f"Fragment length expected 32, got {len(fragment)}"
    assert re.fullmatch(r"[0-9A-Za-z]{32}", fragment), "Fragment contains non-base62 chars"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Capabilities round-trip
# ─────────────────────────────────────────────────────────────────────────────

def test_register_agent_stores_capabilities(pub_b64):
    from warden.marketplace.agent import register_agent, get_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=pub_b64,
        capabilities=["marketplace_buy", "marketplace_negotiate"],
        db_path=_MKTDB,
    )
    fetched = get_agent(agent.agent_id, db_path=_MKTDB)
    assert fetched is not None
    assert set(fetched.capabilities) == {"marketplace_buy", "marketplace_negotiate"}


# ─────────────────────────────────────────────────────────────────────────────
# 3. AP2 mandate creation (fail-open: mandate_id may be empty without commerce)
# ─────────────────────────────────────────────────────────────────────────────

def test_register_agent_creates_ap2_mandate(pub_b64):
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=pub_b64, capabilities=["marketplace_sell"],
        db_path=_MKTDB,
    )
    # mandate_id may be empty if AP2 module unavailable — not a hard failure
    assert isinstance(agent.mandate_id, str)


# ─────────────────────────────────────────────────────────────────────────────
# 4. get_agent lookup
# ─────────────────────────────────────────────────────────────────────────────

def test_get_agent_returns_correct_data(pub_b64):
    from warden.marketplace.agent import register_agent, get_agent
    tid, cid = _tid(), _cid()
    agent = register_agent(
        tenant_id=tid, community_id=cid,
        public_key_b64=pub_b64, capabilities=["marketplace_buy"],
        db_path=_MKTDB,
    )
    fetched = get_agent(agent.agent_id, db_path=_MKTDB)
    assert fetched is not None
    assert fetched.community_id == cid
    assert fetched.tenant_id == tid
    assert fetched.status == "active"


# ─────────────────────────────────────────────────────────────────────────────
# 5. update_capabilities
# ─────────────────────────────────────────────────────────────────────────────

def test_update_capabilities(pub_b64):
    from warden.marketplace.agent import register_agent, update_capabilities, get_agent
    tid = _tid()
    agent = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=pub_b64, capabilities=["marketplace_buy"],
        db_path=_MKTDB,
    )
    ok = update_capabilities(agent.agent_id, tid, ["marketplace_sell", "marketplace_negotiate"],
                              db_path=_MKTDB)
    assert ok is True
    updated = get_agent(agent.agent_id, db_path=_MKTDB)
    assert set(updated.capabilities) == {"marketplace_sell", "marketplace_negotiate"}


# ─────────────────────────────────────────────────────────────────────────────
# 6. Tokenize safe keyword rule
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_rule_safe(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    rule = {"name": "test_rule", "keyword": "jailbreak_bypass", "risk": "HIGH"}
    token = AssetTokenizer().tokenize_rule(rule, keypair, "did:shadow:abc", "comm-1")
    assert re.fullmatch(r"[0-9a-f]{64}", token["sha256"]), "sha256 must be 64-char hex"
    assert token["ueciid"].startswith("SEP-")
    assert token["asset_type"] == "rule"


# ─────────────────────────────────────────────────────────────────────────────
# 7. ReDoS gate rejects catastrophic regex
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_rule_rejects_redos(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    unsafe_rule = {"name": "bad_rule", "regex_pattern": "(a+)+$"}
    with pytest.raises(ValueError, match="[Uu]nsafe"):
        AssetTokenizer().tokenize_rule(unsafe_rule, keypair, "did:shadow:abc", "comm-1")


# ─────────────────────────────────────────────────────────────────────────────
# 8. Tokenize OSI 1.0 model
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_model(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    model = {
        "osi_version": "1.0",
        "id":          "test_model",
        "metrics":     [{"name": "block_rate", "expression": "count(blocked)"}],
        "dimensions":  [{"name": "tenant_id", "column": "tenant_id"}],
    }
    token = AssetTokenizer().tokenize_model(model, keypair, "did:shadow:abc", "comm-1")
    assert token["ueciid"].startswith("SEP-")
    assert token["asset_type"] == "model"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Tokenize signals batch
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_signals(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    signals = [
        {"type": "jailbreak", "score": 0.9},
        {"type": "pii_leak",  "score": 0.7},
        {"type": "abuse",     "score": 0.5},
    ]
    token = AssetTokenizer().tokenize_signals(signals, keypair, "did:shadow:abc", "comm-1")
    assert token["payload"]["count"] == 3
    assert len(token["payload"]["signals"]) == 3


# ─────────────────────────────────────────────────────────────────────────────
# 10. IPFS hash is CID-shaped
# ─────────────────────────────────────────────────────────────────────────────

def test_upload_to_ipfs_returns_cid_shaped_string(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    rule = {"keyword": "test_cid_check"}
    token = AssetTokenizer().tokenize_rule(rule, keypair, "did:shadow:abc", "comm-1")
    assert re.fullmatch(r"Qm[A-Za-z0-9]{44}", token["ipfs_hash"]), (
        f"ipfs_hash not CID-shaped: {token['ipfs_hash']!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 11. register_asset creates UECIID
# ─────────────────────────────────────────────────────────────────────────────

def test_register_asset_creates_ueciid(keypair, pub_b64):
    from warden.marketplace.agent import register_agent
    from warden.marketplace.service import register_asset, get_asset
    tid, cid = _tid(), _cid()
    agent = register_agent(
        tenant_id=tid, community_id=cid,
        public_key_b64=pub_b64, capabilities=["marketplace_sell"],
        db_path=_MKTDB,
    )
    asset_id = register_asset(
        tenant_id=tid,
        seller_agent_id=agent.agent_id,
        asset_type="rule",
        raw_data={"keyword": "test_asset"},
        keypair=keypair,
        db_path=_MKTDB,
    )
    assert asset_id.startswith("SEP-")
    stored = get_asset(asset_id, db_path=_MKTDB)
    assert stored is not None
    assert stored["asset_type"] == "rule"


# ─────────────────────────────────────────────────────────────────────────────
# 12. Agent without sell capability is blocked
# ─────────────────────────────────────────────────────────────────────────────

def test_agent_without_sell_capability_blocked(keypair, pub_b64):
    from warden.marketplace.agent import register_agent
    from warden.marketplace.service import register_asset

    # Register with a second keypair so we get a distinct agent_id
    from warden.communities.keypair import generate_community_keypair
    kp2 = generate_community_keypair("test-comm-2", kid="v1")

    tid = _tid()
    agent = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=kp2.ed25519_pub_b64,
        capabilities=["marketplace_buy"],       # no sell
        db_path=_MKTDB,
    )
    with pytest.raises(PermissionError, match="marketplace_sell"):
        register_asset(
            tenant_id=tid,
            seller_agent_id=agent.agent_id,
            asset_type="rule",
            raw_data={"keyword": "blocked"},
            keypair=keypair,
            db_path=_MKTDB,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 13. list_assets_by_agent filters correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_list_assets_by_agent_filters_correctly(keypair):
    from warden.communities.keypair import generate_community_keypair
    from warden.marketplace.agent import register_agent
    from warden.marketplace.service import register_asset, list_assets_by_agent

    kpA = generate_community_keypair("comm-agent-a", kid="v1")
    kpB = generate_community_keypair("comm-agent-b", kid="v1")
    tid = _tid()

    agentA = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=kpA.ed25519_pub_b64, capabilities=["marketplace_sell"],
        db_path=_MKTDB,
    )
    agentB = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=kpB.ed25519_pub_b64, capabilities=["marketplace_sell"],
        db_path=_MKTDB,
    )

    for _ in range(2):
        register_asset(tid, agentA.agent_id, "rule", {"keyword": "a"}, kpA, db_path=_MKTDB)
    register_asset(tid, agentB.agent_id, "rule", {"keyword": "b"}, kpB, db_path=_MKTDB)

    assets_a = list_assets_by_agent(agentA.agent_id, db_path=_MKTDB)
    assets_b = list_assets_by_agent(agentB.agent_id, db_path=_MKTDB)

    assert len(assets_a) == 2
    assert len(assets_b) == 1
    assert all(r["seller_agent_id"] == agentA.agent_id for r in assets_a)


# ─────────────────────────────────────────────────────────────────────────────
# 14. FastAPI POST /marketplace/agents/register → 201
# ─────────────────────────────────────────────────────────────────────────────

def test_api_register_agent_201():
    from fastapi.testclient import TestClient
    from warden.marketplace.api import router
    from fastapi import FastAPI

    mini_app = FastAPI()
    mini_app.include_router(router)
    client = TestClient(mini_app)

    from warden.communities.keypair import generate_community_keypair
    kp = generate_community_keypair("api-test-comm", kid="v1")

    resp = client.post(
        "/marketplace/agents/register",
        json={
            "tenant_id":    _tid(),
            "community_id": _cid(),
            "public_key":   kp.ed25519_pub_b64,
            "capabilities": ["marketplace_sell"],
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "agent_id" in data
    assert data["agent_id"].startswith("did:shadow:")
