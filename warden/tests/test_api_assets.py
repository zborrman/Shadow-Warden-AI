"""
warden/tests/test_api_assets.py
────────────────────────────────
8 tests for api_assets.py — asset tokenization, registry, capability gate.

Mirrors: warden/marketplace/api_assets.py
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid

import pytest

_TMP    = tempfile.gettempdir()
_DB     = os.path.join(_TMP, f"test_api_assets_{uuid.uuid4().hex}.db")
_CMRCDB = os.path.join(_TMP, f"test_commerce_assets_{uuid.uuid4().hex}.db")
_SEPDB  = os.path.join(_TMP, f"test_sep_assets_{uuid.uuid4().hex}.db")

os.environ.setdefault("MARKETPLACE_DB_PATH", _DB)
os.environ.setdefault("COMMERCE_DB_PATH",    _CMRCDB)
os.environ.setdefault("SEP_DB_PATH",         _SEPDB)


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"

def _cid() -> str:
    return f"comm-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def keypair():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair("assets-test-comm", kid="v1")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Tokenize safe keyword rule
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_rule_safe(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    rule = {"name": "test_rule", "keyword": "jailbreak_bypass", "risk": "HIGH"}
    token = AssetTokenizer().tokenize_rule(rule, keypair, "did:shadow:abc", "comm-1")
    assert re.fullmatch(r"[0-9a-f]{64}", token["sha256"])
    assert token["ueciid"].startswith("SEP-")
    assert token["asset_type"] == "rule"


# ─────────────────────────────────────────────────────────────────────────────
# 2. ReDoS gate rejects catastrophic regex
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_rule_rejects_redos(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    with pytest.raises(ValueError, match="[Uu]nsafe"):
        AssetTokenizer().tokenize_rule(
            {"name": "bad", "regex_pattern": "(a+)+$"},
            keypair, "did:shadow:abc", "comm-1",
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Tokenize OSI 1.0 model
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize_model(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    model = {
        "osi_version": "1.0",
        "id":          "test_model",
        "metrics":     [{"name": "block_rate", "expression": "count(blocked)"}],
        "dimensions":  [{"name": "tenant_id",  "column": "tenant_id"}],
    }
    token = AssetTokenizer().tokenize_model(model, keypair, "did:shadow:abc", "comm-1")
    assert token["ueciid"].startswith("SEP-")
    assert token["asset_type"] == "model"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Tokenize signals batch
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
# 5. IPFS hash is CID-shaped
# ─────────────────────────────────────────────────────────────────────────────

def test_upload_to_ipfs_returns_cid_shaped_string(keypair):
    from warden.marketplace.tokenizer import AssetTokenizer
    token = AssetTokenizer().tokenize_rule(
        {"keyword": "test_cid"}, keypair, "did:shadow:abc", "comm-1"
    )
    assert re.fullmatch(r"Qm[A-Za-z0-9]{44}", token["ipfs_hash"]), token["ipfs_hash"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. register_asset creates UECIID
# ─────────────────────────────────────────────────────────────────────────────

def test_register_asset_creates_ueciid(keypair):
    from warden.communities.keypair import generate_community_keypair
    from warden.marketplace.agent import register_agent
    from warden.marketplace.service import get_asset, register_asset

    kp = generate_community_keypair("reg-asset-comm", kid="v1")
    tid, cid = _tid(), _cid()
    agent = register_agent(
        tenant_id=tid, community_id=cid,
        public_key_b64=kp.ed25519_pub_b64, capabilities=["marketplace_sell"],
        db_path=_DB,
    )
    asset_id = register_asset(
        tenant_id=tid,
        seller_agent_id=agent.agent_id,
        asset_type="rule",
        raw_data={"keyword": "test_asset"},
        keypair=kp,
        db_path=_DB,
    )
    assert asset_id.startswith("SEP-")
    stored = get_asset(asset_id, db_path=_DB)
    assert stored is not None
    assert stored["asset_type"] == "rule"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Agent without marketplace_sell is blocked
# ─────────────────────────────────────────────────────────────────────────────

def test_agent_without_sell_capability_blocked(keypair):
    from warden.communities.keypair import generate_community_keypair
    from warden.marketplace.agent import register_agent
    from warden.marketplace.service import register_asset

    kp = generate_community_keypair("no-sell-comm", kid="v1")
    tid = _tid()
    agent = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=kp.ed25519_pub_b64,
        capabilities=["marketplace_buy"],
        db_path=_DB,
    )
    with pytest.raises(PermissionError, match="marketplace_sell"):
        register_asset(
            tenant_id=tid,
            seller_agent_id=agent.agent_id,
            asset_type="rule",
            raw_data={"keyword": "blocked"},
            keypair=keypair,
            db_path=_DB,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 8. list_assets_by_agent filters by seller
# ─────────────────────────────────────────────────────────────────────────────

def test_list_assets_by_agent_filters_correctly():
    from warden.communities.keypair import generate_community_keypair
    from warden.marketplace.agent import register_agent
    from warden.marketplace.service import list_assets_by_agent, register_asset

    kp_a = generate_community_keypair(f"filter-a-{uuid.uuid4().hex[:4]}", kid="v1")
    kp_b = generate_community_keypair(f"filter-b-{uuid.uuid4().hex[:4]}", kid="v1")
    tid  = _tid()

    agent_a = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=kp_a.ed25519_pub_b64, capabilities=["marketplace_sell"],
        db_path=_DB,
    )
    agent_b = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=kp_b.ed25519_pub_b64, capabilities=["marketplace_sell"],
        db_path=_DB,
    )

    for _ in range(2):
        register_asset(tid, agent_a.agent_id, "rule", {"keyword": "a"}, kp_a, db_path=_DB)
    register_asset(tid, agent_b.agent_id, "rule", {"keyword": "b"}, kp_b, db_path=_DB)

    assets_a = list_assets_by_agent(agent_a.agent_id, db_path=_DB)
    assets_b = list_assets_by_agent(agent_b.agent_id, db_path=_DB)

    assert len(assets_a) == 2
    assert len(assets_b) == 1
    assert all(r["seller_agent_id"] == agent_a.agent_id for r in assets_a)
