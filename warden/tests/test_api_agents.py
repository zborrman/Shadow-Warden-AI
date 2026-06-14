"""
warden/tests/test_api_agents.py
────────────────────────────────
6 tests for api_agents.py — agent DID registration, CRUD, capabilities.

Mirrors: warden/marketplace/api_agents.py
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid

import pytest

_TMP    = tempfile.gettempdir()
_DB     = os.path.join(_TMP, f"test_api_agents_{uuid.uuid4().hex}.db")
_CMRCDB = os.path.join(_TMP, f"test_commerce_agents_{uuid.uuid4().hex}.db")
_SEPDB  = os.path.join(_TMP, f"test_sep_agents_{uuid.uuid4().hex}.db")

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
    return generate_community_keypair("agents-test-comm", kid="v1")


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
        db_path=_DB,
    )
    assert agent.agent_id.startswith("did:shadow:")
    fragment = agent.agent_id[len("did:shadow:"):]
    assert len(fragment) == 32
    assert re.fullmatch(r"[0-9A-Za-z]{32}", fragment)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Capabilities round-trip
# ─────────────────────────────────────────────────────────────────────────────

def test_register_agent_stores_capabilities(pub_b64):
    from warden.marketplace.agent import get_agent, register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=pub_b64,
        capabilities=["marketplace_buy", "marketplace_negotiate"],
        db_path=_DB,
    )
    fetched = get_agent(agent.agent_id, db_path=_DB)
    assert fetched is not None
    assert set(fetched.capabilities) == {"marketplace_buy", "marketplace_negotiate"}


# ─────────────────────────────────────────────────────────────────────────────
# 3. AP2 mandate (fail-open: mandate_id may be empty without commerce module)
# ─────────────────────────────────────────────────────────────────────────────

def test_register_agent_creates_ap2_mandate(pub_b64):
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=pub_b64, capabilities=["marketplace_sell"],
        db_path=_DB,
    )
    assert isinstance(agent.mandate_id, str)


# ─────────────────────────────────────────────────────────────────────────────
# 4. get_agent lookup
# ─────────────────────────────────────────────────────────────────────────────

def test_get_agent_returns_correct_data(pub_b64):
    from warden.marketplace.agent import get_agent, register_agent
    tid, cid = _tid(), _cid()
    agent = register_agent(
        tenant_id=tid, community_id=cid,
        public_key_b64=pub_b64, capabilities=["marketplace_buy"],
        db_path=_DB,
    )
    fetched = get_agent(agent.agent_id, db_path=_DB)
    assert fetched is not None
    assert fetched.community_id == cid
    assert fetched.tenant_id == tid
    assert fetched.status == "active"


# ─────────────────────────────────────────────────────────────────────────────
# 5. update_capabilities persists change
# ─────────────────────────────────────────────────────────────────────────────

def test_update_capabilities(pub_b64):
    from warden.marketplace.agent import get_agent, register_agent, update_capabilities
    tid = _tid()
    agent = register_agent(
        tenant_id=tid, community_id=_cid(),
        public_key_b64=pub_b64, capabilities=["marketplace_buy"],
        db_path=_DB,
    )
    ok = update_capabilities(
        agent.agent_id, tid,
        ["marketplace_sell", "marketplace_negotiate"],
        db_path=_DB,
    )
    assert ok is True
    updated = get_agent(agent.agent_id, db_path=_DB)
    assert set(updated.capabilities) == {"marketplace_sell", "marketplace_negotiate"}


# ─────────────────────────────────────────────────────────────────────────────
# 6. FastAPI POST /marketplace/agents/register → 201
# ─────────────────────────────────────────────────────────────────────────────

def test_api_register_agent_201():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.api import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    from warden.communities.keypair import generate_community_keypair
    kp = generate_community_keypair("api-agents-test", kid="v1")

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
