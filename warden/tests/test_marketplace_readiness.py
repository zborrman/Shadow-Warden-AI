"""
warden/tests/test_marketplace_readiness.py
────────────────────────────────────────────
Tests for GET /marketplace/readiness/{community_id}.
"""
from __future__ import annotations

import os
import uuid

import pytest

_MKT_DB  = f"/tmp/test_mkt_ready_{uuid.uuid4().hex[:8]}.db"
_COMM_DB = f"/tmp/test_comm_ready_{uuid.uuid4().hex[:8]}.db"

os.environ.setdefault("MARKETPLACE_DB_PATH", _MKT_DB)
os.environ.setdefault("COMM_DB_PATH",        _COMM_DB)
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY",         "")
os.environ.setdefault("MODEL_CACHE_DIR",         "/tmp/warden_test_models")
os.environ.setdefault("DYNAMIC_RULES_PATH",      "/tmp/warden_test_dynamic_rules.json")
os.environ.setdefault("LOGS_PATH",               "/tmp/warden_test_logs.json")
os.environ.setdefault("SEMANTIC_THRESHOLD",      "0.72")
os.environ.setdefault("STRICT_MODE",             "false")
os.environ.setdefault("REDIS_URL",               "memory://")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from warden.main import app
    return TestClient(app)


def test_readiness_unknown_community(client):
    resp = client.get("/marketplace/readiness/unknown-comm-xyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["community_exists"] is False
    assert data["ready_to_trade"] is False
    assert "community_not_found" in data["missing_requirements"]


def test_readiness_known_community_no_agents(client):
    """create_community() auto-provisions a default agent (Phase 1), so a
    freshly created community already has agents_registered=True."""
    from warden.communities.community_factory import create_community
    comm = create_community("Ready Test", "desc", f"tenant-{uuid.uuid4().hex[:8]}")

    resp = client.get(f"/marketplace/readiness/{comm.community_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["community_exists"] is True
    assert data["keypair_generated"] is True
    assert data["audit_enabled"] is True
    # Phase 1: default agent is auto-provisioned on community creation
    assert data["agents_registered"] is True
    assert data["ready_to_trade"] is True


def test_readiness_response_shape(client):
    resp = client.get("/marketplace/readiness/any-id")
    assert resp.status_code == 200
    keys = {"community_id", "community_exists", "keypair_generated",
            "audit_enabled", "agents_registered", "ready_to_trade", "missing_requirements"}
    assert keys.issubset(resp.json().keys())


def test_readiness_community_id_echoed(client):
    resp = client.get("/marketplace/readiness/echo-test-id")
    assert resp.json()["community_id"] == "echo-test-id"


def test_readiness_fully_ready(client):
    """Community created + agent registered → ready_to_trade = True."""
    from warden.communities.community_factory import create_community
    from warden.communities.keypair import generate_community_keypair

    tid  = f"tenant-{uuid.uuid4().hex[:8]}"
    comm = create_community("Full Ready", "desc", tid)

    kp = generate_community_keypair(comm.community_id, kid="v1")
    pub_b64 = kp.ed25519_pub_b64

    resp = client.post("/marketplace/agents/register", json={
        "tenant_id":    tid,
        "community_id": comm.community_id,
        "public_key":   pub_b64,
        "capabilities": ["marketplace_sell", "marketplace_buy"],
    })
    assert resp.status_code == 201

    resp2 = client.get(f"/marketplace/readiness/{comm.community_id}")
    data  = resp2.json()
    assert data["agents_registered"] is True
    assert data["ready_to_trade"] is True
    assert data["missing_requirements"] == []
