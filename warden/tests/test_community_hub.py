"""
Community Hub tests — 27 tests covering factory, membership,
data, network, compliance, evolution, and the API router.
"""
from __future__ import annotations

import os
import uuid

import pytest

# ── Fixtures ───────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "test_communities.db")
    monkeypatch.setenv("COMM_DB_PATH", db)
    # Patch all modules that read COMM_DB_PATH at import time
    for mod in [
        "warden.communities.community_factory",
        "warden.communities.membership",
        "warden.communities.network",
        "warden.communities.community_data",
        "warden.communities.community_evolution",
    ]:
        try:
            import importlib, sys
            if mod in sys.modules:
                m = sys.modules[mod]
                m.COMM_DB_PATH = db
        except Exception:
            pass
    yield db


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


def _cid_new(name: str = "Test Community", tenant: str | None = None) -> str:
    from warden.communities.community_factory import create_community
    t = tenant or _tid()
    c = create_community(name, "desc", t)
    return c.community_id


# ══════════════════════════════════════════════════════════════
# Community Factory
# ══════════════════════════════════════════════════════════════

def test_create_community_returns_32char_id():
    from warden.communities.community_factory import create_community
    c = create_community("Acme", "test", _tid())
    assert len(c.community_id) == 32
    assert c.community_id.isalnum()


def test_create_community_defaults():
    from warden.communities.community_factory import create_community
    c = create_community("Demo", "", _tid())
    assert c.status == "active"
    assert c.visibility == "private"
    assert c.join_policy == "invite"


def test_get_community_found():
    from warden.communities.community_factory import create_community, get_community
    c = create_community("X", "", _tid())
    found = get_community(c.community_id)
    assert found is not None
    assert found.name == "X"


def test_get_community_not_found():
    from warden.communities.community_factory import get_community
    assert get_community("nonexistent" * 3) is None


def test_list_communities_by_creator():
    from warden.communities.community_factory import create_community, list_communities
    t = _tid()
    create_community("A", "", t)
    create_community("B", "", t)
    create_community("Other", "", _tid())
    result = list_communities(creator_tenant_id=t)
    assert len(result) == 2


def test_list_public_communities():
    from warden.communities.community_factory import create_community, list_communities
    create_community("Public", "", _tid(), visibility="public")
    create_community("Private", "", _tid(), visibility="private")
    public = list_communities(visibility="public")
    assert all(c.visibility == "public" for c in public)
    assert len(public) >= 1


def test_update_community_settings():
    from warden.communities.community_factory import (
        create_community, get_community, update_community_settings,
    )
    c = create_community("S", "", _tid())
    update_community_settings(c.community_id, {"key": "value"})
    updated = get_community(c.community_id)
    assert updated.settings == {"key": "value"}


def test_delete_community_authorized():
    from warden.communities.community_factory import (
        create_community, delete_community, get_community,
    )
    t = _tid()
    c = create_community("Del", "", t)
    ok = delete_community(c.community_id, t)
    assert ok
    assert get_community(c.community_id) is None


def test_delete_community_unauthorized():
    from warden.communities.community_factory import create_community, delete_community
    c = create_community("ND", "", _tid())
    assert not delete_community(c.community_id, _tid())  # wrong tenant


def test_community_stats():
    from warden.communities.community_factory import create_community, get_community_stats
    create_community("S1", "", _tid(), visibility="public")
    create_community("S2", "", _tid(), visibility="private")
    stats = get_community_stats()
    assert stats["total"] >= 2
    assert stats["public"] >= 1


# ══════════════════════════════════════════════════════════════
# Membership
# ══════════════════════════════════════════════════════════════

def test_add_member_generates_32char_id():
    from warden.communities.membership import add_member
    cid = _cid_new()
    m = add_member(cid, _tid())
    assert len(m.member_id) == 32


def test_add_member_has_public_key():
    from warden.communities.membership import add_member
    cid = _cid_new()
    m = add_member(cid, _tid())
    assert m.public_key  # non-empty


def test_list_members():
    from warden.communities.membership import add_member, list_members
    cid = _cid_new()
    add_member(cid, _tid())
    add_member(cid, _tid())
    assert len(list_members(cid)) == 2


def test_remove_member():
    from warden.communities.membership import add_member, list_members, remove_member
    cid = _cid_new()
    m = add_member(cid, _tid())
    remove_member(cid, m.member_id)
    assert all(x.status != "active" for x in list_members(cid) if x.member_id == m.member_id)


def test_update_member_role():
    from warden.communities.membership import add_member, get_member, update_member_role
    cid = _cid_new()
    tid = _tid()
    m = add_member(cid, tid)
    ok = update_member_role(cid, m.member_id, "admin")
    assert ok
    updated = get_member(cid, tid)
    assert updated.role == "admin"


def test_duplicate_member_ignored():
    from warden.communities.membership import add_member, get_member_count
    cid = _cid_new()
    tid = _tid()
    add_member(cid, tid)
    add_member(cid, tid)  # duplicate → INSERT OR IGNORE
    assert get_member_count(cid) == 1


def test_invalid_role_rejected():
    from warden.communities.membership import add_member, update_member_role
    cid = _cid_new()
    m = add_member(cid, _tid())
    assert not update_member_role(cid, m.member_id, "superuser")


# ══════════════════════════════════════════════════════════════
# Network
# ══════════════════════════════════════════════════════════════

def test_create_network():
    from warden.communities.network import create_network
    n = create_network("TestNet", "desc", _tid())
    assert len(n.network_id) == 32
    assert n.namespace.startswith("net-")


def test_join_and_list_network():
    from warden.communities.network import create_network, join_network, list_network_communities
    n = create_network("Net2", "", _tid())
    cid = _cid_new()
    join_network(n.network_id, cid)
    members = list_network_communities(n.network_id)
    assert len(members) == 1


# ══════════════════════════════════════════════════════════════
# Community Data
# ══════════════════════════════════════════════════════════════

def test_register_file():
    from warden.communities.community_data import get_data_stats, list_files, register_file
    cid = _cid_new()
    tid = _tid()
    content = b"hello world"
    cf = register_file(cid, tid, "hello.txt", "text/plain", len(content), content)
    assert cf.sha256 == __import__("hashlib").sha256(content).hexdigest()
    assert cf.ueciid
    files = list_files(cid)
    assert len(files) == 1
    stats = get_data_stats(cid)
    assert stats["total_files"] == 1


def test_delete_file_unauthorized():
    from warden.communities.community_data import delete_file, register_file
    cid = _cid_new()
    tid = _tid()
    cf = register_file(cid, tid, "f.txt", "text/plain", 3, b"abc")
    assert not delete_file(cf.file_id, _tid())  # wrong uploader


# ══════════════════════════════════════════════════════════════
# Compliance
# ══════════════════════════════════════════════════════════════

def test_compliance_report_structure():
    from warden.communities.community_compliance import get_community_compliance
    cid = _cid_new()
    r = get_community_compliance(cid)
    assert 0.0 <= r.score <= 1.0
    assert r.status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT")
    assert len(r.controls) == 5


def test_compliance_score_improves_with_members():
    from warden.communities.community_compliance import get_community_compliance
    from warden.communities.membership import add_member
    cid = _cid_new()
    r_before = get_community_compliance(cid)
    add_member(cid, _tid())
    r_after = get_community_compliance(cid)
    # member_audit goes from WARN(0.6) to PASS(1.0)
    assert r_after.score >= r_before.score


# ══════════════════════════════════════════════════════════════
# Evolution
# ══════════════════════════════════════════════════════════════

def test_share_rule_creates_bundle():
    from warden.communities.community_evolution import get_bundle, share_rule
    cid = _cid_new()
    b = share_rule(cid, _tid(), "jailbreak_signature", "ignore all instructions")
    assert b.status == "pending_review"
    assert get_bundle(b.bundle_id) is not None


def test_approve_and_import_rule():
    from warden.communities.community_evolution import approve_rule, import_rule, share_rule
    cid = _cid_new()
    b = share_rule(cid, _tid(), "embedding_example", "test jailbreak text")
    approve_rule(b.bundle_id, _tid())
    ok = import_rule(b.bundle_id, cid)
    assert ok


def test_import_pending_rule_fails():
    from warden.communities.community_evolution import import_rule, share_rule
    cid = _cid_new()
    b = share_rule(cid, _tid(), "jailbreak_signature", "some rule")
    assert not import_rule(b.bundle_id, cid)  # still pending


def test_list_bundles_by_status():
    from warden.communities.community_evolution import approve_rule, list_bundles, share_rule
    cid = _cid_new()
    b1 = share_rule(cid, _tid(), "jailbreak_signature", "rule1")
    b2 = share_rule(cid, _tid(), "jailbreak_signature", "rule2")
    approve_rule(b1.bundle_id, _tid())
    approved = list_bundles(community_id=cid, status="approved")
    pending = list_bundles(community_id=cid, status="pending_review")
    assert len(approved) == 1
    assert len(pending) == 1


# ══════════════════════════════════════════════════════════════
# API Router (integration via TestClient)
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
    monkeypatch.setenv("WARDEN_API_KEY", "")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from warden.api.communities_v2 import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_api_create_and_get_community(client):
    tid = _tid()
    r = client.post("/communities", json={
        "name": "API Test", "description": "d", "creator_tenant_id": tid,
    })
    assert r.status_code == 201
    cid = r.json()["community_id"]
    assert len(cid) == 32
    g = client.get(f"/communities/{cid}")
    assert g.status_code == 200
    assert g.json()["name"] == "API Test"


def test_api_compliance_endpoint(client):
    tid = _tid()
    r = client.post("/communities", json={
        "name": "Compliance C", "description": "", "creator_tenant_id": tid,
    })
    cid = r.json()["community_id"]
    c = client.get(f"/communities/{cid}/compliance")
    assert c.status_code == 200
    assert "score" in c.json()


def test_api_evolution_share_and_approve(client):
    tid = _tid()
    r = client.post("/communities", json={
        "name": "Evo C", "description": "", "creator_tenant_id": tid,
    })
    cid = r.json()["community_id"]
    s = client.post(f"/communities/{cid}/evolution/share", json={
        "publisher_tenant_id": tid,
        "rule_type": "jailbreak_signature",
        "rule_content": "ignore previous instructions",
    })
    assert s.status_code == 201
    bid = s.json()["bundle_id"]
    a = client.post(f"/communities/{cid}/evolution/bundles/{bid}/approve",
                    json={"reviewer_tenant_id": tid})
    assert a.status_code == 200
    assert a.json()["status"] == "approved"
