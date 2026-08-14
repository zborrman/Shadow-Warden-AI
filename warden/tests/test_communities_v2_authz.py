"""
Per-tenant AUTHORIZATION on /communities/* (vuln-0002 / CWE-639, 2026-08-14).

`communities_v2.py` authenticates every route (router-level require_api_key) but
used to discard the resolved identity — no handler bound the caller to the target
{community_id}. A Strix pentest proved a two-tenant BFLA: an authenticated
attacker (tenant-a) promoted itself to OWNER of tenant-b's community, demoted the
real owner, patched/deleted it, and read its roster.

Production runs single-key today (every caller → tenant "default"), so this was
LATENT there — but it is live the moment WARDEN_API_KEYS_PATH / multi-tenant is
enabled, which this test simulates. Each handler now calls _require_role(...) /
_require_read(...) and takes actor identity from auth.tenant_id.
"""
from __future__ import annotations

import hashlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _kh(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


@pytest.fixture
def client(monkeypatch, tmp_path):
    import warden.auth_guard as ag

    store = [
        ag._KeyEntry(key_hash=_kh("key-a"), tenant_id="tenant-a", label="", active=True),
        ag._KeyEntry(key_hash=_kh("key-b"), tenant_id="tenant-b", label="", active=True),
    ]
    monkeypatch.setattr(ag, "_VALID_KEY", "", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", str(tmp_path / "keys.json"), raising=False)
    monkeypatch.setattr(ag, "_key_store", store, raising=False)
    monkeypatch.setattr(ag, "_key_store_loaded", True, raising=False)

    dbp = str(tmp_path / "comm.db")
    import warden.communities.community_factory as cf
    import warden.communities.membership as mb
    monkeypatch.setattr(mb, "COMM_DB_PATH", dbp, raising=False)
    monkeypatch.setattr(cf, "COMM_DB_PATH", dbp, raising=False)

    from warden.api.communities_v2 import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


A = {"X-API-Key": "key-a"}  # attacker (tenant-a)
B = {"X-API-Key": "key-b"}  # victim / owner (tenant-b)


@pytest.fixture
def victim_cid(client):
    from warden.communities.community_factory import create_community
    c = create_community("Victim Corp", "confidential", "tenant-b", visibility="private")
    return c.community_id


# ── The takeover vectors from the PoC must all be blocked ──────────────────────

def test_attacker_cannot_patch_victim_community(client, victim_cid):
    r = client.patch(f"/communities/{victim_cid}", json={"name": "PWNED"}, headers=A)
    assert r.status_code == 403


def test_attacker_cannot_delete_victim_community(client, victim_cid):
    assert client.delete(f"/communities/{victim_cid}", headers=A).status_code == 403


def test_attacker_cannot_change_roles_when_not_a_member(client, victim_cid):
    r = client.put(
        f"/communities/{victim_cid}/members/whatever", json={"role": "owner"}, headers=A
    )
    assert r.status_code == 403


def test_attacker_cannot_read_private_community_analytics(client, victim_cid):
    assert client.get(f"/communities/{victim_cid}/analytics", headers=A).status_code == 403


def test_attacker_cannot_delete_via_spoofed_requester_query(client, victim_cid):
    # The old hole: DELETE trusted requester_tenant_id from the query string.
    r = client.delete(
        f"/communities/{victim_cid}?requester_tenant_id=tenant-b", headers=A
    )
    assert r.status_code == 403


def test_admin_cannot_escalate_self_to_owner(client, victim_cid):
    # Even a legitimately-added admin may not grant the owner role.
    from warden.communities.membership import add_member
    m = add_member(victim_cid, "tenant-a", role="admin")
    r = client.put(
        f"/communities/{victim_cid}/members/{m.member_id}", json={"role": "owner"},
        headers=A,
    )
    assert r.status_code == 403


# ── Legitimate owner is not locked out ─────────────────────────────────────────

def test_owner_can_patch_own_community(client, victim_cid):
    r = client.patch(f"/communities/{victim_cid}", json={"name": "Renamed"}, headers=B)
    assert r.status_code == 200


def test_tenant_can_only_list_own_memberships(client):
    assert client.get("/communities/member/tenant-b/memberships", headers=A).status_code == 403
    assert client.get("/communities/member/tenant-a/memberships", headers=A).status_code == 200
