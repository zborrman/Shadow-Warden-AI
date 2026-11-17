"""
A route that acts as an agent named in the body binds that agent to the caller.

H-2 (`warden/marketplace/CLAUDE.md` rule #25): thirteen write routes took
``buyer_agent_id`` / ``seller_agent_id`` / ``agent_id`` / ``caller_did`` as text
and acted on it, so any tenant could buy, list, clear or check out *as another
tenant's agent* by naming it. ``X-Agent-ID`` was read the same way in two
places. Ownership now comes from the registries, never from the request.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import warden.auth_guard as ag
import warden.marketplace.actor_binding as ab
from warden.auth_guard import AuthResult
from warden.marketplace.actor_binding import CallerAgent

A = AuthResult(api_key="ka", tenant_id="tenant-a")
_OWNERS = {"did:a": "tenant-a", "did:b": "tenant-b"}


@pytest.fixture
def prod(monkeypatch):
    monkeypatch.setattr(ab, "tier_header_trusted", lambda: False)
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    monkeypatch.setattr(
        ab, "get_agent",
        lambda aid: SimpleNamespace(tenant_id=_OWNERS[aid]) if aid in _OWNERS else None,
    )
    monkeypatch.setattr(ab, "get_profile", lambda did: None)


def test_own_agent_binds(prod):
    assert CallerAgent(A).bind("did:a") == "did:a"


def test_another_tenants_agent_is_refused(prod):
    with pytest.raises(HTTPException) as exc:
        CallerAgent(A).bind("did:b")
    assert exc.value.status_code == 403


def test_a_kya_owner_counts_too(prod, monkeypatch):
    monkeypatch.setattr(
        ab, "get_profile", lambda did: SimpleNamespace(owner_tenant_id="tenant-b")
    )
    with pytest.raises(HTTPException):
        CallerAgent(A).bind("did:unlisted")


def test_an_unregistered_id_owns_nothing_and_passes(prod):
    assert CallerAgent(A).bind("did:nobody") == "did:nobody"
    assert CallerAgent(A).bind(None) == ""


def test_an_unreadable_registry_refuses(prod, monkeypatch):
    def boom(aid):
        raise RuntimeError("db gone")

    monkeypatch.setattr(ab, "get_agent", boom)
    with pytest.raises(HTTPException) as exc:
        CallerAgent(A).bind("did:a")
    assert exc.value.status_code == 503


def test_the_operator_acts_for_any_agent(prod, monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "adm")
    assert CallerAgent(A, "adm").bind("did:b") == "did:b"


def test_dev_mode_keeps_the_claim(prod, monkeypatch):
    monkeypatch.setattr(ab, "tier_header_trusted", lambda: True)
    assert CallerAgent(A).bind("did:b") == "did:b"


# ── end to end: the purchase that moves money ────────────────────────────────


def test_a_tenant_cannot_buy_as_another_tenants_agent(prod, monkeypatch):
    import warden.marketplace.listing as listing
    from warden.marketplace.api_listings import router

    bought: list[str] = []
    monkeypatch.setattr(
        listing, "purchase_listing",
        lambda **kw: bought.append(kw["buyer_agent_id"]) or {"purchase_id": "p1"},
    )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[ag.require_api_key] = lambda: A
    path = next(r.path for r in router.routes if getattr(r, "path", "").endswith("/purchase"))
    url = path.replace("{listing_id}", "L1")
    client = TestClient(app, raise_server_exceptions=False)
    hdr = {"Idempotency-Key": "k1"}

    resp = client.post(url, json={"buyer_agent_id": "did:b"}, headers=hdr)
    assert resp.status_code == 403, resp.text
    assert bought == []

    own = client.post(url, json={"buyer_agent_id": "did:a"}, headers={"Idempotency-Key": "k2"})
    assert own.status_code != 403, own.text
    assert bought == ["did:a"]


def test_the_analytics_header_is_bound_like_the_body(prod):
    from warden.marketplace.api import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[ag.require_api_key] = lambda: A
    path = next(r.path for r in router.routes if getattr(r, "path", "").endswith("/analytics/query"))
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(path, json={"sql": "SELECT 1"}, headers={"X-Agent-ID": "did:b"})
    assert resp.status_code == 403, resp.text
