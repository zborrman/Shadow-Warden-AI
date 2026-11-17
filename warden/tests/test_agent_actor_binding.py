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


# ── a path id is a claim too (found 2026-11-17 by widening the guard) ────────


def _client(router, monkeypatch=None):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[ag.require_api_key] = lambda: A
    return TestClient(app, raise_server_exceptions=False)


def _path(router, suffix, method):
    return next(
        r.path for r in router.routes
        if getattr(r, "path", "").endswith(suffix) and method in getattr(r, "methods", set())
    )


def test_another_tenants_agent_cannot_be_set_autonomous(prod, monkeypatch):
    import warden.marketplace.autonomy as autonomy
    from warden.marketplace.api import router

    written: list[str] = []
    monkeypatch.setattr(autonomy, "set_policy", lambda p: written.append(p.agent_id) or p)
    c = _client(router)
    url = _path(router, "/autonomy/{agent_id}", "POST").replace("{agent_id}", "did:b")
    body = {"level": 3, "max_spend_usd": 1_000_000}
    assert c.post(url, json=body).status_code == 403
    assert c.delete(url).status_code == 403
    unknown = url.replace("did:b", "did:not-yet-registered")
    assert c.post(unknown, json=body).status_code == 404  # no pre-seeding
    assert written == []


def test_another_tenants_agent_cannot_be_certified_or_revoked(prod, monkeypatch):
    import warden.security.api as sec

    issued: list[str] = []
    monkeypatch.setattr(sec, "get_ca", lambda: SimpleNamespace(
        issue_agent_certificate=lambda **kw: issued.append(kw["agent_id"]) or {},
        revoke_certificate=lambda aid: issued.append("revoked:" + aid) or True,
    ))
    c = _client(sec.router)
    url = _path(sec.router, "/certificate", "POST").replace("{agent_id}", "did:b")
    assert c.post(url, json={"community_id": "c", "public_key_pem": "x"}).status_code == 403
    assert c.delete(url).status_code == 403
    assert issued == []


def test_another_tenants_agent_cannot_be_patched_or_deactivated(prod, monkeypatch):
    import warden.marketplace.agent as agent_mod
    from warden.marketplace.api_agents import router

    touched: list[str] = []
    monkeypatch.setattr(agent_mod, "update_agent", lambda aid, **kw: touched.append(aid) or True)
    monkeypatch.setattr(agent_mod, "deactivate_agent", lambda aid: touched.append(aid) or True)
    c = _client(router)
    url = _path(router, "/agents/{agent_id}", "PATCH").replace("{agent_id}", "did:b")
    assert c.patch(url, json={"budget_limit": 1e9}).status_code == 403
    assert c.delete(url).status_code == 403
    assert touched == []


def test_the_public_agent_page_hides_the_owner(prod, monkeypatch):
    from warden.marketplace.api_agents import router

    full = {"agent_id": "did:b", "tenant_id": "tenant-b", "mandate_id": "m-1", "status": "active"}
    import warden.marketplace.agent as agent_mod

    monkeypatch.setattr(agent_mod, "get_agent", lambda aid: SimpleNamespace(to_dict=lambda: dict(full)))
    app = FastAPI()
    app.include_router(router)
    url = _path(router, "/agents/{agent_id}", "GET").replace("{agent_id}", "did:b")
    body = TestClient(app).get(url).json()
    assert "tenant_id" not in body and "mandate_id" not in body
    assert body["status"] == "active"


def test_an_ap2_agent_belongs_to_its_tenant(prod, monkeypatch):
    import warden.agentic.router as ap2

    monkeypatch.setattr(ag, "tier_header_trusted", lambda: False)
    calls: list[str] = []
    reg = SimpleNamespace(
        get_agent=lambda aid: {"agent_id": aid, "tenant_id": "tenant-b"},
        update_agent=lambda aid, **kw: calls.append(aid) or {},
        revoke_agent=lambda aid: calls.append(aid) or True,
    )
    monkeypatch.setattr(ap2, "get_registry", lambda: reg)
    c = _client(ap2.router)
    url = _path(ap2.router, "/agents/{agent_id}", "PUT").replace("{agent_id}", "x1")
    assert c.put(url, json={"monthly_budget": 1e9}).status_code == 403
    assert c.delete(url).status_code == 403
    assert calls == []


def test_staff_boundaries_are_operator_only(monkeypatch):
    import warden.api.staff as staff

    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
    monkeypatch.setenv("ADMIN_KEY", "adm")
    app = FastAPI()
    app.include_router(staff.router)
    app.dependency_overrides[ag.require_api_key] = lambda: A
    for dep in staff._STAFF_GATE_DEP:
        app.dependency_overrides[dep.dependency] = lambda: None
    c = TestClient(app, raise_server_exceptions=False)
    for path in ("/staff/boundaries/support", "/staff/boundaries/support/suspend"):
        method = c.put if path.endswith("support") else c.post
        resp = method(path, json={"allowed_tools": ["*"]}) if method is c.put else method(path)
        assert resp.status_code in (401, 403), (path, resp.status_code)


# ── reads: an agent's escrows, stats, balance and audit belong to its tenant ──


def test_escrows_are_the_callers_own(prod, monkeypatch):
    import warden.marketplace.agent as agent_mod
    import warden.marketplace.escrow as escrow_mod
    from warden.marketplace.api_escrow import router

    def esc(eid, buyer):
        return SimpleNamespace(escrow_id=eid, status="FUNDED",
                               to_dict=lambda: {"escrow_id": eid, "buyer": buyer, "created_at": eid})

    book = {"did:a": [esc("e1", "did:a")], "did:b": [esc("e2", "did:b")]}
    monkeypatch.setattr(escrow_mod.EscrowService, "list_escrows",
                        lambda self, aid, role="any", limit=50: book.get(aid, []))
    monkeypatch.setattr(escrow_mod.EscrowService, "list_all_escrows",
                        lambda self, status=None, limit=50: [e for v in book.values() for e in v])
    monkeypatch.setattr(agent_mod, "list_agents",
                        lambda tenant_id=None, limit=50: [SimpleNamespace(agent_id="did:a")]
                        if tenant_id == "tenant-a" else [])
    c = _client(router)
    url = _path(router, "/escrows", "GET")
    assert [e["escrow_id"] for e in c.get(url).json()] == ["e1"]  # not the platform's
    assert c.get(url, params={"agent_id": "did:b"}).status_code == 403


def test_another_tenants_agent_audit_cannot_be_triggered(prod, monkeypatch):
    import warden.marketplace.api_maestro as mae

    ran: list[str] = []
    monkeypatch.setattr(mae, "_svc", SimpleNamespace(
        run_full_audit=lambda aid: ran.append(aid) or SimpleNamespace(
            overall_threat_level="low", to_dict=lambda: {})))
    c = _client(mae.router)
    url = _path(mae.router, "/maestro-report", "GET").replace("{agent_id}", "did:b")
    assert c.get(url).status_code == 403
    assert ran == []


def test_another_tenants_agent_stats_and_balance_are_hidden(prod, monkeypatch):
    import warden.gsam.api as gsam
    import warden.voice.api as voice

    for router, suffix in ((gsam.router, "/stats"), (voice.router, "/x402/balance/{agent_id}")):
        c = _client(router)
        url = _path(router, suffix, "GET").replace("{agent_id}", "did:b")
        assert c.get(url).status_code == 403, url
