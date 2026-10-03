"""Both registration routes onboard an agent through KYA, identically.

KYA screening used to run only on the `POST /marketplace/register` wrapper.
`POST /marketplace/agents/register` — the route the TypeScript SDK calls —
skipped it, so an SDK-registered agent got no KYA record and therefore no
autonomy policy (`screen_agent()` grants the default L2 one on VERIFIED).
Harmless while `AUTHORIZE_PAYMENT_ENFORCED` is off, which is why nothing
noticed; with it on, every purchase such an agent made is refused with
`autonomy=REQUIRE_APPROVAL`. Flipping the flag would have shipped a kill switch
for the SDK's own front door — the same defect class rule #26 closed once.
"""
from __future__ import annotations

import pytest

ROUTES = ("/marketplace/register", "/marketplace/agents/register")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setenv("REDIS_URL", "memory://")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.api import router
    from warden.marketplace.api_agents import router as agents_router

    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    app.include_router(agents_router, prefix="/marketplace")
    return TestClient(app)


def _register(client, route: str, *, headers: dict | None = None, tenant: str = "t-body"):
    from warden.communities.keypair import generate_community_keypair

    kp = generate_community_keypair("kya-routes", kid="v1")
    return client.post(route, headers=headers or {}, json={
        "tenant_id": tenant, "community_id": "c-kya-routes",
        "public_key": kp.ed25519_pub_b64, "capabilities": ["marketplace_buy"],
    }), kp


@pytest.mark.parametrize("route", ROUTES)
def test_registration_screens_the_agent(client, route):
    resp, _ = _register(client, route)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["kya_status"] == "VERIFIED"

    from warden.marketplace.kya import get_kya_status
    assert get_kya_status(body["agent_id"]) == "VERIFIED"


@pytest.mark.parametrize("route", ROUTES)
def test_a_registered_agent_can_buy_once_enforcement_is_on(client, route, monkeypatch):
    """The exit criterion: the flip must not regress the purchase path for an
    agent registered through either front door."""
    resp, _ = _register(client, route)
    agent_id = resp.json()["agent_id"]
    monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")

    from warden.marketplace.autonomy import check_action
    verdict = check_action(agent_id, "purchase", 1.0)
    assert getattr(verdict, "value", verdict) == "ALLOW", verdict


@pytest.mark.parametrize("route", ROUTES)
def test_ownership_comes_from_the_credential_on_both_routes(client, route, monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda key: "t-real" if key == "k" else None)
    resp, _ = _register(client, route, headers={"X-API-Key": "k"}, tenant="t-victim")
    assert resp.status_code == 201, resp.text

    from warden.marketplace.kya import get_kya_record
    assert get_kya_record(resp.json()["agent_id"]).owner_tenant_id == "t-real"


def test_a_re_registration_does_not_re_screen(client, monkeypatch):
    """A 409 must not reach KYA: re-running screening would re-grant a policy
    an operator had deliberately revoked."""
    resp, kp = _register(client, "/marketplace/agents/register")
    assert resp.status_code == 201

    import warden.marketplace.kya as kya
    calls: list[str] = []
    monkeypatch.setattr(kya, "screen_agent", lambda aid: calls.append(aid))

    again = client.post("/marketplace/agents/register", json={
        "tenant_id": "t-other", "community_id": "c-kya-routes",
        "public_key": kp.ed25519_pub_b64, "capabilities": ["marketplace_buy"],
    })
    assert again.status_code == 409
    assert calls == []


def test_screening_failure_still_registers_as_pending(client, monkeypatch):
    """Rule 18: KYA is fail-open at registration, on the SDK route too."""
    import warden.marketplace.kya as kya

    def boom(_aid):
        raise RuntimeError("screening backend down")

    monkeypatch.setattr(kya, "screen_agent", boom)
    resp, _ = _register(client, "/marketplace/agents/register")
    assert resp.status_code == 201
    assert resp.json()["kya_status"] == "PENDING"
