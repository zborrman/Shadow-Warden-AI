"""
warden/m2m_store/tests/test_m2m_store_m5.py
────────────────────────────────────────────
Plan stage M5: an agent's order needs the buyer's passkey on that one offer,
and a human buyer's order request is repriced, sealed and answered by the
seller. The passkey here is a real P-256 key signing real WebAuthn bytes, so
the verifier under test is py_webauthn itself, not a mock of it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")

API = "/m2m-store"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("M2M_STORE_DB_PATH", str(tmp_path / "m2m.db"))
    monkeypatch.setenv("FIDO_DB_PATH", str(tmp_path / "fido.db"))
    monkeypatch.delenv("FIDO_ALLOW_STUB", raising=False)
    import warden.auth.fido as fido
    monkeypatch.setattr(fido, "_DB_PATH", str(tmp_path / "fido.db"))
    from warden.limiter import limiter
    monkeypatch.setattr(limiter, "enabled", False)
    from warden.m2m_store import inventory as inv_mod
    inv_mod._inventory = inv_mod.InventoryManager()
    yield
    from warden.db.connect import close_cached_connections
    close_cached_connections()


@pytest.fixture
def client():
    from warden.auth_guard import AuthResult, require_api_key
    from warden.m2m_store.api import router

    app = FastAPI()
    app.include_router(router)

    def _auth(request: Request) -> AuthResult:
        return AuthResult(api_key="k", tenant_id=request.headers.get("X-Test-Tenant", "buyer"))

    app.dependency_overrides[require_api_key] = _auth
    return TestClient(app)


@pytest.fixture
def paid(monkeypatch):
    calls: list = []

    def _pay(self, **kw):
        calls.append(kw)
        return {"success": True, "transaction_id": "tx-1"}

    from warden.business_community.agentic_commerce import ap2
    monkeypatch.setattr(ap2.AP2Processor, "execute_payment", _pay)
    return calls


def _token(tenant: str) -> dict:
    from warden.portal_router import _issue_access_token
    return {"Authorization": f"Bearer {_issue_access_token('u-' + tenant, tenant, 'owner')}"}


# ── A passkey ─────────────────────────────────────────────────────────────────

class Passkey:
    """A software authenticator: P-256, user present + verified, counter 0."""

    def __init__(self, tenant: str) -> None:
        import warden.auth.fido as fido
        self.key = ec.generate_private_key(ec.SECP256R1())
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"),
                            -3: nums.y.to_bytes(32, "big")})
        self.cred_id = _b64(os.urandom(16))
        self.rp_id, self.origin = fido._RP_ID, fido._ORIGIN
        fido.FIDOProvider()._store_credential(tenant, self.cred_id,
                                              base64.b64encode(cose).decode(), 0)

    def sign(self, challenge: str, origin: str | None = None) -> dict:
        client_data = json.dumps({"type": "webauthn.get", "challenge": challenge,
                                  "origin": origin or self.origin, "crossOrigin": False}).encode()
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + b"\x05" + (0).to_bytes(4, "big")
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": self.cred_id, "rawId": self.cred_id, "type": "public-key",
                "response": {"authenticatorData": _b64(auth_data), "clientDataJSON": _b64(client_data),
                             "signature": _b64(sig)},
                "clientExtensionResults": {}}


def _offer(client, tenant="buyer"):
    seller = {"X-Test-Tenant": "seller"}
    pid = client.post(f"{API}/products", json={"name": "Widget", "price_base": 10, "stock": 5},
                      headers=seller).json()["id"]
    r = client.post(f"{API}/offers", json={"product_id": pid, "qty": 1, "agent_id": "bot"},
                    headers={"X-Test-Tenant": tenant})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _approve(client, key: Passkey, offer_id: str, tenant="buyer") -> str:
    r = client.post(f"{API}/offers/{offer_id}/challenge", headers={"X-Test-Tenant": tenant})
    assert r.status_code == 200, r.text
    opts = r.json()
    assert {"id": key.cred_id, "type": "public-key"} in opts["allowCredentials"]
    return json.dumps(key.sign(opts["challenge"]))


def _order(client, offer_id, token, tenant="buyer"):
    return client.post(f"{API}/orders", headers={"X-Test-Tenant": tenant},
                       json={"offer_id": offer_id, "mandate_id": "m-1", "payment_token": token})


# ── Agent orders: the passkey check is real ───────────────────────────────────

def test_a_real_passkey_approval_places_the_order(client, paid):
    key = Passkey("buyer")
    offer = _offer(client)
    r = _order(client, offer, _approve(client, key, offer))
    assert r.status_code == 201, r.text
    assert len(paid) == 1


def test_an_approval_cannot_be_replayed(client, paid):
    from warden.auth.fido import FIDOProvider
    key = Passkey("buyer")
    opts = FIDOProvider().issue_bound_challenge("buyer", "m2m_order:o-1")
    assertion = key.sign(opts["challenge"])
    assert FIDOProvider().verify_bound("buyer", "m2m_order:o-1", assertion)["verified"] is True
    # The counter stays at 0, so only the consumed challenge stops a replay.
    assert FIDOProvider().verify_bound("buyer", "m2m_order:o-1", assertion) == \
        {"verified": False, "reason": "no_challenge"}


def test_an_approval_of_one_offer_does_not_buy_another(client, paid):
    key = Passkey("buyer")
    first, second = _offer(client), _offer(client)
    r = _order(client, second, _approve(client, key, first))
    assert r.status_code == 401
    assert paid == []


def test_another_tenants_passkey_does_not_approve(client, paid):
    Passkey("buyer")
    stranger = Passkey("stranger")
    offer = _offer(client)
    r = client.post(f"{API}/offers/{offer}/challenge", headers={"X-Test-Tenant": "buyer"})
    r = _order(client, offer, json.dumps(stranger.sign(r.json()["challenge"])))
    assert r.status_code == 401
    assert paid == []


def test_a_forged_signature_or_foreign_origin_is_refused(client, paid):
    from warden.auth.fido import FIDOProvider
    key = Passkey("buyer")
    p = FIDOProvider()
    bad = key.sign(p.issue_bound_challenge("buyer", "x")["challenge"])
    bad["response"]["signature"] = _b64(b"\x30\x06\x02\x01\x01\x02\x01\x01")
    assert p.verify_bound("buyer", "x", bad)["verified"] is False
    phished = key.sign(p.issue_bound_challenge("buyer", "x")["challenge"], origin="https://evil.example")
    assert p.verify_bound("buyer", "x", phished)["verified"] is False


def test_an_old_challenge_has_expired(client, paid, tmp_path):
    from warden.auth.fido import FIDOProvider
    key = Passkey("buyer")
    opts = FIDOProvider().issue_bound_challenge("buyer", "x")
    from warden.auth.fido import _conn
    with _conn() as con:
        con.execute("UPDATE fido_challenges SET created_at='2020-01-01T00:00:00+00:00'")
    assert FIDOProvider().verify_bound("buyer", "x", key.sign(opts["challenge"]))["reason"] == "no_challenge"


def test_a_registered_credential_is_stored_under_the_id_assertions_use(monkeypatch):
    import webauthn

    from warden.auth.fido import FIDOProvider

    class _Result:
        credential_id = b"\x01\x02\x03"
        credential_public_key = b"cose"
        sign_count = 0

    monkeypatch.setattr(webauthn, "verify_registration_response", lambda **kw: _Result())
    monkeypatch.setattr("webauthn.helpers.parse_registration_credential_json", lambda raw: object())
    p = FIDOProvider()
    p.generate_registration_options("t-reg", "Seller")
    assert p.verify_registration("t-reg", {"id": "x"})["credential_id"] == "AQID"
    assert [c["credential_id"] for c in p.list_credentials("t-reg")] == ["AQID"]


def test_the_payment_chokepoint_can_refuse_an_order(client, paid, monkeypatch):
    from warden.payments.authorize import AuthorizationResult
    monkeypatch.setattr("warden.payments.authorize.authorize_payment",
                        lambda *a, **kw: AuthorizationResult(verdict="DENY", reasons=["policy"]))
    key = Passkey("buyer")
    offer = _offer(client)
    r = _order(client, offer, _approve(client, key, offer))
    assert r.status_code == 403
    assert paid == []


# ── Human order requests ──────────────────────────────────────────────────────

def _shop(client):
    h = _token("seller")
    sid = client.post(f"{API}/stores", headers=h, json={
        "slug": "acme", "name": "Acme", "default_currency": "EUR",
        "currencies": ["USD", "EUR"]}).json()["id"]
    pids = []
    for name, eur, stock in (("Cheese", 3250, 4), ("Tea", 920, 10)):
        pid = client.post(f"{API}/products", headers=h, json={
            "store_id": sid, "name": name, "price_base": eur / 100, "stock": stock}).json()["id"]
        r = client.put(f"{API}/products/{pid}/prices", headers=h,
                       json=[{"currency": "USD", "amount_minor": eur + 200},
                             {"currency": "EUR", "amount_minor": eur}])
        assert r.status_code == 200, r.text
        pids.append(pid)
    r = client.post(f"{API}/stores/{sid}/shipping-zones", headers=h, json={
        "name": "World", "countries": ["*"], "currency": "EUR", "rate_minor": 990,
        "free_over_minor": None, "duty_estimate_bps": 1000, "min_days": 3, "max_days": 9})
    assert r.status_code == 201, r.text
    return sid, pids, h


CONTACT = {"name": "Ada Buyer", "email": "ada@example.org", "address_line1": "1 Main St",
           "city": "Lyon", "postal_code": "69001"}


def _request(client, pids, **kw):
    body = {"items": [{"product_id": pids[0], "qty": 2, "unit_minor": 1},
                      {"product_id": pids[1], "qty": 1}],
            "currency": "EUR", "country": "FR", "contact": CONTACT, "timezone": "Europe/Paris"} | kw
    return client.post(f"{API}/storefront/acme/order-requests", json=body)


def test_a_request_is_priced_by_the_server_not_the_browser(client):
    _, pids, _ = _shop(client)
    r = _request(client, pids)
    assert r.status_code == 201, r.text
    v = r.json()
    assert v["status"] == "PENDING_MERCHANT"
    assert [(i["qty"], i["unit_minor"]) for i in v["items"]] == [(2, 3250), (1, 920)]
    assert (v["subtotal_minor"], v["shipping_minor"]) == (7420, 990)
    assert v["duty_estimate_minor"] == 742 and v["duty_is_estimate"] is True
    assert v["total_minor"] == 7420 + 990          # duty is paid on import, not to the seller
    assert v["buyer_tz"] == "Europe/Paris"
    assert len(v["buyer_token"]) >= 40


def test_contact_details_are_sealed_and_never_shown_to_the_link_holder(client, tmp_path):
    _, pids, _ = _shop(client)
    v = _request(client, pids).json()
    from warden.m2m_store.inventory import _conn
    with _conn() as con:
        raw = tuple(con.execute("SELECT * FROM m2m_order_requests").fetchone())
    assert "ada@example.org" not in repr(raw) and "Ada Buyer" not in repr(raw)
    assert v["buyer_token"] not in repr(raw)
    seen = client.get(f"{API}/storefront/acme/order-requests/{v['id']}",
                      headers={"X-Order-Token": v["buyer_token"]})
    assert seen.status_code == 200
    assert "contact" not in seen.json() and "ada@example.org" not in seen.text


def test_a_wrong_or_missing_token_reads_as_no_request(client):
    _, pids, _ = _shop(client)
    v = _request(client, pids).json()
    url = f"{API}/storefront/acme/order-requests/{v['id']}"
    assert client.get(url).status_code == 404
    assert client.get(url, headers={"X-Order-Token": "x" * 43}).status_code == 404


def test_the_seller_sees_the_contact_and_no_one_else_does(client):
    sid, pids, h = _shop(client)
    _request(client, pids, note="Ring twice")
    rows = client.get(f"{API}/stores/{sid}/order-requests", headers=h).json()
    assert rows[0]["contact"]["email"] == "ada@example.org" and rows[0]["note"] == "Ring twice"
    assert client.get(f"{API}/stores/{sid}/order-requests",
                      headers=_token("other")).status_code == 404


def test_accepting_takes_the_stock_and_cancelling_returns_it(client):
    from warden.m2m_store.inventory import get_inventory
    sid, pids, h = _shop(client)
    rid = _request(client, pids).json()["id"]
    r = client.patch(f"{API}/order-requests/{rid}", headers=h, json={"status": "accepted"})
    assert r.status_code == 200 and r.json()["status"] == "ACCEPTED"
    assert get_inventory().get_product(pids[0]).stock == 2
    assert client.patch(f"{API}/order-requests/{rid}", headers=h,
                        json={"status": "ACCEPTED"}).status_code == 422
    r = client.patch(f"{API}/order-requests/{rid}", headers=h, json={"status": "CANCELLED"})
    assert r.status_code == 200
    assert get_inventory().get_product(pids[0]).stock == 4
    assert [e["status"] for e in r.json()["history"]] == ["PENDING_MERCHANT", "ACCEPTED", "CANCELLED"]


def test_accepting_without_enough_stock_takes_none_of_it(client):
    from warden.m2m_store.inventory import get_inventory
    sid, pids, h = _shop(client)
    rid = _request(client, pids, items=[{"product_id": pids[1], "qty": 3},
                                        {"product_id": pids[0], "qty": 4}]).json()["id"]
    get_inventory().update_stock(pids[0], -1)       # sold elsewhere meanwhile: 3 left
    r = client.patch(f"{API}/order-requests/{rid}", headers=h, json={"status": "ACCEPTED"})
    assert r.status_code == 409
    assert get_inventory().get_product(pids[1]).stock == 10
    assert get_inventory().get_product(pids[0]).stock == 3


def test_another_seller_cannot_answer_a_request(client):
    _, pids, _ = _shop(client)
    rid = _request(client, pids).json()["id"]
    assert client.patch(f"{API}/order-requests/{rid}", headers=_token("other"),
                        json={"status": "ACCEPTED"}).status_code == 404


def test_the_buyer_can_withdraw_only_an_unanswered_request(client):
    _, pids, h = _shop(client)
    a, b = _request(client, pids).json(), _request(client, pids).json()
    url = f"{API}/storefront/acme/order-requests/{{}}/cancel"
    r = client.post(url.format(a["id"]), headers={"X-Order-Token": a["buyer_token"]})
    assert r.status_code == 200 and r.json()["status"] == "CANCELLED"
    client.patch(f"{API}/order-requests/{b['id']}", headers=h, json={"status": "ACCEPTED"})
    r = client.post(url.format(b["id"]), headers={"X-Order-Token": b["buyer_token"]})
    assert r.status_code == 422


@pytest.mark.parametrize("change, status", [
    ({"currency": "CHF"}, 422),                                     # store does not sell in it
    ({"currency": "USD"}, 422),                                     # no USD shipping zone
    ({"items": [{"product_id": "nope", "qty": 1}]}, 422),
    ({"items": [{"product_id": "__0", "qty": 99}]}, 409),           # more than available
    ({"contact": CONTACT | {"email": "not-an-email"}}, 422),
])
def test_requests_that_cannot_be_honoured_are_refused(client, change, status):
    _, pids, _ = _shop(client)
    if "items" in change and change["items"][0]["product_id"] == "__0":
        change = {"items": [{"product_id": pids[0], "qty": 99}]}
    assert _request(client, pids, **change).status_code == status


def test_a_store_flooded_with_unanswered_requests_takes_no_more(client, monkeypatch):
    from warden.m2m_store import order_requests
    monkeypatch.setattr(order_requests, "MAX_PENDING_PER_STORE", 2)
    _, pids, _ = _shop(client)
    assert [_request(client, pids).status_code for _ in range(3)] == [201, 201, 409]


def test_no_key_no_request(client, monkeypatch):
    _, pids, _ = _shop(client)

    def _no_key(*a, **kw):
        raise RuntimeError("no master key")

    monkeypatch.setattr("warden.secret_keys.resolve_key", _no_key)
    assert _request(client, pids).status_code == 503


def test_the_seller_webhook_carries_no_personal_data(client, monkeypatch):
    sent: list = []

    async def _capture(**kw):
        sent.append(kw)

    monkeypatch.setattr("warden.webhook_dispatch.dispatch_tenant_event", _capture)
    _, pids, _ = _shop(client)
    _request(client, pids)
    assert sent and sent[0]["tenant_id"] == "seller"
    assert sent[0]["event_type"] == "m2m_store.order_request.created"
    blob = json.dumps(sent[0]["data"])
    assert "ada" not in blob.lower() and "Lyon" not in blob and "buyer_token" not in blob
