"""
Closing a seller's account: the export holds everything, the purge leaves no
personal data and no catalog, and another seller's store is untouched.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from warden.m2m_store import closure
from warden.m2m_store.tests.test_m2m_store_m5 import API, CONTACT, _request, _shop, _token


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("M2M_STORE_DB_PATH", str(tmp_path / "m2m.db"))
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


def _seller_with_a_customer(client):
    sid, pids, h = _shop(client)
    assert _request(client, pids).status_code == 201
    cid = client.get(f"{API}/stores/{sid}/customers", headers=h).json()[0]["id"]
    client.post(f"{API}/stores/{sid}/customers/{cid}/journal", headers=h,
                json={"kind": "note", "body": "Prefers mornings"})
    return sid, pids, h


def _count(sql, *args):
    from warden.m2m_store.inventory import _conn
    with _conn() as con:
        return con.execute(sql, args).fetchone()[0]


def test_the_export_holds_catalog_orders_customers_and_journal(client):
    _seller_with_a_customer(client)
    data = closure.export_tenant("seller")
    (store,) = data["stores"]
    assert store["slug"] == "acme"
    assert {p["name"] for p in store["products"]} == {"Cheese", "Tea"}
    assert len(store["order_requests"]) == 1
    (customer,) = store["customers"]
    assert customer["contact"]["email"] == CONTACT["email"]
    assert [e["body"] for e in customer["journal"]] == ["Prefers mornings"]
    assert store["shipping_zones"]


def test_the_purge_removes_every_trace_but_keeps_the_slug_reserved(client):
    sid, _pids, h = _seller_with_a_customer(client)
    # A second seller who must come through untouched.
    other = _token("other")
    osid = client.post(f"{API}/stores", headers=other, json={
        "slug": "other", "name": "Other", "default_currency": "USD", "currencies": ["USD"]}).json()["id"]
    client.post(f"{API}/products", headers=other, json={"store_id": osid, "name": "Kept", "price_base": 1})

    removed = closure.purge_tenant("seller")
    assert removed["products"] == 2 and removed["order_requests"] == 1 and removed["customers"] == 1

    for sql in ("SELECT COUNT(*) FROM m2m_order_requests WHERE seller_tenant_id=?",
                "SELECT COUNT(*) FROM m2m_customers WHERE seller_tenant_id=?",
                "SELECT COUNT(*) FROM m2m_customer_journal WHERE seller_tenant_id=?",
                "SELECT COUNT(*) FROM m2m_shipping_zones WHERE tenant_id=?",
                "SELECT COUNT(*) FROM m2m_products WHERE json_extract(data_json,'$.tenant_id')=?"):
        assert _count(sql, "seller") == 0, sql
    assert _count("SELECT COUNT(*) FROM m2m_customer_orders") == 0
    # The store row stays, empty and deleted, so the address stays reserved.
    assert _count("SELECT COUNT(*) FROM m2m_stores WHERE tenant_id=? AND deleted_at<>'' AND name=''",
                  "seller") == 1
    assert client.get(f"{API}/storefront/acme").status_code == 404
    again = client.post(f"{API}/stores", headers=other, json={
        "slug": "acme", "name": "Squatter", "default_currency": "USD", "currencies": ["USD"]})
    assert again.status_code == 409
    # The other seller still has its store and product.
    assert _count("SELECT COUNT(*) FROM m2m_products WHERE json_extract(data_json,'$.tenant_id')=?",
                  "other") == 1
    assert client.get(f"{API}/storefront/other").status_code == 200


def test_an_empty_tenant_purges_cleanly():
    assert sum(closure.purge_tenant("nobody").values()) == 0
    assert closure.export_tenant("nobody")["stores"] == []
