"""
R8.3 - a product's GS1 GTIN: shape and check digit, one product per number per
seller, and the number on the public storefront feed.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from warden.m2m_store import gtin
from warden.m2m_store.tests.test_m2m_store_m5 import API, _shop, _token

# Real, published check digits: EAN-13, UPC-A, EAN-8, GTIN-14.
VALID = ["4006381333931", "036000291452", "96385074", "10614141000415"]


@pytest.mark.parametrize("number", VALID)
def test_valid_numbers_pass(number):
    assert gtin.normalize(number) == number


def test_separators_are_dropped_and_empty_means_none():
    assert gtin.normalize("400-6381 333931") == "4006381333931"
    assert gtin.normalize("") == "" and gtin.normalize("  ") == ""


@pytest.mark.parametrize("bad", [
    "4006381333932",       # wrong check digit
    "400638133393",        # 12 digits, but not a valid UPC-A
    "12345",               # wrong length
    "40063813339A1",       # a letter
    "４００６３８１３３３９３１",  # full-width digits are not ASCII
    "0000000000000",       # all zeros has a valid check digit and is still not a number
])
def test_invalid_numbers_are_refused(bad):
    with pytest.raises(gtin.GtinError):
        gtin.normalize(bad)


def test_kind_names_the_symbology():
    assert [gtin.kind(n) for n in VALID] == ["EAN-13", "UPC-A", "EAN-8", "ITF-14"]


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


def _product(client, h, sid, **extra):
    return client.post(f"{API}/products", headers=h,
                       json={"store_id": sid, "name": "Paint", "price_base": 5, "stock": 1} | extra)


def test_a_product_keeps_its_gtin_and_the_storefront_shows_it(client):
    sid, _pids, h = _shop(client)
    r = _product(client, h, sid, gtin="400 6381 333931")
    assert r.status_code == 201, r.text
    feed = client.get(f"{API}/storefront/acme/catalog/ucp").json()
    assert [p["gtin"] for p in feed["products"] if p["id"] == r.json()["id"]] == ["4006381333931"]


def test_a_bad_check_digit_is_a_422(client):
    sid, _pids, h = _shop(client)
    r = _product(client, h, sid, gtin="4006381333932")
    assert r.status_code == 422
    assert "check digit" in r.text


def test_one_number_names_one_product_per_seller(client):
    sid, _pids, h = _shop(client)
    first = _product(client, h, sid, gtin="4006381333931").json()["id"]
    assert _product(client, h, sid, gtin="4006381333931").status_code == 409
    # Saving the same product again with its own number is not a clash.
    again = _product(client, h, sid, id=first, gtin="4006381333931")
    assert again.status_code == 201, again.text
    # Another seller may list the same item: resellers share manufacturer GTINs.
    other = _token("other")
    osid = client.post(f"{API}/stores", headers=other, json={
        "slug": "other", "name": "Other", "default_currency": "USD", "currencies": ["USD"]}).json()["id"]
    assert _product(client, other, osid, gtin="4006381333931").status_code == 201
