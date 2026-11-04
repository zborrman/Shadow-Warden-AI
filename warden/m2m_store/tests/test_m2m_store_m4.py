"""
warden/m2m_store/tests/test_m2m_store_m4.py
────────────────────────────────────────────
Plan stage M4: a buyer's browser holds no API key, so the storefront reads are
anonymous. They must still show only what the seller published.
"""
from __future__ import annotations

import io
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")

API = "/m2m-store"


class _FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def head_bucket(self, **kw):
        return {}

    def put_object(self, **kw):
        self.objects[kw["Key"]] = kw["Body"]

    def get_object(self, **kw):
        return {"Body": io.BytesIO(self.objects[kw["Key"]])}

    def delete_object(self, **kw):
        self.objects.pop(kw["Key"], None)


@pytest.fixture(autouse=True)
def fresh_store(tmp_path, monkeypatch):
    monkeypatch.setenv("M2M_STORE_DB_PATH", str(tmp_path / "m2m.db"))
    from warden.m2m_store import inventory as inv_mod
    from warden.m2m_store import media

    inv_mod._inventory = inv_mod.InventoryManager()
    monkeypatch.setattr(media, "_bucket_ready", False)
    monkeypatch.setattr("warden.storage.s3.object_client", lambda: _FakeS3.shared)
    _FakeS3.shared = _FakeS3()
    yield
    from warden.db.connect import close_cached_connections
    close_cached_connections()


@pytest.fixture
def client():
    """No dependency overrides: an anonymous request is really anonymous."""
    from warden.m2m_store.api import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _token(tenant: str) -> dict:
    from warden.portal_router import _issue_access_token
    return {"Authorization": f"Bearer {_issue_access_token('u-' + tenant, tenant, 'owner')}"}


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (4, 4), (10, 200, 10)).save(buf, "PNG")
    return buf.getvalue()


def _shop(client, slug="acme", tenant="tenant-a"):
    """A store with one product that has one photo."""
    h = _token(tenant)
    store = client.post(f"{API}/stores", json={"slug": slug, "name": slug.title()}, headers=h)
    assert store.status_code == 201, store.text
    sid = store.json()["id"]
    prod = client.post(f"{API}/products",
                       json={"name": "Widget", "price_base": 10, "stock": 3, "store_id": sid},
                       headers=h)
    assert prod.status_code == 201, prod.text
    pid = prod.json()["id"]
    img = client.post(f"{API}/products/{pid}/images", content=_png(),
                      headers=h | {"Content-Type": "image/png"})
    assert img.status_code == 201, img.text
    return sid, pid, img.json()["id"], h


def test_a_buyer_reads_the_storefront_without_a_key(client):
    _shop(client)
    assert client.get(f"{API}/storefront/acme").status_code == 200
    feed = client.get(f"{API}/storefront/acme/catalog/ucp")
    assert feed.status_code == 200
    assert [p["name"] for p in feed.json()["products"]] == ["Widget"]


def test_owner_routes_stay_closed_to_an_anonymous_caller(client, monkeypatch):
    _shop(client)
    # The test env runs with no key configured (dev mode); production has one.
    monkeypatch.setattr("warden.auth_guard._VALID_KEY", "realkey")
    assert client.get(f"{API}/stores").status_code == 401
    assert client.post(f"{API}/stores", json={"slug": "x", "name": "X"}).status_code == 401


def test_the_feed_names_photos_by_the_store_address_and_they_load(client):
    _, _, image_id, _ = _shop(client)
    images = client.get(f"{API}/storefront/acme/catalog/ucp").json()["products"][0]["images"]
    assert [i["url"] for i in images] == [f"{API}/storefront/acme/images/{image_id}"]
    r = client.get(images[0]["url"])
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_a_photo_is_not_served_under_another_stores_address(client):
    _, _, image_id, _ = _shop(client, "acme", "tenant-a")
    _shop(client, "other", "tenant-b")
    assert client.get(f"{API}/storefront/other/images/{image_id}").status_code == 404


def test_a_hidden_product_or_closed_store_hides_its_photos(client):
    sid, pid, image_id, h = _shop(client)
    url = f"{API}/storefront/acme/images/{image_id}"
    assert client.get(url).status_code == 200

    hidden = client.post(f"{API}/products",
                         json={"id": pid, "name": "Widget", "price_base": 10, "stock": 3,
                               "store_id": sid, "active": False},
                         headers=h)
    assert hidden.status_code in (200, 201), hidden.text
    assert client.get(url).status_code == 404

    client.post(f"{API}/products",
                json={"id": pid, "name": "Widget", "price_base": 10, "stock": 3,
                      "store_id": sid, "active": True},
                headers=h)
    assert client.get(url).status_code == 200
    assert client.patch(f"{API}/stores/{sid}", json={"active": False}, headers=h).status_code == 200
    assert client.get(url).status_code == 404
    assert client.get(f"{API}/storefront/acme").status_code == 404


def test_the_storefront_never_shows_owner_fields(client):
    _shop(client)
    body = client.get(f"{API}/storefront/acme").json()
    assert "tenant_id" not in body
    feed = client.get(f"{API}/storefront/acme/catalog/ucp").json()
    assert all("tenant_id" not in p for p in feed["products"])
