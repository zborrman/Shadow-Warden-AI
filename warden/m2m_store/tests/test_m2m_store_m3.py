"""
warden/m2m_store/tests/test_m2m_store_m3.py
────────────────────────────────────────────
Plan stage M3 (backend): a portal session acts as its own tenant on the owner
routes, and product photos are re-encoded before they are stored.
"""
from __future__ import annotations

import io
import os

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from PIL import Image

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")

API = "/m2m-store"


class _FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}

    # boto3 passes everything by keyword, in its own capitalised spelling.
    def head_bucket(self, **kw):
        return {}

    def put_object(self, **kw):
        self.objects[kw["Key"]] = (kw["Body"], kw["ContentType"])

    def get_object(self, **kw):
        return {"Body": io.BytesIO(self.objects[kw["Key"]][0])}

    def delete_object(self, **kw):
        self.objects.pop(kw["Key"], None)


@pytest.fixture(autouse=True)
def fresh_store(tmp_path, monkeypatch):
    monkeypatch.setenv("M2M_STORE_DB_PATH", str(tmp_path / "m2m.db"))
    from warden.m2m_store import inventory as inv_mod
    from warden.m2m_store import media

    inv_mod._inventory = inv_mod.InventoryManager()
    monkeypatch.setattr(media, "_bucket_ready", False)
    yield
    from warden.db.connect import close_cached_connections
    close_cached_connections()


@pytest.fixture
def s3(monkeypatch):
    fake = _FakeS3()
    monkeypatch.setattr("warden.storage.s3.object_client", lambda: fake)
    return fake


@pytest.fixture
def client():
    """API-key callers are faked per tenant; portal tokens go through the real check."""
    from warden.auth_guard import AuthResult, require_api_key
    from warden.m2m_store.api import router

    app = FastAPI()
    app.include_router(router)

    def _auth(request: Request) -> AuthResult:
        return AuthResult(api_key="k", tenant_id=request.headers.get("X-Test-Tenant", "tenant-a"))

    app.dependency_overrides[require_api_key] = _auth
    return TestClient(app)


def _keyed(monkeypatch, tenant="tenant-a"):
    """Make the plain-key fallback resolve to ``tenant`` (it is called, not injected)."""
    from warden.auth_guard import AuthResult
    from warden.m2m_store import api

    monkeypatch.setattr(api, "require_api_key",
                        lambda key: AuthResult(api_key="k", tenant_id=tenant))


def _token(tenant: str, role: str = "owner") -> dict:
    from warden.portal_router import _issue_access_token
    return {"Authorization": f"Bearer {_issue_access_token('u-' + tenant, tenant, role)}"}


def _png(size=(4, 4)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, (200, 10, 10)).save(buf, "PNG")
    return buf.getvalue()


def _store(client, headers, slug="acme"):
    r = client.post(f"{API}/stores", json={"slug": slug, "name": "Acme"}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def _product(client, headers, store_id):
    r = client.post(f"{API}/products",
                    json={"name": "Widget", "price_base": 10, "stock": 3, "store_id": store_id},
                    headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ── Portal session ────────────────────────────────────────────────────────────

def test_a_portal_session_acts_as_its_own_tenant(client, monkeypatch):
    _keyed(monkeypatch, "shared-portal-key-tenant")
    store = _store(client, _token("tenant-a"))
    assert [s["id"] for s in client.get(f"{API}/stores", headers=_token("tenant-a")).json()] \
        == [store["id"]]
    # Another user's session, and the portal's shared key, both see nothing.
    assert client.get(f"{API}/stores", headers=_token("tenant-b")).json() == []
    assert client.get(f"{API}/stores", headers={"X-API-Key": "k"}).json() == []
    r = client.patch(f"{API}/stores/{store['id']}", json={"name": "Mine"},
                     headers=_token("tenant-b"))
    assert r.status_code == 404


def test_a_bad_token_is_refused_not_downgraded_to_the_key(client, monkeypatch):
    _keyed(monkeypatch)
    r = client.get(f"{API}/stores",
                   headers={"Authorization": "Bearer not-a-jwt", "X-API-Key": "k"})
    assert r.status_code == 401


def test_a_refresh_token_is_not_a_session(client, monkeypatch):
    from warden.portal_router import _issue_refresh_token
    _keyed(monkeypatch)
    r = client.get(f"{API}/stores",
                   headers={"Authorization": f"Bearer {_issue_refresh_token('u')}"})
    assert r.status_code == 401


def test_a_read_only_role_cannot_change_a_store(client):
    r = client.post(f"{API}/stores", json={"slug": "acme", "name": "Acme"},
                    headers=_token("tenant-a", role="viewer"))
    assert r.status_code == 403


def test_buyer_routes_do_not_take_a_portal_session(client):
    # The catalog is read with an API key (overridden here), whatever else is sent.
    r = client.get(f"{API}/catalog", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 200


# ── Owner product listing ─────────────────────────────────────────────────────

def test_the_owner_lists_inactive_products_but_not_deleted_ones(client):
    a = _token("tenant-a")
    store = _store(client, a)
    live = _product(client, a, store["id"])
    hidden = client.post(f"{API}/products", json={"name": "Draft", "price_base": 1,
                                                  "store_id": store["id"], "active": False},
                         headers=a).json()["id"]
    gone = _product(client, a, store["id"])
    assert client.delete(f"{API}/products/{gone}", headers=a).status_code == 204
    listed = client.get(f"{API}/stores/{store['id']}/products", headers=a).json()
    assert sorted(p["id"] for p in listed) == sorted([live, hidden])
    assert all("tenant_id" not in p and p["images"] == [] for p in listed)
    assert client.get(f"{API}/stores/{store['id']}/products",
                      headers=_token("tenant-b")).status_code == 404


# ── Images ────────────────────────────────────────────────────────────────────

def _upload(client, headers, product_id, data, ctype="image/png"):
    return client.post(f"{API}/products/{product_id}/images", content=data,
                       headers=headers | {"Content-Type": ctype})


def test_an_image_round_trips_with_safe_headers(client, s3):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    r = _upload(client, a, pid, _png())
    assert r.status_code == 201, r.text
    img = r.json()
    assert (img["content_type"], img["width"], img["height"]) == ("image/png", 4, 4)
    got = client.get(img["url"])
    assert got.status_code == 200
    assert got.headers["content-type"] == "image/png"
    assert got.headers["x-content-type-options"] == "nosniff"
    assert Image.open(io.BytesIO(got.content)).size == (4, 4)
    listed = client.get(f"{API}/stores/{_store_id(client, a)}/products", headers=a).json()
    assert [i["id"] for i in listed[0]["images"]] == [img["id"]]


def _store_id(client, headers):
    return client.get(f"{API}/stores", headers=headers).json()[0]["id"]


def test_exif_and_gps_are_stripped(client, s3):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    exif = Image.Exif()
    exif[0x8825] = {2: (55, 45, 0)}  # GPSInfo: a latitude
    exif[0x010F] = "PhoneMaker"
    buf = io.BytesIO()
    Image.new("RGB", (8, 8)).save(buf, "JPEG", exif=exif)
    assert Image.open(io.BytesIO(buf.getvalue())).getexif()
    r = _upload(client, a, pid, buf.getvalue(), "image/jpeg")
    assert r.status_code == 201, r.text
    stored = Image.open(io.BytesIO(client.get(r.json()["url"]).content))
    assert not stored.getexif()


@pytest.mark.parametrize("data,ctype", [
    (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
     "image/svg+xml"),
    (b"<html><script>alert(1)</script></html>", "image/png"),
    (b"GIF89a" + b"\x00" * 32, "image/gif"),
])
def test_anything_but_a_raster_photo_is_refused(client, s3, data, ctype):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    assert _upload(client, a, pid, data, ctype).status_code == 422
    assert s3.objects == {}


def test_a_gif_is_refused_even_when_it_decodes(client, s3):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    buf = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf, "GIF")
    assert _upload(client, a, pid, buf.getvalue(), "image/gif").status_code == 422


def test_a_non_image_body_type_is_415(client, s3):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    assert _upload(client, a, pid, _png(), "application/json").status_code == 415


def test_an_oversized_upload_is_413(client, s3):
    from warden.m2m_store import media
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    big = b"\x89PNG" + b"\x00" * (media.MAX_IMAGE_BYTES + 1)
    assert _upload(client, a, pid, big).status_code == 413


def test_a_decompression_bomb_is_refused_before_decoding(client, s3, monkeypatch):
    from warden.m2m_store import media
    monkeypatch.setattr(media, "MAX_IMAGE_PIXELS", 10)
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    assert _upload(client, a, pid, _png((4, 4))).status_code == 422


def test_the_image_cap_holds_and_leaves_no_orphan(client, s3, monkeypatch):
    from warden.m2m_store import media
    monkeypatch.setattr(media, "MAX_IMAGES_PER_PRODUCT", 2)
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    assert _upload(client, a, pid, _png()).status_code == 201
    assert _upload(client, a, pid, _png()).status_code == 201
    assert _upload(client, a, pid, _png()).status_code == 409
    assert len(s3.objects) == 2


def test_only_the_owner_uploads_or_deletes(client, s3):
    a, b = _token("tenant-a"), _token("tenant-b")
    pid = _product(client, a, _store(client, a)["id"])
    assert _upload(client, b, pid, _png()).status_code == 404
    img = _upload(client, a, pid, _png()).json()
    assert client.delete(f"{API}/images/{img['id']}", headers=b).status_code == 404
    assert client.delete(f"{API}/images/{img['id']}", headers=a).status_code == 204
    assert client.get(img["url"]).status_code == 404
    assert s3.objects == {}


def test_a_deleted_products_images_are_not_served(client, s3):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    img = _upload(client, a, pid, _png()).json()
    assert client.delete(f"{API}/products/{pid}", headers=a).status_code == 204
    assert client.get(img["url"]).status_code == 404


def test_no_object_store_is_a_503_not_a_silent_drop(client, monkeypatch):
    monkeypatch.setattr("warden.storage.s3.object_client", lambda: None)
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    assert _upload(client, a, pid, _png()).status_code == 503


# ── Builder reads (M3b) ───────────────────────────────────────────────────────

def test_the_owner_reads_the_category_tree_of_an_inactive_store(client):
    a = _token("tenant-a")
    store = _store(client, a)
    client.patch(f"{API}/stores/{store['id']}", json={"active": False}, headers=a)
    root = client.post(f"{API}/stores/{store['id']}/categories",
                       json={"slug": "tools", "name": "Tools"}, headers=a).json()
    client.post(f"{API}/stores/{store['id']}/categories",
                json={"slug": "saws", "name": "Saws", "parent_id": root["id"]}, headers=a)
    tree = client.get(f"{API}/stores/{store['id']}/categories", headers=a).json()
    assert [(n["slug"], [c["slug"] for c in n["children"]]) for n in tree] == [("tools", ["saws"])]
    assert client.get(f"{API}/stores/{store['id']}/categories",
                      headers=_token("tenant-b")).status_code == 404


def test_a_portal_session_can_preview_its_own_photo(client, s3):
    a = _token("tenant-a")
    pid = _product(client, a, _store(client, a)["id"])
    img = _upload(client, a, pid, _png()).json()
    assert client.get(img["url"], headers=a).status_code == 200


def test_cors_allows_put_for_prices_and_translations():
    from warden.main import app
    cors = next(m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware")
    assert "PUT" in cors.kwargs["allow_methods"]
