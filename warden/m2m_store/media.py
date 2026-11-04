"""
warden/m2m_store/media.py
──────────────────────────
Product photos (plan stage M3), kept in the S3-compatible object store.

An upload is decoded and re-encoded before it is stored. That does three jobs:
it proves the bytes are the image they claim to be (a polyglot or a script
named ``.png`` does not decode), it drops EXIF and other metadata — a phone
photo carries the GPS position it was taken at — and it fixes the served
content type to one of three raster formats. SVG is refused: it is a document
that can carry script, not a picture.

Unlike the evidence and log shipping in ``warden.storage.s3``, an upload never
degrades quietly. A seller who uploads a photo must learn when it was not
stored, so an unavailable object store is a 503, not a silent drop.
"""
from __future__ import annotations

import contextlib
import io
import threading
import uuid
from typing import Any

from warden.config import settings
from warden.db.ddl_registry import register

from .inventory import _conn, _db_lock, _now_iso
from .storefront import StoreConflictError, StoreInvalidError, StoreNotFoundError, _owned_product

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_IMAGES_PER_PRODUCT = 8
# A small file can declare an enormous canvas (a decompression bomb), so the
# pixel count is checked from the header before anything is decoded.
MAX_IMAGE_PIXELS = 4096 * 4096
_FORMATS = {"JPEG": ("image/jpeg", "jpg"), "PNG": ("image/png", "png"),
            "WEBP": ("image/webp", "webp")}

_MEDIA_DDL = """
    CREATE TABLE IF NOT EXISTS m2m_product_images (
        id TEXT PRIMARY KEY,
        product_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        object_key TEXT NOT NULL,
        content_type TEXT NOT NULL,
        bytes INTEGER NOT NULL,
        width INTEGER NOT NULL,
        height INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_images_product ON m2m_product_images(product_id);
"""

register("m2m_store", "media", _MEDIA_DDL)


class MediaUnavailableError(RuntimeError):
    """The object store is not configured or not reachable."""


_bucket_ready = False
_bucket_lock = threading.Lock()


def _client() -> Any:
    global _bucket_ready
    from warden.storage.s3 import object_client

    client = object_client()
    if client is None:
        raise MediaUnavailableError("object storage is not available")
    bucket = settings.s3_bucket_store_media
    with _bucket_lock:
        if not _bucket_ready:
            try:
                client.head_bucket(Bucket=bucket)
            except Exception:
                try:
                    client.create_bucket(Bucket=bucket)
                except Exception as exc:
                    raise MediaUnavailableError("object storage is not available") from exc
            _bucket_ready = True
    return client


def normalise(data: bytes) -> tuple[bytes, str, str, int, int]:
    """Decode and re-encode an upload. Returns (bytes, content_type, ext, width, height)."""
    from PIL import Image

    if not data:
        raise StoreInvalidError("empty image")
    if len(data) > MAX_IMAGE_BYTES:
        raise StoreInvalidError(f"an image is at most {MAX_IMAGE_BYTES // (1024 * 1024)} MB")
    try:
        with Image.open(io.BytesIO(data)) as im:
            if im.format not in _FORMATS:
                raise StoreInvalidError("an image is JPEG, PNG or WebP")
            width, height = im.size
            if width * height > MAX_IMAGE_PIXELS:
                raise StoreInvalidError("image dimensions are too large")
            im.load()
            content_type, ext = _FORMATS[im.format]
            out = io.BytesIO()
            # Saving without exif=/pnginfo= is what drops the metadata.
            if im.format == "JPEG":
                im.convert("RGB").save(out, "JPEG", quality=88, optimize=True)
            elif im.format == "PNG":
                im.save(out, "PNG", optimize=True)
            else:
                im.save(out, "WEBP", quality=88)
    except StoreInvalidError:
        raise
    except Exception as exc:
        raise StoreInvalidError("not a readable image") from exc
    return out.getvalue(), content_type, ext, width, height


def _image_row(r: Any) -> dict[str, Any]:
    return {"id": r["id"], "url": f"/m2m-store/images/{r['id']}",
            "content_type": r["content_type"], "bytes": r["bytes"],
            "width": r["width"], "height": r["height"], "created_at": r["created_at"]}


def add_image(product_id: str, tenant_id: str, data: bytes) -> dict[str, Any]:
    _owned_product(product_id, tenant_id)
    body, content_type, ext, width, height = normalise(data)
    image_id = uuid.uuid4().hex
    key = f"products/{product_id}/{image_id}.{ext}"
    client = _client()
    bucket = settings.s3_bucket_store_media
    try:
        client.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)
    except Exception as exc:
        raise MediaUnavailableError("object storage is not available") from exc
    # One conditional INSERT, so four workers cannot race past the cap.
    with _db_lock, _conn() as con:
        cur = con.execute(
            "INSERT INTO m2m_product_images(id, product_id, tenant_id, object_key, content_type,"
            " bytes, width, height, created_at) SELECT ?,?,?,?,?,?,?,?,?"
            " WHERE (SELECT COUNT(*) FROM m2m_product_images"
            "        WHERE product_id=? AND deleted_at='') < ?",
            (image_id, product_id, tenant_id, key, content_type, len(body), width, height,
             _now_iso(), product_id, MAX_IMAGES_PER_PRODUCT),
        )
        stored = cur.rowcount == 1
    if not stored:
        _remove_object(client, key)
        raise StoreConflictError(f"a product has at most {MAX_IMAGES_PER_PRODUCT} images")
    with _db_lock, _conn() as con:
        r = con.execute("SELECT * FROM m2m_product_images WHERE id=?", (image_id,)).fetchone()
    return _image_row(r)


def list_images(product_id: str) -> list[dict[str, Any]]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM m2m_product_images WHERE product_id=? AND deleted_at=''"
            " ORDER BY created_at, id",
            (product_id,),
        ).fetchall()
    return [_image_row(r) for r in rows]


def _remove_object(client: Any, key: str) -> None:
    # The row is what makes an image visible; an orphaned object is never served.
    with contextlib.suppress(Exception):
        client.delete_object(Bucket=settings.s3_bucket_store_media, Key=key)


def delete_image(image_id: str, tenant_id: str) -> None:
    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT object_key FROM m2m_product_images"
            " WHERE id=? AND tenant_id=? AND deleted_at=''",
            (image_id, tenant_id),
        ).fetchone()
        if r is None:
            raise StoreNotFoundError("image")
        con.execute("UPDATE m2m_product_images SET deleted_at=? WHERE id=?",
                    (_now_iso(), image_id))
    # The photo itself goes too: a seller who deletes a picture expects it gone.
    with contextlib.suppress(MediaUnavailableError):
        _remove_object(_client(), r["object_key"])


def public_image_url(slug: str, image_id: str) -> str:
    return f"/m2m-store/storefront/{slug}/images/{image_id}"


def public_images(slug: str, product_id: str) -> list[dict[str, Any]]:
    """A product's photos as a buyer fetches them: through the store's own address."""
    return [img | {"url": public_image_url(slug, img["id"])} for img in list_images(product_id)]


def get_public_image(slug: str, image_id: str) -> tuple[bytes, str]:
    """
    A photo as the storefront serves it: only while the store is open and the
    product is on sale in it. A photo of a hidden or deleted product, or one
    asked for under another store's address, is a 404 like a missing one.
    """
    from .inventory import get_inventory
    from .storefront import get_public_store

    store = get_public_store(slug)
    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT product_id FROM m2m_product_images WHERE id=? AND deleted_at=''",
            (image_id,),
        ).fetchone()
    if r is None:
        raise StoreNotFoundError("image")
    p = get_inventory().get_product(r["product_id"])
    if p is None or p.deleted_at or not p.active or p.store_id != store["id"]:
        raise StoreNotFoundError("image")
    return get_image(image_id)


def get_image(image_id: str) -> tuple[bytes, str]:
    """A live image of a live product, as (bytes, content_type)."""
    from .inventory import get_inventory

    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT product_id, object_key, content_type FROM m2m_product_images"
            " WHERE id=? AND deleted_at=''",
            (image_id,),
        ).fetchone()
    if r is None:
        raise StoreNotFoundError("image")
    p = get_inventory().get_product(r["product_id"])
    if p is None or p.deleted_at:
        raise StoreNotFoundError("image")
    try:
        obj = _client().get_object(Bucket=settings.s3_bucket_store_media, Key=r["object_key"])
        return obj["Body"].read(), r["content_type"]
    except MediaUnavailableError:
        raise
    except Exception as exc:
        raise MediaUnavailableError("object storage is not available") from exc
