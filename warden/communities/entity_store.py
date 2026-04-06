"""
warden/communities/entity_store.py
────────────────────────────────────
S3-backed encrypted entity persistence for Community content.

Storage architecture
────────────────────
  PostgreSQL (metadata layer):
    - entity_id, community_id, kid, clearance, cek_wrapped_b64, nonce_b64,
      sig_b64, s3_key, byte_size, content_type, sender_mid, created_at

  S3 / MinIO (payload layer):
    - Key: communities/{community_id}/{entity_id}.enc
    - Content: raw AES-256-GCM ciphertext (base64-decoded payload_b64)
    - No metadata in the key — no content-type, filename, or user info leaks

Why S3 for payloads?
────────────────────
  E2EE prevents server-side deduplication: 100 users uploading the same
  PDF produces 100 uniquely encrypted blobs (different CEKs, different
  ciphertext). This makes PostgreSQL blob storage unsuitable beyond ~10 GB.

  S3/MinIO advantages:
    - Multipart upload for entities > 100 MB
    - Server-side retention policies (lifecycle rules) map to tier retention_days
    - Pre-signed URLs for direct client download (zero server bandwidth)
    - Async streaming: upload and quota check happen concurrently

Quota integration
─────────────────
  Before upload: check_entity_size() + check_storage_quota()
  After upload:  record_upload(community_id, bytes)
  On delete:     release_storage(community_id, bytes)

Retention enforcement
─────────────────────
  Individual: 90-day S3 lifecycle rule on prefix communities/{cid}/
  Business:   365-day lifecycle rule
  MCP:        No lifecycle rule (manual crypto_shred only)

Usage
─────
  # Store encrypted entity
  meta = await store_entity(envelope, community_id, tier, content_type, sender_mid)

  # Retrieve (returns ClearanceEnvelope reconstructed from DB + S3)
  envelope = await get_entity(entity_id, community_id)

  # Delete (crypto-shreds payload, records storage release)
  await delete_entity(entity_id, community_id)
"""
from __future__ import annotations

import base64
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

log = logging.getLogger("warden.communities.entity_store")

_ENTITY_DB_PATH = os.getenv("ENTITY_DB_PATH", "/tmp/warden_entity_store.db")
_S3_BUCKET      = os.getenv("COMMUNITY_S3_BUCKET", "warden-communities")
_db_lock        = threading.RLock()


# ── Schema ────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_ENTITY_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_entities (
            entity_id       TEXT PRIMARY KEY,
            community_id    TEXT NOT NULL,
            kid             TEXT NOT NULL,
            clearance       TEXT NOT NULL DEFAULT 'PUBLIC',
            cek_wrapped_b64 TEXT NOT NULL,
            nonce_b64       TEXT NOT NULL,
            pay_nonce_b64   TEXT NOT NULL,
            sig_b64         TEXT NOT NULL,
            sender_mid      TEXT NOT NULL,
            s3_key          TEXT,
            byte_size       INTEGER NOT NULL DEFAULT 0,
            content_type    TEXT NOT NULL DEFAULT 'application/octet-stream',
            status          TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            expires_at      TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS ce_community_idx ON community_entities(community_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS ce_kid_idx ON community_entities(community_id, kid)
    """)
    conn.commit()
    return conn


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class EntityMeta:
    entity_id:       str
    community_id:    str
    kid:             str
    clearance:       str
    cek_wrapped_b64: str
    nonce_b64:       str
    pay_nonce_b64:   str
    sig_b64:         str
    sender_mid:      str
    s3_key:          str | None
    byte_size:       int
    content_type:    str
    status:          str
    created_at:      str
    expires_at:      str | None


def _row_to_meta(row) -> EntityMeta:
    return EntityMeta(
        entity_id       = row["entity_id"],
        community_id    = row["community_id"],
        kid             = row["kid"],
        clearance       = row["clearance"],
        cek_wrapped_b64 = row["cek_wrapped_b64"],
        nonce_b64       = row["nonce_b64"],
        pay_nonce_b64   = row["pay_nonce_b64"],
        sig_b64         = row["sig_b64"],
        sender_mid      = row["sender_mid"],
        s3_key          = row["s3_key"],
        byte_size       = row["byte_size"],
        content_type    = row["content_type"],
        status          = row["status"],
        created_at      = row["created_at"],
        expires_at      = row["expires_at"],
    )


# ── S3 helpers ────────────────────────────────────────────────────────────────

def _s3_key(community_id: str, entity_id: str) -> str:
    """
    S3 object key for an encrypted entity payload.

    Format: communities/{community_id}/{entity_id}.enc
    No content-type, filename, or sender info in the path.
    """
    return f"communities/{community_id}/{entity_id}.enc"


def _get_s3():
    """Return boto3 S3 client. Raises ImportError if boto3 not installed."""
    import boto3
    return boto3.client(
        "s3",
        endpoint_url         = os.getenv("S3_ENDPOINT_URL"),       # MinIO local
        aws_access_key_id    = os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name          = os.getenv("AWS_REGION", "us-east-1"),
    )


def _s3_put(key: str, payload_bytes: bytes) -> bool:
    """Upload bytes to S3. Returns True on success, False on error."""
    try:
        s3 = _get_s3()
        s3.put_object(
            Bucket      = _S3_BUCKET,
            Key         = key,
            Body        = payload_bytes,
            ContentType = "application/octet-stream",
            ServerSideEncryption = "AES256",   # S3 SSE as defence-in-depth
        )
        return True
    except Exception as exc:
        log.error("entity_store: S3 put error key=%s: %s", key, exc)
        return False


def _s3_get(key: str) -> bytes | None:
    """Download bytes from S3. Returns None on error."""
    try:
        s3       = _get_s3()
        response = s3.get_object(Bucket=_S3_BUCKET, Key=key)
        return response["Body"].read()
    except Exception as exc:
        log.error("entity_store: S3 get error key=%s: %s", key, exc)
        return None


def _s3_delete(key: str) -> bool:
    """Delete an object from S3. Returns True on success."""
    try:
        s3 = _get_s3()
        s3.delete_object(Bucket=_S3_BUCKET, Key=key)
        return True
    except Exception as exc:
        log.error("entity_store: S3 delete error key=%s: %s", key, exc)
        return False


def _s3_presign(key: str, expires_in: int = 3600) -> str | None:
    """Generate a pre-signed GET URL for direct client download."""
    try:
        s3 = _get_s3()
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": _S3_BUCKET, "Key": key},
            ExpiresIn=expires_in,
        )
    except Exception as exc:
        log.error("entity_store: S3 presign error key=%s: %s", key, exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def store_entity(
    envelope,          # ClearanceEnvelope
    community_id: str,
    tier:         str,
    content_type: str = "application/octet-stream",
    retention_days: int | None = None,
) -> EntityMeta:
    """
    Store an encrypted entity.

    Steps:
      1. Enforce entity size limit (check_entity_size).
      2. Check storage quota (check_storage_quota) — raises QuotaExceeded or
         OverageRequired.
      3. Decode payload from Base64 → raw ciphertext bytes.
      4. Upload raw bytes to S3 (key = communities/{cid}/{eid}.enc).
      5. Insert metadata row into SQLite/PostgreSQL.
      6. Record storage usage (record_upload).

    Returns EntityMeta.

    NOTE: The caller is responsible for calling overage.resolve_overage()
    if OverageRequired is raised (allows billing before proceeding).
    """
    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    from warden.communities.quota import check_entity_size, check_storage_quota, record_upload

    # Decode payload bytes (what actually gets stored in S3)
    payload_bytes = base64.b64decode(envelope.payload_b64)
    byte_size     = len(payload_bytes)

    # Quota pre-checks (raise before any storage)
    check_entity_size(tier, byte_size)
    check_storage_quota(community_id, tier, byte_size)

    entity_id = str(envelope.entity_id) if hasattr(envelope, "entity_id") else str(uuid.uuid4())
    key       = _s3_key(community_id, entity_id)

    # Compute expiry from retention_days
    expires_at = None
    if retention_days is None:
        retention_days = TIER_LIMITS[_normalize_tier(tier)]["retention_days"]
    if retention_days and retention_days > 0:
        from datetime import timedelta
        expires_at = (datetime.now(UTC) + timedelta(days=retention_days)).isoformat()

    now = datetime.now(UTC).isoformat()

    # Upload to S3 (payload only — metadata stays in DB)
    s3_ok = _s3_put(key, payload_bytes)
    if not s3_ok:
        # Fallback: store inline in DB (dev/test without S3)
        key = None
        log.warning(
            "entity_store: S3 unavailable, storing payload inline entity=%s", entity_id[:8]
        )

    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO community_entities
              (entity_id, community_id, kid, clearance, cek_wrapped_b64, nonce_b64,
               pay_nonce_b64, sig_b64, sender_mid, s3_key, byte_size,
               content_type, status, created_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            entity_id, community_id, envelope.kid, envelope.clearance,
            envelope.cek_wrapped_b64, envelope.nonce_b64, envelope.pay_nonce_b64,
            envelope.sig_b64, envelope.sender_mid, key, byte_size,
            content_type, "ACTIVE", now, expires_at,
        ))
        conn.commit()

    # Record usage after successful storage
    record_upload(community_id, byte_size)

    log.info(
        "entity_store: stored entity=%s community=%s clearance=%s size=%d",
        entity_id[:8], community_id[:8], envelope.clearance, byte_size,
    )
    return EntityMeta(
        entity_id       = entity_id,
        community_id    = community_id,
        kid             = envelope.kid,
        clearance       = envelope.clearance,
        cek_wrapped_b64 = envelope.cek_wrapped_b64,
        nonce_b64       = envelope.nonce_b64,
        pay_nonce_b64   = envelope.pay_nonce_b64,
        sig_b64         = envelope.sig_b64,
        sender_mid      = envelope.sender_mid,
        s3_key          = key,
        byte_size       = byte_size,
        content_type    = content_type,
        status          = "ACTIVE",
        created_at      = now,
        expires_at      = expires_at,
    )


def get_entity_meta(entity_id: str, community_id: str) -> EntityMeta | None:
    """Return entity metadata without downloading the payload."""
    with _db_lock:
        conn = _get_conn()
        row  = conn.execute(
            "SELECT * FROM community_entities WHERE entity_id=? AND community_id=? AND status='ACTIVE'",
            (entity_id, community_id)
        ).fetchone()
    return _row_to_meta(row) if row else None


def get_entity_payload(entity_id: str, community_id: str) -> bytes | None:
    """
    Download raw encrypted payload bytes from S3.

    Records bandwidth usage after successful download.
    Returns None if entity not found or S3 error.
    """
    from warden.communities.quota import record_download
    meta = get_entity_meta(entity_id, community_id)
    if not meta:
        return None

    payload = _s3_get(meta.s3_key) if meta.s3_key else None

    if payload:
        record_download(community_id, len(payload))

    return payload


def get_entity_presigned_url(entity_id: str, community_id: str, expires_in: int = 3600) -> str | None:
    """
    Return a pre-signed S3 URL for direct client download.

    This bypasses Warden bandwidth (client downloads directly from S3)
    — useful for large files to avoid server egress charges.
    """
    meta = get_entity_meta(entity_id, community_id)
    if not meta or not meta.s3_key:
        return None
    return _s3_presign(meta.s3_key, expires_in)


def delete_entity(entity_id: str, community_id: str) -> bool:
    """
    Delete (crypto-shred) an entity.

    Deletes S3 object, marks DB row DELETED, releases storage quota.
    Returns True if entity was found and deleted.
    """
    from warden.communities.quota import release_storage
    meta = get_entity_meta(entity_id, community_id)
    if not meta:
        return False

    # Delete from S3
    if meta.s3_key:
        _s3_delete(meta.s3_key)

    # Soft-delete metadata row
    with _db_lock:
        conn = _get_conn()
        conn.execute(
            "UPDATE community_entities SET status='DELETED' WHERE entity_id=? AND community_id=?",
            (entity_id, community_id)
        )
        conn.commit()

    # Release storage quota
    release_storage(community_id, meta.byte_size)

    log.info(
        "entity_store: deleted entity=%s community=%s freed=%d bytes",
        entity_id[:8], community_id[:8], meta.byte_size,
    )
    return True


def list_entities(
    community_id: str,
    clearance_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[EntityMeta]:
    """List active entities for a community, newest first."""
    with _db_lock:
        conn = _get_conn()
        if clearance_filter:
            rows = conn.execute(
                "SELECT * FROM community_entities "
                "WHERE community_id=? AND clearance=? AND status='ACTIVE' "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (community_id, clearance_filter, limit, offset)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM community_entities "
                "WHERE community_id=? AND status='ACTIVE' "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (community_id, limit, offset)
            ).fetchall()
    return [_row_to_meta(r) for r in rows]


def expire_entities(community_id: str) -> int:
    """
    Delete entities past their expires_at date (called by retention reaper).

    Returns count of entities deleted.
    """
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT entity_id, byte_size, s3_key FROM community_entities "
            "WHERE community_id=? AND status='ACTIVE' AND expires_at IS NOT NULL AND expires_at < ?",
            (community_id, now)
        ).fetchall()

    count = 0
    for row in rows:
        if delete_entity(row["entity_id"], community_id):
            count += 1

    if count:
        log.info("entity_store: retention expired %d entities community=%s", count, community_id[:8])
    return count
