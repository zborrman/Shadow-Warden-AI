"""
warden/communities/data_pod.py
────────────────────────────────
Sovereign Data Pods — per-jurisdiction MinIO routing.

A DataPod binds a community to a specific MinIO endpoint (Hetzner DC,
on-prem rack, or any S3-compatible store).  When an entity with a
Sovereign Pod Tag is stored or transferred, it is routed to the pod
whose jurisdiction matches the tag — ensuring data never leaves the
legal boundary.

Typical Hetzner DCs
────────────────────
  EU (Germany / Falkenstein): https://fsn1.your-objectstorage.com
  EU (Finland / Helsinki):    https://hel1.your-objectstorage.com
  EU (Germany / Nuremberg):   https://nbg1.your-objectstorage.com
  US / APAC:                  self-hosted MinIO on any cloud/on-prem

Each pod stores its own MinIO access_key / secret_key.  The secret key
is Fernet-encrypted at rest (key: COMMUNITY_VAULT_KEY → VAULT_MASTER_KEY).

Database
────────
  SQLite `sep_data_pods` in SEP_DB_PATH — same connection as sep.py.

API endpoints
─────────────
  POST   /sep/pods                    register new pod
  GET    /sep/pods/{community_id}     list pods for community
  DELETE /sep/pods/{pod_id}           decommission pod
  POST   /sep/pods/{pod_id}/probe     connectivity health check
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.communities.data_pod")

_SEP_DB_PATH = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_db_lock     = threading.RLock()


# ── Schema ─────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_data_pods (
            pod_id          TEXT PRIMARY KEY,
            community_id    TEXT NOT NULL,
            jurisdiction    TEXT NOT NULL,       -- EU | US | UK | etc.
            minio_endpoint  TEXT NOT NULL,       -- https://fsn1.your-objectstorage.com
            minio_region    TEXT NOT NULL DEFAULT 'eu-central-1',
            access_key      TEXT NOT NULL DEFAULT '',
            secret_key_enc  TEXT NOT NULL DEFAULT '',  -- Fernet-encrypted
            data_classes    TEXT NOT NULL DEFAULT '["GENERAL"]',  -- JSON array
            bucket          TEXT NOT NULL DEFAULT 'warden-evidence',
            is_primary      INTEGER NOT NULL DEFAULT 0,
            status          TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE | SUSPENDED
            notes           TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS pod_community_idx
            ON sep_data_pods(community_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS pod_jurisdiction_idx
            ON sep_data_pods(jurisdiction)
    """)
    conn.commit()
    return conn


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _vault_key() -> bytes:
    """32-byte key for Fernet encryption of MinIO secret keys."""
    import base64
    import hashlib
    raw = (
        os.getenv("COMMUNITY_VAULT_KEY")
        or os.getenv("VAULT_MASTER_KEY")
        or "dev-vault-key-insecure-do-not-use"
    )
    return base64.urlsafe_b64encode(
        hashlib.sha256(raw.encode()).digest()
    )


def _encrypt_secret(plaintext: str) -> str:
    """Fernet-encrypt a MinIO secret key for storage."""
    if not plaintext:
        return ""
    try:
        from cryptography.fernet import Fernet
        return Fernet(_vault_key()).encrypt(plaintext.encode()).decode()
    except ImportError:
        log.warning("data_pod: cryptography package missing — secret stored in plaintext")
        return plaintext


def _decrypt_secret(ciphertext: str) -> str:
    """Fernet-decrypt a MinIO secret key retrieved from storage."""
    if not ciphertext:
        return ""
    try:
        from cryptography.fernet import Fernet, InvalidToken
        try:
            return Fernet(_vault_key()).decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            return ciphertext  # legacy plain-text entry
    except ImportError:
        return ciphertext


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class DataPod:
    pod_id:         str
    community_id:   str
    jurisdiction:   str     # EU | US | UK | CA | SG | AU | JP | CH
    minio_endpoint: str     # https://fsn1.your-objectstorage.com
    minio_region:   str     # eu-central-1
    access_key:     str
    secret_key_enc: str     # Fernet-encrypted (do not expose via API)
    data_classes:   list[str]
    bucket:         str
    is_primary:     bool
    status:         str     # ACTIVE | SUSPENDED
    notes:          str
    created_at:     str


def _row_to_pod(row: sqlite3.Row) -> DataPod:
    d = dict(row)
    d["data_classes"] = json.loads(d.get("data_classes") or '["GENERAL"]')
    d["is_primary"]   = bool(d.get("is_primary", 0))
    return DataPod(**d)


# ── Public API ────────────────────────────────────────────────────────────────

def register_pod(
    community_id:   str,
    jurisdiction:   str,
    minio_endpoint: str,
    minio_region:   str     = "eu-central-1",
    access_key:     str     = "",
    secret_key:     str     = "",    # plaintext — encrypted before storage
    data_classes:   list[str] | None = None,
    bucket:         str     = "warden-evidence",
    is_primary:     bool    = False,
    notes:          str     = "",
) -> DataPod:
    """
    Register a Sovereign Data Pod for a community.

    *secret_key* is Fernet-encrypted before being written to SQLite.
    The pod is immediately available for entity routing.
    """
    pod_id         = str(uuid.uuid4())
    now            = datetime.now(UTC).isoformat()
    data_classes   = data_classes or ["GENERAL"]
    secret_key_enc = _encrypt_secret(secret_key)

    with _db_lock:
        conn = _get_conn()
        if is_primary:
            conn.execute(
                "UPDATE sep_data_pods SET is_primary=0 WHERE community_id=? AND jurisdiction=?",
                (community_id, jurisdiction),
            )
        conn.execute("""
            INSERT INTO sep_data_pods
              (pod_id, community_id, jurisdiction, minio_endpoint, minio_region,
               access_key, secret_key_enc, data_classes, bucket, is_primary, notes, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            pod_id, community_id, jurisdiction, minio_endpoint, minio_region,
            access_key, secret_key_enc, json.dumps(data_classes),
            bucket, int(is_primary), notes, now,
        ))
        conn.commit()

    log.info(
        "data_pod: registered pod=%s community=%s jurisdiction=%s endpoint=%s",
        pod_id[:8], community_id[:8], jurisdiction, minio_endpoint,
    )
    return DataPod(
        pod_id=pod_id, community_id=community_id, jurisdiction=jurisdiction,
        minio_endpoint=minio_endpoint, minio_region=minio_region,
        access_key=access_key, secret_key_enc=secret_key_enc,
        data_classes=data_classes, bucket=bucket, is_primary=is_primary,
        status="ACTIVE", notes=notes, created_at=now,
    )


def get_pod(pod_id: str) -> DataPod | None:
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM sep_data_pods WHERE pod_id=?", (pod_id,)
        ).fetchone()
    return _row_to_pod(row) if row else None


def list_pods(community_id: str) -> list[DataPod]:
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM sep_data_pods WHERE community_id=? ORDER BY is_primary DESC, created_at",
            (community_id,),
        ).fetchall()
    return [_row_to_pod(r) for r in rows]


def get_pod_for_entity(
    community_id: str,
    entity_id:    str,
    data_class:   str = "GENERAL",
    jurisdiction: str = "",
) -> DataPod | None:
    """
    Return the best matching pod for an entity.

    Resolution order:
      1. Pod whose jurisdiction matches the entity's Sovereign Pod Tag.
      2. Pod whose data_classes list includes the entity's data class.
      3. Primary pod for the community.
      4. Any ACTIVE pod for the community.
    """
    # Try to get jurisdiction from pod tag
    if not jurisdiction:
        try:
            from warden.communities.sep import get_pod_tag
            tag = get_pod_tag(entity_id, community_id)
            if tag:
                jurisdiction = tag.jurisdiction
                data_class   = data_class or tag.data_class
        except Exception:
            pass

    pods = [p for p in list_pods(community_id) if p.status == "ACTIVE"]
    if not pods:
        return None

    # 1. Jurisdiction match
    if jurisdiction:
        for pod in pods:
            if pod.jurisdiction.upper() == jurisdiction.upper():
                return pod

    # 2. Data-class match
    for pod in pods:
        if data_class.upper() in [dc.upper() for dc in pod.data_classes]:
            return pod

    # 3. Primary pod
    for pod in pods:
        if pod.is_primary:
            return pod

    # 4. First available
    return pods[0]


def probe_pod(pod_id: str) -> dict[str, Any]:
    """
    Test connectivity to a pod's MinIO endpoint.

    Returns {"status": "ok"|"error", "latency_ms": float, "endpoint": str}.
    """
    pod = get_pod(pod_id)
    if not pod:
        return {"status": "error", "reason": "pod not found"}

    import time
    t0 = time.perf_counter()
    try:
        import httpx
        resp = httpx.get(
            pod.minio_endpoint.rstrip("/") + "/minio/health/live",
            timeout=5.0,
            follow_redirects=True,
        )
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "status":      "ok" if resp.status_code < 400 else "degraded",
            "http_status": resp.status_code,
            "latency_ms":  latency_ms,
            "endpoint":    pod.minio_endpoint,
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "status":     "error",
            "reason":     str(exc),
            "latency_ms": latency_ms,
            "endpoint":   pod.minio_endpoint,
        }


def suspend_pod(pod_id: str) -> bool:
    with _db_lock:
        conn = _get_conn()
        n = conn.execute(
            "UPDATE sep_data_pods SET status='SUSPENDED' WHERE pod_id=?", (pod_id,)
        ).rowcount
        conn.commit()
    return n > 0


def decommission_pod(pod_id: str) -> bool:
    with _db_lock:
        conn = _get_conn()
        n = conn.execute(
            "DELETE FROM sep_data_pods WHERE pod_id=?", (pod_id,)
        ).rowcount
        conn.commit()
    log.info("data_pod: decommissioned pod=%s", pod_id[:8])
    return n > 0


def get_pod_client(pod: DataPod) -> Any:
    """
    Return a configured boto3 S3 client for *pod*'s MinIO endpoint.

    Raises ImportError if boto3 is not installed.
    """
    import boto3
    secret = _decrypt_secret(pod.secret_key_enc)
    return boto3.client(
        "s3",
        endpoint_url          = pod.minio_endpoint,
        aws_access_key_id     = pod.access_key,
        aws_secret_access_key = secret,
        region_name           = pod.minio_region,
    )
