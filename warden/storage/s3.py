"""
warden/storage/s3.py
━━━━━━━━━━━━━━━━━━━
Data-Gravity Hybrid Hub — S3-compatible object storage backend.

Stores Evidence Vault bundles and analytics log entries on local/colocation
S3-compatible object storage (MinIO by default) instead of cloud object storage.
This keeps all unstructured security data on-premises (data sovereignty) while
sending only clean filtered tokens to the upstream LLM cloud provider.

Architecture:
  Evidence Vault bundles → s3://<S3_BUCKET_EVIDENCE>/bundles/<session_id>.json
  Analytics log entries  → s3://<S3_BUCKET_LOGS>/logs/<date>/<request_id>.json

Configuration (set in .env):
  S3_ENABLED=true               # master switch (default: false)
  S3_ENDPOINT=http://minio:9000 # MinIO or any S3-compatible endpoint
  S3_ACCESS_KEY=minioadmin
  S3_SECRET_KEY=minioadmin
  S3_BUCKET_EVIDENCE=warden-evidence
  S3_BUCKET_LOGS=warden-logs
  S3_REGION=us-east-1           # required by SDK even for MinIO

Fail-open design:
  • If boto3 is not installed → silently disabled, local storage only.
  • If S3_ENABLED=false → disabled, local storage only.
  • If bucket unreachable → logs warning, continues without raising.
  All S3 operations are background-threaded so they never add latency to the
  filter pipeline.

GDPR note:
  Evidence bundles contain only GDPR-safe metadata (pseudonymised IDs, tool
  names, compliance scores). No prompt content or raw PII is ever written to S3.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.storage.s3")

# ── Configuration ─────────────────────────────────────────────────────────────

S3_ENABLED         = os.getenv("S3_ENABLED", "false").lower() == "true"
S3_ENDPOINT        = os.getenv("S3_ENDPOINT", "http://minio:9000")
S3_ACCESS_KEY      = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY      = os.getenv("S3_SECRET_KEY", "minioadmin")
S3_BUCKET_EVIDENCE = os.getenv("S3_BUCKET_EVIDENCE", "warden-evidence")
S3_BUCKET_LOGS     = os.getenv("S3_BUCKET_LOGS",     "warden-logs")
S3_REGION          = os.getenv("S3_REGION",          "us-east-1")

# Background thread pool — max 2 threads (S3 I/O is the only work)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="warden-s3")

# ── boto3 lazy import ─────────────────────────────────────────────────────────

_boto3_client: Any | None = None
_boto3_lock  = threading.Lock()
_boto3_ok    = False   # set True once client is verified reachable


def _get_client() -> Any | None:
    """
    Return a boto3 S3 client, initialising on first call.
    Returns None if boto3 is not installed or S3_ENABLED=false.
    """
    global _boto3_client, _boto3_ok

    if not S3_ENABLED:
        return None

    with _boto3_lock:
        if _boto3_client is not None:
            return _boto3_client if _boto3_ok else None

        try:
            import boto3  # noqa: PLC0415
            from botocore.config import Config  # noqa: PLC0415

            _boto3_client = boto3.client(
                "s3",
                endpoint_url          = S3_ENDPOINT,
                aws_access_key_id     = S3_ACCESS_KEY,
                aws_secret_access_key = S3_SECRET_KEY,
                region_name           = S3_REGION,
                config                = Config(signature_version="s3v4"),
            )
            # Verify connectivity + ensure buckets exist
            _ensure_buckets(_boto3_client)
            _boto3_ok = True
            log.info(
                "S3 storage active — endpoint=%s evidence=%s logs=%s",
                S3_ENDPOINT, S3_BUCKET_EVIDENCE, S3_BUCKET_LOGS,
            )
        except ImportError:
            log.warning(
                "boto3 not installed — S3 storage disabled. "
                "Install with: pip install boto3"
            )
            _boto3_client = object()  # sentinel so we don't retry
        except Exception as exc:
            log.warning("S3 init failed (%s) — storage disabled.", exc)
            _boto3_client = object()  # sentinel

        return _boto3_client if _boto3_ok else None


def _ensure_buckets(client: Any) -> None:
    """Create buckets if they do not exist (MinIO auto-creates on put, but be explicit)."""
    for bucket in (S3_BUCKET_EVIDENCE, S3_BUCKET_LOGS):
        try:
            client.head_bucket(Bucket=bucket)
        except Exception:
            try:
                client.create_bucket(Bucket=bucket)
                log.info("Created S3 bucket: %s", bucket)
            except Exception as exc:
                log.warning("Could not create bucket %s: %s", bucket, exc)
                raise


# ── Public API ────────────────────────────────────────────────────────────────

def save_bundle(session_id: str, bundle: dict) -> None:
    """
    Persist an evidence bundle to S3 in the background.

    Key format: bundles/<session_id>.json
    The bundle is stored as compact JSON with Content-Type application/json.
    Fails silently if S3 is not configured or unreachable.
    """
    _executor.submit(_upload_bundle, session_id, bundle)


def ship_log_entry(entry: dict) -> None:
    """
    Ship one analytics log entry to S3 in the background.

    Key format: logs/<YYYY-MM-DD>/<request_id>.json
    GDPR: entry contains only metadata (no content, no raw PII).
    Fails silently if S3 is not configured or unreachable.
    """
    _executor.submit(_upload_log, entry)


def list_bundles(prefix: str = "bundles/") -> list[str]:
    """
    Return S3 keys of all stored evidence bundles.
    Returns an empty list if S3 is not available.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        resp    = client.list_objects_v2(Bucket=S3_BUCKET_EVIDENCE, Prefix=prefix)
        return [obj["Key"] for obj in resp.get("Contents", [])]
    except Exception as exc:
        log.warning("S3 list_bundles failed: %s", exc)
        return []


def get_bundle(session_id: str) -> dict | None:
    """
    Retrieve an evidence bundle by session_id.
    Returns None if not found or S3 is not available.
    """
    client = _get_client()
    if client is None:
        return None
    key = f"bundles/{session_id}.json"
    try:
        resp = client.get_object(Bucket=S3_BUCKET_EVIDENCE, Key=key)
        return json.loads(resp["Body"].read())
    except Exception as exc:
        log.debug("S3 get_bundle(%s) failed: %s", session_id, exc)
        return None


# ── Internal upload helpers ───────────────────────────────────────────────────

def _upload_bundle(session_id: str, bundle: dict) -> None:
    client = _get_client()
    if client is None:
        return
    key  = f"bundles/{session_id}.json"
    body = json.dumps(bundle, separators=(",", ":")).encode()
    try:
        client.put_object(
            Bucket       = S3_BUCKET_EVIDENCE,
            Key          = key,
            Body         = body,
            ContentType  = "application/json",
        )
        log.debug("S3 bundle saved: %s/%s", S3_BUCKET_EVIDENCE, key)
    except Exception as exc:
        log.warning("S3 upload_bundle(%s) failed: %s", session_id, exc)


def _upload_log(entry: dict) -> None:
    client = _get_client()
    if client is None:
        return
    date_str   = datetime.now(UTC).strftime("%Y-%m-%d")
    request_id = entry.get("request_id", "unknown")
    key        = f"logs/{date_str}/{request_id}.json"
    body       = json.dumps(entry, separators=(",", ":")).encode()
    try:
        client.put_object(
            Bucket       = S3_BUCKET_LOGS,
            Key          = key,
            Body         = body,
            ContentType  = "application/json",
        )
        log.debug("S3 log shipped: %s/%s", S3_BUCKET_LOGS, key)
    except Exception as exc:
        log.warning("S3 ship_log(%s) failed: %s", request_id, exc)
