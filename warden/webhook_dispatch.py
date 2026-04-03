"""
warden/webhook_dispatch.py
══════════════════════════
Per-tenant outbound webhooks — POST security events to customer-configured
URLs when the Warden filter raises HIGH or BLOCK risk.

Design
──────
  • SQLite-backed store (data/webhooks.db) for per-tenant webhook config
  • HMAC-SHA256 payload signature via X-Warden-Signature header
  • Async delivery with up to 3 retries + exponential back-off (1 s, 2 s, 4 s)
  • Payload is GDPR-safe: no raw content, only metadata + SHA-256 content hash

Webhook payload (JSON)
───────────────────────
  {
    "event_id":        "<uuid4>",
    "tenant_id":       "acme",
    "timestamp":       "2026-03-13T12:00:00Z",
    "risk_level":      "high",
    "owasp_categories": ["LLM02 — Insecure Output Handling"],
    "reason":          "Jailbreak pattern detected in input",
    "content_hash":    "sha256:abc123...",
    "processing_ms":   42.1
  }

Signature verification (receiver side)
────────────────────────────────────────
  import hmac, hashlib
  mac = hmac.new(secret.encode(), body_bytes, "sha256")
  assert request.headers["X-Warden-Signature"] == f"sha256={mac.hexdigest()}"

Environment variables
─────────────────────
  WEBHOOK_DB_PATH      Path to SQLite store (default: data/webhooks.db)
  WEBHOOK_TIMEOUT_S    HTTP delivery timeout in seconds  (default: 10)
  WEBHOOK_MAX_RETRIES  Max delivery attempts             (default: 3)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from datetime import UTC, datetime

import httpx

from warden.config import settings
from warden.retry import WEBHOOK_RETRY, async_retry

log = logging.getLogger("warden.webhook_dispatch")

_DB_PATH  = settings.webhook_db_path
_TIMEOUT  = settings.webhook_timeout_s
_MAX_RETRIES = settings.webhook_max_retries

_RISK_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "block": 3}


# ── Database helpers ──────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    os.makedirs(os.path.dirname(os.path.abspath(_DB_PATH)), exist_ok=True)
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                tenant_id   TEXT PRIMARY KEY,
                url         TEXT NOT NULL,
                secret      TEXT NOT NULL,
                min_risk    TEXT NOT NULL DEFAULT 'high',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        conn.commit()


# ── WebhookStore ──────────────────────────────────────────────────────────────

class WebhookStore:
    """CRUD for per-tenant webhook configuration."""

    def __init__(self) -> None:
        _init_db()

    def register(
        self,
        tenant_id: str,
        url: str,
        secret: str,
        min_risk: str = "high",
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT INTO webhooks (tenant_id, url, secret, min_risk, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    url=excluded.url,
                    secret=excluded.secret,
                    min_risk=excluded.min_risk,
                    updated_at=excluded.updated_at
                """,
                (tenant_id, url, secret, min_risk, now, now),
            )
            conn.commit()
        log.info("Webhook registered: tenant=%s url=%s min_risk=%s", tenant_id, url, min_risk)

    def deregister(self, tenant_id: str) -> bool:
        """Return True if a row was deleted."""
        with _get_conn() as conn:
            cur = conn.execute("DELETE FROM webhooks WHERE tenant_id = ?", (tenant_id,))
            conn.commit()
        return cur.rowcount > 0

    def get(self, tenant_id: str) -> dict | None:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT tenant_id, url, min_risk, created_at, updated_at FROM webhooks WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
        return dict(row) if row else None

    def _get_with_secret(self, tenant_id: str) -> dict | None:
        """Internal: includes secret for signing."""
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM webhooks WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
        return dict(row) if row else None


# ── Delivery ──────────────────────────────────────────────────────────────────

async def dispatch_event(
    *,
    tenant_id: str,
    risk_level: str,
    owasp_categories: list[str],
    reason: str,
    content: str,
    processing_ms: float,
    store: WebhookStore,
) -> None:
    """
    Fire-and-forget: look up tenant's webhook config and POST an event.
    Designed to run as a FastAPI BackgroundTask — all exceptions are caught.
    Content is never included in the payload (GDPR): only its SHA-256 hash.
    """
    cfg = store._get_with_secret(tenant_id)
    if cfg is None:
        return

    min_risk = cfg.get("min_risk", "high")
    if _RISK_ORDER.get(risk_level.lower(), 0) < _RISK_ORDER.get(min_risk, 2):
        return

    content_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    event: dict = {
        "event_id":        str(uuid.uuid4()),
        "tenant_id":       tenant_id,
        "timestamp":       datetime.now(UTC).isoformat(),
        "risk_level":      risk_level,
        "owasp_categories": owasp_categories,
        "reason":          reason,
        "content_hash":    content_hash,
        "processing_ms":   processing_ms,
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    sig  = _sign(body, cfg["secret"])
    await _deliver(cfg["url"], body, sig)


async def dispatch_bypass_event(
    *,
    tenant_id: str,
    reason: str,
    content: str,
    processing_ms: float,
    store: WebhookStore,
) -> None:
    """POST a bypass event to the tenant's webhook — min_risk check is skipped.

    Bypass events (pipeline timeout or circuit breaker) always warrant
    notification regardless of the tenant's configured min_risk threshold,
    because they represent a degradation of the security posture.

    Payload additions vs normal dispatch_event:
      "event_type":  "bypass"
      "bypass_type": "timeout" | "circuit_breaker"
    """
    cfg = store._get_with_secret(tenant_id)
    if cfg is None:
        return

    bypass_type  = "circuit_breaker" if reason == "circuit_breaker:open" else "timeout"
    content_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    event: dict = {
        "event_id":      str(uuid.uuid4()),
        "event_type":    "bypass",
        "tenant_id":     tenant_id,
        "timestamp":     datetime.now(UTC).isoformat(),
        "risk_level":    "low",
        "reason":        reason,
        "bypass_type":   bypass_type,
        "content_hash":  content_hash,
        "processing_ms": processing_ms,
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    sig  = _sign(body, cfg["secret"])
    await _deliver(cfg["url"], body, sig)


def _sign(body: bytes, secret: str) -> str:
    """Return 'sha256=<hex>' HMAC-SHA256 signature."""
    mac = hmac.new(secret.encode(), body, "sha256")
    return f"sha256={mac.hexdigest()}"


def _is_webhook_retryable(exc: Exception) -> bool:
    """Retry on network errors and 5xx; accept 2xx–4xx (don't retry 404, 401, etc.)."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return True


@async_retry(WEBHOOK_RETRY)
async def _deliver(url: str, body: bytes, signature: str) -> None:
    headers = {
        "Content-Type":        "application/json",
        "X-Warden-Signature":  signature,
        "User-Agent":          "ShadowWardenAI/1.1",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, content=body, headers=headers)
    if resp.status_code >= 500:
        resp.raise_for_status()  # triggers WEBHOOK_RETRY
    log.debug("Webhook delivered to %s — HTTP %d", url, resp.status_code)
