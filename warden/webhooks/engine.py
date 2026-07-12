"""
warden/webhooks/engine.py  (DEV-05)
────────────────────────────────────
Webhook Event System — CRUD + HMAC-SHA256 signed delivery.

Tenants register endpoint URLs for specific event types.
On each qualifying filter event the engine fires HTTP POST to all
matching endpoints with a signed payload.

Signature
---------
  X-Warden-Signature: sha256=<hex>
  computed over the raw JSON body using the webhook's secret key.

Delivery
--------
  Background asyncio task, ≤3 retries with 1/2/4s backoff.
  Delivery receipts stored in SQLite for audit.

Event types
-----------
  filter.blocked   — blocked filter request
  filter.flagged   — flagged (HIGH/MEDIUM risk) request
  filter.secret    — secrets detected + redacted
  agent.anomaly    — agentic loop anomaly (β₂ Betti)
  compliance.gap   — new compliance gap detected
  evolution.update — EvolutionEngine added new examples
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from warden.config import data_path

log = logging.getLogger("warden.webhooks.engine")

_DB_PATH  = data_path("warden_webhooks.db", "WEBHOOKS_DB_PATH")
_db_lock  = threading.RLock()
_MAX_RETRY = 3

EVENT_TYPES = frozenset({
    "filter.blocked",
    "filter.flagged",
    "filter.secret",
    "agent.anomaly",
    "compliance.gap",
    "evolution.update",
})


@dataclass
class WebhookEndpoint:
    id:         str
    tenant_id:  str
    url:        str
    secret:     str
    events:     list[str]
    enabled:    bool = True
    created_at: str  = ""


def _get_db() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def _ensure_schema() -> None:
    with _db_lock:
        con = _get_db()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS webhook_endpoints (
                id          TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                url         TEXT NOT NULL,
                secret      TEXT NOT NULL,
                events      TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id          TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                status_code INTEGER,
                attempt     INTEGER NOT NULL DEFAULT 1,
                delivered   INTEGER NOT NULL DEFAULT 0,
                ts          TEXT NOT NULL
            );
        """)
        con.commit()
        con.close()


_ensure_schema()


# ── CRUD ───────────────────────────────────────────────────────────────────────

def create_endpoint(tenant_id: str, url: str, secret: str, events: list[str]) -> WebhookEndpoint:
    import secrets as _sec  # noqa: PLC0415

    from warden.net_guard import assert_public_url  # noqa: PLC0415
    # SSRF guard: reject internal / metadata / private URLs at registration time.
    assert_public_url(url)

    wid = _sec.token_hex(12)
    ts  = datetime.now(UTC).isoformat()
    valid_events = [e for e in events if e in EVENT_TYPES]
    with _db_lock:
        con = _get_db()
        con.execute(
            "INSERT INTO webhook_endpoints(id,tenant_id,url,secret,events,enabled,created_at) "
            "VALUES(?,?,?,?,?,1,?)",
            (wid, tenant_id, url, secret, json.dumps(valid_events), ts),
        )
        con.commit()
        con.close()
    return WebhookEndpoint(id=wid, tenant_id=tenant_id, url=url, secret=secret,
                           events=valid_events, enabled=True, created_at=ts)


def list_endpoints(tenant_id: str) -> list[WebhookEndpoint]:
    with _db_lock:
        con = _get_db()
        rows = con.execute(
            "SELECT * FROM webhook_endpoints WHERE tenant_id=?", (tenant_id,)
        ).fetchall()
        con.close()
    return [
        WebhookEndpoint(
            id=r["id"], tenant_id=r["tenant_id"], url=r["url"],
            secret=r["secret"], events=json.loads(r["events"]),
            enabled=bool(r["enabled"]), created_at=r["created_at"],
        ) for r in rows
    ]


def delete_endpoint(endpoint_id: str, tenant_id: str) -> bool:
    with _db_lock:
        con = _get_db()
        cur = con.execute(
            "DELETE FROM webhook_endpoints WHERE id=? AND tenant_id=?",
            (endpoint_id, tenant_id),
        )
        con.commit()
        con.close()
    return cur.rowcount > 0


# ── Delivery ───────────────────────────────────────────────────────────────────

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def _deliver_once(endpoint: WebhookEndpoint, payload: dict, attempt: int) -> int:
    body    = json.dumps(payload, separators=(",", ":")).encode()
    sig     = _sign(endpoint.secret, body)
    headers = {
        "Content-Type":       "application/json",
        "X-Warden-Signature": sig,
        "X-Warden-Event":     payload.get("event_type", ""),
        "User-Agent":         "ShadowWarden/1.0",
    }
    try:
        import httpx  # noqa: PLC0415

        from warden.net_guard import assert_public_url  # noqa: PLC0415
        # Re-validate at delivery time — defends against DNS rebinding between
        # registration and firing, and against rows written before this guard.
        assert_public_url(endpoint.url)
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(endpoint.url, content=body, headers=headers)
            return resp.status_code
    except Exception as exc:
        log.debug("webhook delivery failed attempt=%d url=%s — %s", attempt, endpoint.url, exc)
        return 0


async def fire_event(event_type: str, tenant_id: str, data: dict[str, Any]) -> None:
    """Fire an event to all matching tenant endpoints (background, non-blocking)."""
    if event_type not in EVENT_TYPES:
        return

    endpoints = list_endpoints(tenant_id)
    active    = [e for e in endpoints if e.enabled and event_type in e.events]
    if not active:
        return

    payload = {
        "event_type": event_type,
        "tenant_id":  tenant_id,
        "ts":         datetime.now(UTC).isoformat(),
        "data":       data,
    }

    async def _deliver(ep: WebhookEndpoint) -> None:
        import secrets as _sec  # noqa: PLC0415
        did    = _sec.token_hex(8)
        status = 0
        for attempt in range(1, _MAX_RETRY + 1):
            status = await _deliver_once(ep, payload, attempt)
            if 200 <= status < 300:
                break
            if attempt < _MAX_RETRY:
                await asyncio.sleep(2 ** (attempt - 1))

        with _db_lock:
            con = _get_db()
            con.execute(
                "INSERT INTO webhook_deliveries(id,endpoint_id,event_type,status_code,attempt,delivered,ts) "
                "VALUES(?,?,?,?,?,?,?)",
                (did, ep.id, event_type, status, _MAX_RETRY,
                 1 if 200 <= status < 300 else 0, datetime.now(UTC).isoformat()),
            )
            con.commit()
            con.close()

        log.info("webhook: event=%s endpoint=%s status=%d", event_type, ep.id, status)

    for ep in active:
        asyncio.create_task(_deliver(ep))


def delivery_history(endpoint_id: str, limit: int = 50) -> list[dict]:
    with _db_lock:
        con = _get_db()
        rows = con.execute(
            "SELECT * FROM webhook_deliveries WHERE endpoint_id=? ORDER BY ts DESC LIMIT ?",
            (endpoint_id, limit),
        ).fetchall()
        con.close()
    return [dict(r) for r in rows]
