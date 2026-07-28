"""
warden/api/ws_events.py  (OB-26)
──────────────────────────────────
Real-time anomaly WebSocket stream.

Clients connect to  ws://host/ws/events  and receive JSON-encoded XAI event
objects pushed whenever the /filter pipeline produces a HIGH or BLOCK verdict.

The broadcast mechanism uses an in-process asyncio.Queue fan-out (no Redis
pub/sub required for single-instance deployments).  A Redis-backed fallback
with aioredis SUBSCRIBE is activated when REDIS_URL is set and not memory://.

Protocol
────────
  Client → Server : { "subscribe": ["HIGH","BLOCK","FLAG"] }
              (optional filter — defaults to all BLOCK+HIGH)
  Server → Client : XAI event JSON (see _EventPayload below)
  Server → Client : { "type": "ping" }  every 30 s (keepalive)

Payload keys
────────────
  type          : "event"
  request_id    : str
  verdict       : "HIGH" | "BLOCK"
  score         : float  0–1
  tenant_id     : str
  stage_verdicts: dict[stage, verdict]
  primary_cause : str | None
  ts            : ISO-8601
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from warden.auth_guard import require_api_key

log = logging.getLogger("warden.api.ws_events")

router = APIRouter(tags=["WebSocket"])

# ── In-process fan-out registry ───────────────────────────────────────────────

_subscribers: list[asyncio.Queue] = []
_KEEPALIVE_INTERVAL = 30  # seconds


def _register() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _subscribers.append(q)
    return q


def _unregister(q: asyncio.Queue) -> None:
    with contextlib.suppress(ValueError):
        _subscribers.remove(q)


def subscriber_count() -> int:
    """Live WebSocket listener count — surfaced by GET /health as ws_clients."""
    return len(_subscribers)


async def broadcast_event(payload: dict) -> None:
    """
    Called by warden/main.py after every HIGH/BLOCK verdict.
    Fan-out to all connected WebSocket clients.  Dropped if queue full (non-blocking).
    """
    if not _subscribers:
        return
    for q in list(_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            log.debug("ws_events: queue full for subscriber, dropping event")

    # Also publish to Redis channel when available (multi-instance support)
    await _redis_publish(payload)


async def _redis_publish(payload: dict) -> None:
    redis_url = os.getenv("REDIS_URL", "")
    if not redis_url or redis_url == "memory://":
        return
    try:
        import redis.asyncio as aioredis  # noqa: PLC0415
        r = aioredis.from_url(redis_url)
        await r.publish("warden:events", json.dumps(payload))
        await r.aclose()
    except Exception as exc:
        log.debug("ws_events: redis publish failed: %s", exc)


# ── WebSocket endpoint ─────────────────────────────────────────────────────────

@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    """
    Real-time HIGH/BLOCK event stream.

    Connect:  ws://host/ws/events?key=<api_key>

    Optionally send ``{"subscribe": ["HIGH","BLOCK"]}`` to filter by verdict.
    Events are pushed as JSON.

    Authentication is REQUIRED. This stream carries cross-tenant security
    metadata (tenant_id, verdicts, detection flags, secret *kinds*), so an
    anonymous listener would both leak tenant activity and gain a live oracle
    for tuning filter bypasses against their own probes.
    """
    # ── Auth first: never accept() an unauthenticated socket ─────────────────
    #
    # This mirrors the handler that used to live in warden/main.py. When OB-26
    # extracted this endpoint into a router, the API-key check was dropped and
    # the inline handler was left behind — where it was silently shadowed,
    # because main.py mounts this router (line ~1363) BEFORE defining its own
    # @app.websocket("/ws/events"), and Starlette resolves in registration
    # order. The endpoint therefore ran unauthenticated in production.
    api_key = websocket.query_params.get("key", "") or None
    try:
        require_api_key(api_key)
    except HTTPException as exc:
        # Accept, explain, then close 1008 — a bare reject gives the client no
        # way to distinguish "bad key" from "endpoint missing".
        await websocket.accept()
        with contextlib.suppress(Exception):
            await websocket.send_text(
                json.dumps({"type": "error", "code": exc.status_code, "detail": exc.detail})
            )
        await websocket.close(code=1008)
        return

    await websocket.accept()
    log.info("ws_events: client connected %s", websocket.client)

    q = _register()
    subscribed: set[str] = {"HIGH", "BLOCK"}  # default

    # Read optional subscribe filter (non-blocking, 1s timeout)
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
        msg = json.loads(raw)
        if isinstance(msg.get("subscribe"), list):
            subscribed = {v.upper() for v in msg["subscribe"]}
    except (TimeoutError, Exception):
        pass  # no filter message — use defaults

    keepalive_task = asyncio.create_task(_keepalive(websocket))

    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=_KEEPALIVE_INTERVAL + 5)
            except TimeoutError:
                continue

            verdict = str(event.get("verdict", "")).upper()
            if verdict not in subscribed:
                continue

            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                break

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.debug("ws_events: connection error: %s", exc)
    finally:
        keepalive_task.cancel()
        _unregister(q)
        log.info("ws_events: client disconnected %s", websocket.client)


async def _keepalive(ws: WebSocket) -> None:
    """Send a ping frame every 30 s to prevent proxy timeouts."""
    while True:
        await asyncio.sleep(_KEEPALIVE_INTERVAL)
        try:
            await ws.send_text(json.dumps({"type": "ping", "ts": _ts()}))
        except Exception:
            break


def _ts() -> str:
    from datetime import UTC, datetime  # noqa: PLC0415
    return datetime.now(UTC).isoformat()


# ── Redis-backed subscriber (multi-instance) ──────────────────────────────────

async def redis_subscriber_loop() -> None:
    """
    Background task: subscribe to warden:events Redis channel and fan-out
    to local WebSocket clients.  Only runs when REDIS_URL is set.
    Restart-on-error loop (exponential backoff capped at 60 s).
    """
    redis_url = os.getenv("REDIS_URL", "")
    if not redis_url or redis_url == "memory://":
        return

    delay = 1.0
    while True:
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
            r = aioredis.from_url(redis_url)
            ps = r.pubsub()
            await ps.subscribe("warden:events")
            log.info("ws_events: Redis subscriber started on warden:events")
            delay = 1.0  # reset on success

            async for msg in ps.listen():
                if msg["type"] != "message":
                    continue
                try:
                    payload = json.loads(msg["data"])
                    for q in list(_subscribers):
                        with contextlib.suppress(asyncio.QueueFull):
                            q.put_nowait(payload)
                except Exception:
                    pass

        except Exception as exc:
            log.warning("ws_events: Redis subscriber error: %s — reconnecting in %ds", exc, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)
