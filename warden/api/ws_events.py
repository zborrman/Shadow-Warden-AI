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
import json
import logging
import os
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

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
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


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

    Connect with any WebSocket client, optionally send a subscribe message
    to filter by verdict types.  Events are pushed as JSON.
    """
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
    except (asyncio.TimeoutError, Exception):
        pass  # no filter message — use defaults

    keepalive_task = asyncio.create_task(_keepalive(websocket))

    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=_KEEPALIVE_INTERVAL + 5)
            except asyncio.TimeoutError:
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
                        try:
                            q.put_nowait(payload)
                        except asyncio.QueueFull:
                            pass
                except Exception:
                    pass

        except Exception as exc:
            log.warning("ws_events: Redis subscriber error: %s — reconnecting in %ds", exc, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)
