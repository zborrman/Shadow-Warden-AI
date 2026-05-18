"""
warden/integrations/misp_bridge.py  (IN-22)
────────────────────────────────────────────
MISP ZMQ / syslog bridge.

Subscribes to a MISP platform's ZMQ pub socket and ingests incoming IoCs
(IPs, domains, URLs, file hashes) as Shadow Warden AI threat indicators.

Two modes
─────────
  ZMQ subscriber (MISP_ZMQ_URL set):
    Connects to MISP ZMQ topic "misp_json_self" and processes
    full MISP events with attributes.

  HTTP pull (MISP_API_URL + MISP_API_KEY set):
    Polls /events/restSearch for recent threat events on a schedule.
    Does NOT require ZMQ or pyzmq.

Config
──────
  MISP_ZMQ_URL         tcp://your-misp-host:50000
  MISP_API_URL         https://your-misp-host
  MISP_API_KEY         <MISP auth key>
  MISP_TENANT_ID       default
  MISP_POLL_INTERVAL   300  (seconds, for HTTP pull mode)

Start from FastAPI lifespan
────────────────────────────
  from warden.integrations.misp_bridge import start_misp_bridge
  # in lifespan:
  task = asyncio.create_task(start_misp_bridge())
  yield
  task.cancel()
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

log = logging.getLogger("warden.integrations.misp_bridge")

_MISP_ZMQ_URL       = os.getenv("MISP_ZMQ_URL",       "")
_MISP_API_URL       = os.getenv("MISP_API_URL",        "")
_MISP_API_KEY       = os.getenv("MISP_API_KEY",        "")
_MISP_TENANT_ID     = os.getenv("MISP_TENANT_ID",      "default")
_MISP_POLL_INTERVAL = int(os.getenv("MISP_POLL_INTERVAL", "300"))

# IoC attribute types Warden cares about
_BLOCK_TYPES = {
    "ip-dst", "ip-src", "domain", "hostname", "url",
    "ip-dst|port", "ip-src|port", "domain|ip",
}


# ── IoC ingest ────────────────────────────────────────────────────────────────

def _ingest_attribute(attr: dict, event_info: str = "") -> None:
    """
    Ingest a single MISP attribute into Warden's threat store.
    Blocks IPs; logs domains for Shadow AI detection.
    """
    atype = attr.get("type", "")
    value = attr.get("value", "")
    if not value or atype not in _BLOCK_TYPES:
        return

    comment = f"MISP: {event_info or attr.get('comment', 'IoC')}".strip()

    # IP address → block_ip in ThreatStore
    if atype in ("ip-dst", "ip-src"):
        try:
            from warden.main import _threat_store
            _threat_store.block_ip(
                ip         = value,
                tenant_id  = _MISP_TENANT_ID,
                reason     = comment,
                blocked_by = "misp_bridge",
            )
            log.info("misp_bridge: blocked IP %s (%s)", value, comment)
        except Exception as exc:
            log.debug("misp_bridge: block_ip error for %s: %s", value, exc)

    # Domain/hostname → feed to Shadow AI classifier
    elif atype in ("domain", "hostname"):
        try:
            from warden.shadow_ai.discovery import ShadowAIDetector
            ShadowAIDetector().classify_dns_event(
                domain    = value,
                source_ip = "misp",
                tenant_id = _MISP_TENANT_ID,
            )
        except Exception as exc:
            log.debug("misp_bridge: dns classify error for %s: %s", value, exc)


def _process_misp_event(event_json: dict) -> int:
    """Extract and ingest all relevant attributes from a MISP event dict."""
    event = event_json.get("Event", event_json)
    info  = event.get("info", "")
    attrs = event.get("Attribute", [])
    count = 0
    for attr in attrs:
        _ingest_attribute(attr, info)
        count += 1
    return count


# ── ZMQ subscriber ────────────────────────────────────────────────────────────

async def _zmq_loop() -> None:
    """Subscribe to MISP ZMQ and process events indefinitely."""
    try:
        import zmq
        import zmq.asyncio as azmq
    except ImportError:
        log.warning("misp_bridge: pyzmq not installed — ZMQ mode unavailable")
        return

    ctx    = azmq.Context()
    socket = ctx.socket(zmq.SUB)  # type: ignore[attr-defined]
    socket.connect(_MISP_ZMQ_URL)
    socket.setsockopt_string(zmq.SUBSCRIBE, "misp_json")  # type: ignore[attr-defined]
    log.info("misp_bridge: ZMQ subscribed to %s", _MISP_ZMQ_URL)

    while True:
        try:
            raw = await socket.recv_string()
            # ZMQ messages: "misp_json_self {json}" or "misp_json {json}"
            _, _, payload = raw.partition(" ")
            event_json = json.loads(payload)
            count = _process_misp_event(event_json)
            log.debug("misp_bridge: processed event with %d attributes", count)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("misp_bridge ZMQ error: %s", exc)
            await asyncio.sleep(5)

    socket.close()
    ctx.term()


# ── HTTP pull loop ────────────────────────────────────────────────────────────

async def _http_poll_loop() -> None:
    """Poll MISP REST API for recent events every _MISP_POLL_INTERVAL seconds."""
    import httpx

    log.info("misp_bridge: HTTP poll mode — %s every %ds", _MISP_API_URL, _MISP_POLL_INTERVAL)
    while True:
        try:
            since = (datetime.now(UTC) - timedelta(seconds=_MISP_POLL_INTERVAL * 2)).strftime("%Y-%m-%d")
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:  # noqa: S501
                resp = await client.post(
                    f"{_MISP_API_URL.rstrip('/')}/events/restSearch",
                    headers={
                        "Authorization": _MISP_API_KEY,
                        "Accept":        "application/json",
                        "Content-Type":  "application/json",
                    },
                    json={"returnFormat": "json", "timestamp": since, "threat_level_id": [1, 2]},
                )
                if resp.status_code == 200:
                    events = resp.json().get("response", [])
                    total  = sum(_process_misp_event(e) for e in events)
                    if total:
                        log.info("misp_bridge: pulled %d events (%d attrs)", len(events), total)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("misp_bridge HTTP poll error: %s", exc)

        await asyncio.sleep(_MISP_POLL_INTERVAL)


# ── Public start function ─────────────────────────────────────────────────────

async def start_misp_bridge() -> None:
    """
    Auto-select ZMQ (preferred) or HTTP poll mode based on env vars.
    Safe to call even when MISP is not configured — exits immediately.
    """
    if _MISP_ZMQ_URL:
        await _zmq_loop()
    elif _MISP_API_URL and _MISP_API_KEY:
        await _http_poll_loop()
    else:
        log.debug(
            "misp_bridge: not started (set MISP_ZMQ_URL or MISP_API_URL+MISP_API_KEY)"
        )
