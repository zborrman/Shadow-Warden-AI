"""
warden/integrations/misp_bridge.py  (IN-22)
────────────────────────────────────────────
MISP ZMQ → Shadow Warden syslog bridge.

Subscribes to a MISP platform's ZMQ pub socket and ingests incoming IoCs
into Shadow Warden's threat pipeline via two parallel paths:

  1. Direct ingest — domain IoCs → ShadowAIDetector.classify_dns_event()
                     IP IoCs    → _threat_store.block_ip()

  2. Syslog forwarding — domain IoCs formatted as dnsmasq-style syslog lines
                         and UDP-forwarded to the Shadow AI syslog sink
                         (port SHADOW_AI_SYSLOG_PORT, default 5514).
                         This enables real-time correlation with passive DNS
                         telemetry from pfSense / BIND / Zeek in the same sink.

Two modes
─────────
  ZMQ subscriber (MISP_ZMQ_URL set):
    Connects to MISP ZMQ and processes full MISP events with attributes.
    Supports both single-string ("topic {json}") and multipart ZMQ frames.

  HTTP pull (MISP_API_URL + MISP_API_KEY set):
    Polls /events/restSearch for recent threat events on a schedule.
    Does NOT require ZMQ or pyzmq.

Config
──────
  MISP_ZMQ_URL             tcp://your-misp-host:50000
  MISP_API_URL             https://your-misp-host
  MISP_API_KEY             <MISP auth key>
  MISP_TENANT_ID           default
  MISP_POLL_INTERVAL       300  (seconds, HTTP pull mode)
  MISP_SYSLOG_ENABLED      true  (forward domains to syslog sink)
  MISP_SYSLOG_TARGET_HOST  127.0.0.1  (syslog sink host)
  SHADOW_AI_SYSLOG_PORT    5514  (syslog sink port — shared with syslog_sink.py)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket as _socket
from datetime import UTC, datetime, timedelta
from typing import Any

log = logging.getLogger("warden.integrations.misp_bridge")

_MISP_ZMQ_URL        = os.getenv("MISP_ZMQ_URL",             "")
_MISP_API_URL        = os.getenv("MISP_API_URL",             "")
_MISP_API_KEY        = os.getenv("MISP_API_KEY",             "")
_MISP_TENANT_ID      = os.getenv("MISP_TENANT_ID",           "default")
_MISP_POLL_INTERVAL  = int(os.getenv("MISP_POLL_INTERVAL",   "300"))
_SYSLOG_ENABLED      = os.getenv("MISP_SYSLOG_ENABLED",      "true").lower() == "true"
_SYSLOG_TARGET_HOST  = os.getenv("MISP_SYSLOG_TARGET_HOST",  "127.0.0.1")
_SYSLOG_TARGET_PORT  = int(os.getenv("SHADOW_AI_SYSLOG_PORT","5514"))

# IoC attribute types Warden cares about
_DOMAIN_TYPES = {"domain", "hostname", "domain|ip"}
_IP_TYPES     = {"ip-dst", "ip-src", "ip-dst|port", "ip-src|port"}
_ALL_TYPES    = _DOMAIN_TYPES | _IP_TYPES | {"url"}
_BLOCK_TYPES  = _ALL_TYPES  # public alias used by tests + external consumers

# ── Stats ─────────────────────────────────────────────────────────────────────

_BRIDGE_STATS: dict[str, Any] = {
    "zmq_events":        0,
    "http_events":       0,
    "attrs_ingested":    0,
    "domains_classified":0,
    "ips_blocked":       0,
    "syslog_forwarded":  0,
    "errors":            0,
    "last_event_ts":     None,
}


def get_bridge_stats() -> dict[str, Any]:
    return dict(_BRIDGE_STATS)


# ── Syslog forwarding ─────────────────────────────────────────────────────────

def _forward_domain_to_syslog(domain: str) -> None:
    """
    Format domain as dnsmasq query line and UDP-send to the syslog sink.

    Format:  query[A] <domain> from 127.0.0.1
    Matches: syslog_sink._RE_DNSMASQ → classify_dns_event()
    """
    line = f"query[A] {domain} from 127.0.0.1".encode()
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.sendto(line, (_SYSLOG_TARGET_HOST, _SYSLOG_TARGET_PORT))
        _BRIDGE_STATS["syslog_forwarded"] += 1
    except Exception as exc:
        log.debug("misp_bridge: syslog forward failed for %s: %s", domain, exc)
        _BRIDGE_STATS["errors"] += 1


# ── IoC ingest ────────────────────────────────────────────────────────────────

def _ingest_attribute(attr: dict, event_info: str = "") -> None:
    """
    Ingest a single MISP attribute into Warden's threat pipeline.

    Domains: ShadowAIDetector.classify_dns_event() + syslog sink forwarding.
    IPs:     _threat_store.block_ip().
    """
    atype = attr.get("type", "")
    value = str(attr.get("value", "")).strip()
    if not value or atype not in _ALL_TYPES:
        return

    _BRIDGE_STATS["attrs_ingested"] += 1
    comment = f"MISP: {event_info or attr.get('comment', 'IoC')}".strip()

    # ── Domain / hostname ────────────────────────────────────────────────────
    if atype in _DOMAIN_TYPES:
        domain = value.split("|")[0].strip()
        if not domain or "." not in domain:
            return

        # Direct classification
        try:
            from warden.shadow_ai.discovery import ShadowAIDetector  # noqa: PLC0415
            ShadowAIDetector().classify_dns_event(
                domain=domain, source_ip="misp-bridge", tenant_id=_MISP_TENANT_ID
            )
            _BRIDGE_STATS["domains_classified"] += 1
        except Exception as exc:
            log.debug("misp_bridge: classify_dns_event error for %s: %s", domain, exc)

        # Syslog sink forwarding (real-time correlation with passive DNS stream)
        if _SYSLOG_ENABLED:
            _forward_domain_to_syslog(domain)

    # ── IP address ───────────────────────────────────────────────────────────
    elif atype in _IP_TYPES:
        ip = value.split("|")[0].strip()
        try:
            from warden.runtime import runtime as _runtime  # noqa: PLC0415
            _threat_store = _runtime.get("threat_store")
            if _threat_store is None:
                raise RuntimeError("threat_store not published to runtime")
            _threat_store.block_ip(
                ip=ip, tenant_id=_MISP_TENANT_ID,
                reason=comment, blocked_by="misp_bridge",
            )
            _BRIDGE_STATS["ips_blocked"] += 1
            log.info("misp_bridge: blocked IP %s (%s)", ip, comment)
        except Exception as exc:
            log.debug("misp_bridge: block_ip error for %s: %s", ip, exc)


def _process_misp_event(event_json: dict, source: str = "zmq") -> int:
    """Extract and ingest all relevant attributes from a MISP event dict."""
    event = event_json.get("Event", event_json)
    info  = event.get("info", "")

    count = 0
    for attr in event.get("Attribute", []):
        _ingest_attribute(attr, info)
        count += 1

    # Also walk objects' attributes
    for obj in event.get("Object", []):
        for attr in obj.get("Attribute", []):
            _ingest_attribute(attr, info)
            count += 1

    _BRIDGE_STATS["last_event_ts"] = datetime.now(UTC).isoformat()
    if source == "zmq":
        _BRIDGE_STATS["zmq_events"] += 1
    else:
        _BRIDGE_STATS["http_events"] += 1
    return count


# ── ZMQ subscriber ────────────────────────────────────────────────────────────

async def _zmq_loop() -> None:
    """Subscribe to MISP ZMQ and process events indefinitely."""
    try:
        import zmq  # noqa: PLC0415
        import zmq.asyncio as azmq  # noqa: PLC0415
    except ImportError:
        log.warning("misp_bridge: pyzmq not installed — ZMQ mode unavailable")
        return

    ctx = azmq.Context()
    sock = ctx.socket(zmq.SUB)
    sock.connect(_MISP_ZMQ_URL)
    sock.setsockopt_string(zmq.SUBSCRIBE, "misp_json")
    log.info("misp_bridge: ZMQ subscribed to %s", _MISP_ZMQ_URL)

    while True:
        try:
            # MISP sends either multipart [topic, payload] or single "topic json"
            parts = await sock.recv_multipart()
            if len(parts) >= 2:
                payload = parts[1]
            else:
                # Single-frame: "topic {json}"
                _, _, payload_str = parts[0].decode(errors="replace").partition(" ")
                payload = payload_str.encode()

            event_json = json.loads(payload)
            count = _process_misp_event(event_json, source="zmq")
            log.debug("misp_bridge: ZMQ event processed, %d attrs", count)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("misp_bridge ZMQ error: %s", exc)
            _BRIDGE_STATS["errors"] += 1
            await asyncio.sleep(5)

    sock.close()
    ctx.term()
    log.info("misp_bridge: ZMQ loop stopped")


# ── HTTP pull loop ────────────────────────────────────────────────────────────

async def _http_poll_loop() -> None:
    """Poll MISP REST API for recent events every _MISP_POLL_INTERVAL seconds."""
    import httpx  # noqa: PLC0415

    log.info(
        "misp_bridge: HTTP poll mode — %s every %ds",
        _MISP_API_URL, _MISP_POLL_INTERVAL,
    )
    while True:
        try:
            since = (
                datetime.now(UTC) - timedelta(seconds=_MISP_POLL_INTERVAL * 2)
            ).strftime("%Y-%m-%d")
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:  # noqa: S501
                resp = await client.post(
                    f"{_MISP_API_URL.rstrip('/')}/events/restSearch",
                    headers={
                        "Authorization": _MISP_API_KEY,
                        "Accept":        "application/json",
                        "Content-Type":  "application/json",
                    },
                    json={
                        "returnFormat": "json",
                        "timestamp":    since,
                        "threat_level_id": [1, 2],
                    },
                )
                if resp.status_code == 200:
                    events = resp.json().get("response", [])
                    total  = sum(
                        _process_misp_event(e, source="http") for e in events
                    )
                    if total:
                        log.info(
                            "misp_bridge: HTTP pulled %d events (%d attrs)",
                            len(events), total,
                        )
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("misp_bridge HTTP poll error: %s", exc)
            _BRIDGE_STATS["errors"] += 1

        await asyncio.sleep(_MISP_POLL_INTERVAL)


# ── Public start function ─────────────────────────────────────────────────────

async def start_misp_bridge() -> None:
    """
    Auto-select ZMQ (preferred) or HTTP poll mode based on env vars.
    Safe to call when MISP is not configured — exits immediately.
    """
    if _MISP_ZMQ_URL:
        log.info(
            "misp_bridge: starting ZMQ mode (syslog_forward=%s target=%s:%d)",
            _SYSLOG_ENABLED, _SYSLOG_TARGET_HOST, _SYSLOG_TARGET_PORT,
        )
        await _zmq_loop()
    elif _MISP_API_URL and _MISP_API_KEY:
        log.info(
            "misp_bridge: starting HTTP poll mode (syslog_forward=%s)",
            _SYSLOG_ENABLED,
        )
        await _http_poll_loop()
    else:
        log.debug(
            "misp_bridge: not started (set MISP_ZMQ_URL or MISP_API_URL+MISP_API_KEY)"
        )
