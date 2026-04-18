"""
warden/sovereign/tunnel.py
──────────────────────────
MASQUE Jurisdictional Tunnel registry.

A MASQUETunnel is a MASQUE-over-HTTP/3 proxy endpoint (RFC 9298 / RFC 9484)
that routes AI API traffic through a specific geographic jurisdiction.
Warden's /filter pipeline can proxy upstream AI calls through the tunnel
corresponding to the tenant's home jurisdiction, ensuring data never crosses
an unauthorized border.

Tunnel lifecycle:
  PENDING  → ACTIVE   (first successful health-check)
  ACTIVE   → DEGRADED (health check fails but not all probes lost)
  DEGRADED → OFFLINE  (all probes lost for OFFLINE_AFTER_FAILS consecutive checks)
  OFFLINE  → ACTIVE   (manual reactivation or auto-recovery)

Storage: Redis hash `sovereign:tunnel:{tunnel_id}` (no TTL).
Falls back to in-process dict when Redis unavailable.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Literal

log = logging.getLogger("warden.sovereign.tunnel")

TunnelStatus   = Literal["PENDING", "ACTIVE", "DEGRADED", "OFFLINE"]
TunnelProtocol = Literal["MASQUE_H3", "MASQUE_H2", "CONNECT_TCP", "DIRECT"]

_OFFLINE_AFTER_FAILS = int(os.getenv("TUNNEL_OFFLINE_AFTER_FAILS", "5"))

_MEMORY_TUNNELS: dict[str, dict] = {}


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class MASQUETunnel:
    tunnel_id:       str
    jurisdiction:    str          # "EU", "US", etc.
    region:          str          # "eu-west-1"
    endpoint:        str          # "masque-eu.shadow-warden.net:443"
    protocol:        TunnelProtocol
    status:          TunnelStatus
    tls_fingerprint: str          # SHA-256 of server cert (TOFU pinning)
    created_at:      str
    last_seen_at:    str
    fail_count:      int
    tenant_id:       str | None   # None = shared; else tenant-dedicated tunnel
    tags:            list[str]    # e.g. ["GDPR", "EU_AI_ACT"]
    latency_ms:      float | None # last measured round-trip latency


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _save(tunnel: MASQUETunnel) -> None:
    d = asdict(tunnel)
    _MEMORY_TUNNELS[tunnel.tunnel_id] = d
    r = _redis()
    if r:
        try:
            r.hset(f"sovereign:tunnel:{tunnel.tunnel_id}", mapping={
                k: json.dumps(v) if isinstance(v, (list, dict)) else str(v) if v is not None else ""
                for k, v in d.items()
            })
            r.sadd("sovereign:tunnels", tunnel.tunnel_id)
        except Exception as exc:
            log.debug("tunnel _save redis error: %s", exc)


def _load(tunnel_id: str) -> dict | None:
    r = _redis()
    if r:
        try:
            raw = r.hgetall(f"sovereign:tunnel:{tunnel_id}")
            if raw:
                d = {}
                for k, v in raw.items():
                    try:
                        d[k] = json.loads(v)
                    except Exception:
                        d[k] = v if v != "" else None
                return d
        except Exception as exc:
            log.debug("tunnel _load redis error: %s", exc)
    return _MEMORY_TUNNELS.get(tunnel_id)


def _all_ids() -> list[str]:
    r = _redis()
    if r:
        try:
            return list(r.smembers("sovereign:tunnels"))
        except Exception:
            pass
    return list(_MEMORY_TUNNELS.keys())


# ── Public API ────────────────────────────────────────────────────────────────

def register_tunnel(
    jurisdiction:    str,
    region:          str,
    endpoint:        str,
    protocol:        TunnelProtocol = "MASQUE_H3",
    tls_fingerprint: str            = "",
    tenant_id:       str | None     = None,
    tags:            list[str]      = (),   # type: ignore[assignment]
) -> MASQUETunnel:
    """
    Register a new MASQUE tunnel and persist it to Redis.

    `tls_fingerprint` should be the SHA-256 hex of the proxy server's leaf
    certificate — used for Trust-On-First-Use (TOFU) pinning.  If not
    supplied, it is derived as a placeholder from the endpoint string.
    """
    from warden.sovereign.jurisdictions import get_jurisdiction
    j = get_jurisdiction(jurisdiction)
    if not j:
        raise ValueError(f"Unknown jurisdiction: {jurisdiction!r}")
    if region not in j.cloud_regions:
        raise ValueError(f"Region {region!r} is not in jurisdiction {jurisdiction!r}.")

    now = datetime.now(UTC).isoformat()
    fp  = tls_fingerprint or hashlib.sha256(endpoint.encode()).hexdigest()

    tunnel = MASQUETunnel(
        tunnel_id       = f"t-{uuid.uuid4().hex[:12]}",
        jurisdiction    = jurisdiction.upper(),
        region          = region,
        endpoint        = endpoint,
        protocol        = protocol,
        status          = "PENDING",
        tls_fingerprint = fp,
        created_at      = now,
        last_seen_at    = now,
        fail_count      = 0,
        tenant_id       = tenant_id,
        tags            = list(tags) or list(j.frameworks),
        latency_ms      = None,
    )
    _save(tunnel)
    log.info("Registered MASQUE tunnel %s → %s (%s)", tunnel.tunnel_id, endpoint, jurisdiction)
    return tunnel


def get_tunnel(tunnel_id: str) -> MASQUETunnel | None:
    d = _load(tunnel_id)
    if not d:
        return None
    return MASQUETunnel(**{k: d.get(k) for k in MASQUETunnel.__dataclass_fields__})


def list_tunnels(
    jurisdiction: str | None = None,
    tenant_id:    str | None = None,
    status:       str | None = None,
) -> list[MASQUETunnel]:
    tunnels: list[MASQUETunnel] = []
    for tid in _all_ids():
        t = get_tunnel(tid)
        if not t:
            continue
        if jurisdiction and t.jurisdiction != jurisdiction.upper():
            continue
        if tenant_id and t.tenant_id not in (tenant_id, None):
            continue
        if status and t.status != status:
            continue
        tunnels.append(t)
    return sorted(tunnels, key=lambda t: t.created_at, reverse=True)


def update_tunnel_status(
    tunnel_id: str,
    status:    TunnelStatus,
    latency_ms: float | None = None,
) -> MASQUETunnel | None:
    t = get_tunnel(tunnel_id)
    if not t:
        return None
    t.status       = status
    t.last_seen_at = datetime.now(UTC).isoformat()
    if latency_ms is not None:
        t.latency_ms = latency_ms
    if status == "ACTIVE":
        t.fail_count = 0
    _save(t)
    return t


def record_tunnel_failure(tunnel_id: str) -> TunnelStatus:
    """
    Increment fail counter.  Transitions ACTIVE → DEGRADED → OFFLINE
    after _OFFLINE_AFTER_FAILS consecutive failures.
    """
    t = get_tunnel(tunnel_id)
    if not t:
        return "OFFLINE"
    t.fail_count  += 1
    t.last_seen_at = datetime.now(UTC).isoformat()
    if t.fail_count >= _OFFLINE_AFTER_FAILS:
        t.status = "OFFLINE"
    elif t.fail_count >= 2:
        t.status = "DEGRADED"
    _save(t)
    return t.status


async def probe_tunnel(tunnel_id: str) -> dict:
    """
    Health-check a MASQUE tunnel by measuring TCP round-trip to its endpoint.
    Updates status and latency_ms in Redis.
    Returns {"tunnel_id", "status", "latency_ms", "error"}.
    """
    import asyncio
    t = get_tunnel(tunnel_id)
    if not t:
        return {"tunnel_id": tunnel_id, "status": "OFFLINE", "error": "not found"}

    host, _, port_str = t.endpoint.rpartition(":")
    port = int(port_str) if port_str.isdigit() else 443
    t0   = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5.0
        )
        writer.close()
        await writer.wait_closed()
        latency = round((time.perf_counter() - t0) * 1000, 1)
        update_tunnel_status(tunnel_id, "ACTIVE", latency_ms=latency)
        return {"tunnel_id": tunnel_id, "status": "ACTIVE", "latency_ms": latency}
    except Exception as exc:
        new_status = record_tunnel_failure(tunnel_id)
        return {"tunnel_id": tunnel_id, "status": new_status, "error": str(exc)}


def deactivate_tunnel(tunnel_id: str) -> bool:
    t = get_tunnel(tunnel_id)
    if not t:
        return False
    t.status = "OFFLINE"
    _save(t)
    return True
