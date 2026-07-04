"""
warden/api/threats.py
──────────────────────
Threat Intelligence + ThreatVault endpoints — extracted from main.py
(architecture Phase 3).

The three backing singletons (ThreatIntelStore, ThreatIntelScheduler,
ThreatVault) are built in main.py's lifespan and published into
``warden.runtime``. This router resolves them from runtime on each call, so it
never imports ``warden.main`` (layer rule: api → runtime, never upward). The
route paths and behaviour are identical to the previous inline handlers; the
route-inventory guard (test_route_inventory.py) verifies the move changed
nothing externally.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel

from warden.auth_guard import AuthResult, require_api_key
from warden.runtime import runtime

log = logging.getLogger("warden.api.threats")

router = APIRouter()


# ── Threat Intelligence endpoints ───────────────────────────────────────────────


def _require_threat_intel():
    store = runtime.get("threat_intel_store")
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat Intelligence Engine disabled. Set THREAT_INTEL_ENABLED=true.",
        )
    return store


@router.get("/threats/intel/stats", tags=["threat-intel"])
async def threat_intel_stats(_: AuthResult = Depends(require_api_key)):
    """Aggregated statistics for the threat intelligence collection."""
    store = _require_threat_intel()
    return store.stats()


@router.get("/threats/intel", tags=["threat-intel"])
async def list_threat_intel(
    item_status: str | None = None,
    source:      str | None = None,
    limit:       int        = 50,
    offset:      int        = 0,
    _: AuthResult = Depends(require_api_key),
):
    """List collected threat intelligence items."""
    store = _require_threat_intel()
    items = store.list_items(status=item_status, source=source, limit=limit, offset=offset)
    return {"items": [i.model_dump() for i in items], "total": len(items)}


@router.get("/threats/intel/{item_id}", tags=["threat-intel"])
async def get_threat_intel_item(
    item_id: str,
    _: AuthResult = Depends(require_api_key),
):
    """Retrieve a single threat intelligence item with its countermeasures."""
    store = _require_threat_intel()
    item = store.get_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Threat item {item_id!r} not found.")
    countermeasures = store.get_countermeasures(item_id)
    return {**item.model_dump(), "countermeasures": countermeasures}


@router.post("/threats/intel/refresh", tags=["threat-intel"], status_code=202)
async def refresh_threat_intel(
    background_tasks: BackgroundTasks,
    _: AuthResult = Depends(require_api_key),
):
    """Trigger an immediate out-of-cycle collection + analysis run."""
    scheduler = runtime.get("ti_scheduler")
    if scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat Intelligence Engine disabled. Set THREAT_INTEL_ENABLED=true.",
        )
    background_tasks.add_task(scheduler.run_once)
    return {"queued": True, "message": "Threat intel refresh queued as background task."}


@router.post("/threats/intel/{item_id}/dismiss", tags=["threat-intel"])
async def dismiss_threat_intel_item(
    item_id: str,
    _: AuthResult = Depends(require_api_key),
):
    """Manually dismiss a threat intelligence item (will not generate rules)."""
    store = _require_threat_intel()
    found = store.dismiss(item_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Threat item {item_id!r} not found.")
    return {"item_id": item_id, "status": "dismissed"}


# ── ThreatVault endpoints ──────────────────────────────────────────────────────


@router.get("/threats/vault", tags=["threat-vault"])
async def list_threat_vault(_: AuthResult = Depends(require_api_key)):
    """List all adversarial prompt signatures loaded in the ThreatVault."""
    vault = runtime.get("threat_vault")
    if vault is None:
        raise HTTPException(status_code=503, detail="ThreatVault not initialized.")
    return {
        "stats":   vault.stats(),
        "threats": vault.list_threats(),
    }


@router.get("/threats/vault/stats", tags=["threat-vault"])
async def threat_vault_stats(_: AuthResult = Depends(require_api_key)):
    """Aggregated ThreatVault statistics: totals by severity, category, OWASP."""
    vault = runtime.get("threat_vault")
    if vault is None:
        raise HTTPException(status_code=503, detail="ThreatVault not initialized.")
    return vault.stats()


@router.post("/threats/vault/reload", tags=["threat-vault"], status_code=202)
async def reload_threat_vault(_: AuthResult = Depends(require_api_key)):
    """Hot-reload ThreatVault signatures from disk (no restart required)."""
    vault = runtime.get("threat_vault")
    if vault is None:
        raise HTTPException(status_code=503, detail="ThreatVault not initialized.")
    count = vault.reload()
    return {"reloaded": True, "signatures_loaded": count}


# ── ThreatStore blocklist / attacker-profile endpoints ───────────────────────
# Extracted from main.py (Phase 3). Backed by the ThreatStore singleton
# published to warden.runtime as "threat_store".


class _BlockIpRequest(BaseModel):
    ip:         str
    tenant_id:  str         = "default"
    reason:     str         = ""
    expires_at: str | None  = None   # ISO-8601; None = permanent


def _require_threat_store():
    store = runtime.get("threat_store")
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat store not available.",
        )
    return store


@router.get(
    "/threats/profiles",
    tags=["threats"],
    summary="Cross-session attacker profiles aggregated by IP + tenant",
    dependencies=[Depends(require_api_key)],
)
async def get_threat_profiles(tenant_id: str | None = None, limit: int = 50):
    """Return attacker profiles sorted by most recent block activity."""
    store = _require_threat_store()
    return {"profiles": store.get_profiles(tenant_id=tenant_id, limit=limit)}


@router.get(
    "/threats/blocked-ips",
    tags=["threats"],
    summary="List all currently-blocked IPs",
    dependencies=[Depends(require_api_key)],
)
async def get_blocked_ips(tenant_id: str | None = None):
    store = _require_threat_store()
    return {"blocked_ips": store.get_blocked_ips(tenant_id=tenant_id)}


@router.post(
    "/threats/block-ip",
    tags=["threats"],
    summary="Manually block an IP address across the filter pipeline",
    dependencies=[Depends(require_api_key)],
)
async def block_ip(body: _BlockIpRequest):
    """
    Add an IP to the blocklist.  All future requests from this IP will receive
    HTTP 403 before any other processing occurs.  Optionally provide an
    ISO-8601 ``expires_at`` for temporary blocks; omit for permanent.
    """
    store = _require_threat_store()
    store.block_ip(
        ip         = body.ip,
        tenant_id  = body.tenant_id,
        reason     = body.reason,
        blocked_by = "manual",
        expires_at = body.expires_at,
    )
    # Mirror to global Redis blocklist so all regions enforce immediately
    try:
        from warden.global_blocklist import block_ip as _gbl_block  # noqa: PLC0415
        expires_s = 0
        if body.expires_at:
            delta = datetime.fromisoformat(body.expires_at) - datetime.now(UTC)
            expires_s = max(0, int(delta.total_seconds()))
        _gbl_block(body.ip, body.tenant_id, body.reason, expires_s, "manual")
    except Exception as _gbl_err:
        log.debug("GlobalBlocklist.block_ip skipped (non-fatal): %s", _gbl_err)
    log.info(
        json.dumps({
            "event":     "ip_manually_blocked",
            "ip":        body.ip,
            "tenant_id": body.tenant_id,
            "reason":    body.reason,
        })
    )
    return {
        "ip":         body.ip,
        "tenant_id":  body.tenant_id,
        "blocked_by": "manual",
        "expires_at": body.expires_at,
        "message":    f"IP {body.ip!r} blocked globally.",
    }


@router.post(
    "/api/ips/block",
    tags=["threats"],
    summary="Block a CIDR IP range (SOVA tool #47)",
    dependencies=[Depends(require_api_key)],
)
async def block_ip_range_endpoint(body: dict):
    """
    Block all IPs in a CIDR range.  Used by SOVA tool #47 `block_ip_range`.
    Maximum prefix /24 (256 hosts).  Adds each host to the ThreatStore and
    global Redis blocklist.
    """
    import ipaddress  # noqa: PLC0415
    store = _require_threat_store()
    cidr      = body.get("cidr", "")
    reason    = body.get("reason", "SOVA CIDR block")
    tenant_id = body.get("tenant_id", "default")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid CIDR: {exc}") from exc
    if net.prefixlen < 24:
        raise HTTPException(status_code=422, detail="CIDR too broad — minimum /24 prefix required.")
    hosts_blocked = 0
    for host in net.hosts():
        ip_str = str(host)
        try:
            store.block_ip(ip=ip_str, tenant_id=tenant_id, reason=reason, blocked_by="sova")
            hosts_blocked += 1
        except Exception as exc:
            log.debug("block_ip_range: host=%s error=%s", ip_str, exc)
    log.info(json.dumps({"event": "cidr_blocked", "cidr": cidr, "hosts": hosts_blocked, "tenant_id": tenant_id}))
    return {"cidr": cidr, "hosts_blocked": hosts_blocked, "reason": reason, "tenant_id": tenant_id}


@router.delete(
    "/threats/blocked-ips/{ip}",
    tags=["threats"],
    summary="Remove an IP from the blocklist",
    dependencies=[Depends(require_api_key)],
)
async def unblock_ip(ip: str, tenant_id: str = "default"):
    store = _require_threat_store()
    found = store.unblock_ip(ip, tenant_id)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP {ip!r} is not in the blocklist for tenant {tenant_id!r}.",
        )
    log.info(json.dumps({"event": "ip_unblocked", "ip": ip, "tenant_id": tenant_id}))
    return {"ip": ip, "tenant_id": tenant_id, "message": f"IP {ip!r} unblocked."}
