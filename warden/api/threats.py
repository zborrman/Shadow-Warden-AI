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

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from warden.auth_guard import AuthResult, require_api_key
from warden.runtime import runtime

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
