"""warden/marketplace/api.py — Marketplace aggregator router.

All domain endpoints live in domain-specific sub-modules:
  api_agents.py       — /agents*
  api_assets.py       — /assets*
  api_listings.py     — /listings*, /purchases
  api_negotiations.py — /negotiations*
  api_escrow.py       — /escrow*, /escrows

This file owns: /stats, /analytics/*, and the shared _require_marketplace_gate helper.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Query

log = logging.getLogger("warden.marketplace.api")

router = APIRouter(prefix="/marketplace", tags=["Marketplace"])

# Sub-routers are included directly on the FastAPI app (in main.py) with
# prefix="/marketplace" to avoid FastAPI _IncludedRouter nesting issues.


def _require_marketplace_gate() -> None:
    try:
        from warden.billing.feature_gate import require_feature
        require_feature("marketplace_enabled")
    except Exception:
        pass   # fail-open when billing module not configured


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def marketplace_stats(
    tenant_id: str | None = Query(default=None),
) -> dict:
    from warden.marketplace.agent import list_agents as _list_agents
    from warden.marketplace.listing import get_listings
    from warden.marketplace.listing import list_purchases as _list_pur

    agents    = _list_agents(tenant_id=tenant_id, limit=1000)
    listings  = get_listings(limit=1000)
    purchases = _list_pur(limit=1000)

    active_listings  = sum(1 for lst in listings if lst.status == "active")
    completed_trades = sum(1 for p in purchases if p.status == "completed")
    pending_trades   = sum(1 for p in purchases if p.status == "pending")
    total_volume_usd = sum(p.price_paid for p in purchases if p.status == "completed")

    return {
        "agents":           len(agents),
        "active_listings":  active_listings,
        "total_listings":   len(listings),
        "completed_trades": completed_trades,
        "pending_trades":   pending_trades,
        "total_volume_usd": round(total_volume_usd, 2),
    }


# ── Analytics ─────────────────────────────────────────────────────────────────

@router.get("/analytics/summary")
async def marketplace_analytics_summary(
    tenant_id:    str | None = Query(default=None),
    community_id: str | None = Query(default=None),
    period_days:  int        = Query(default=30, ge=1, le=365),
) -> dict:
    from warden.marketplace.analytics import get_summary
    return get_summary(tenant_id=tenant_id, community_id=community_id, period_days=period_days)


@router.get("/analytics/volume")
async def marketplace_volume_series(
    tenant_id:    str | None = Query(default=None),
    community_id: str | None = Query(default=None),
    period_days:  int        = Query(default=30, ge=7, le=365),
) -> list[dict]:
    from warden.marketplace.analytics import get_volume_series
    return get_volume_series(tenant_id=tenant_id, community_id=community_id, period_days=period_days)


@router.get("/analytics/agents")
async def marketplace_agent_leaderboard(
    tenant_id:    str | None = Query(default=None),
    community_id: str | None = Query(default=None),
    limit:        int        = Query(default=10, le=50),
) -> dict:
    from warden.marketplace.analytics import get_agent_leaderboard
    return get_agent_leaderboard(tenant_id=tenant_id, community_id=community_id, limit=limit)


# ── Readiness ──────────────────────────────────────────────────────────────────

@router.get("/readiness/{community_id}")
async def marketplace_readiness(community_id: str) -> dict:
    """Check whether a community is ready to participate in the marketplace."""
    import contextlib

    from warden.marketplace.agent import list_agents as _list_agents

    community = None
    with contextlib.suppress(Exception):
        from warden.communities.registry import get_community as _get_community
        community = _get_community(community_id)
    if community is None:
        with contextlib.suppress(Exception):
            from warden.communities.community_factory import get_community as _get_community_f
            community = _get_community_f(community_id)

    community_exists = community is not None
    _settings = getattr(community, "settings", {}) or {}
    keypair_generated = bool(_settings.get("keypair_generated")) if community else False
    audit_enabled = bool(_settings.get("audit_enabled")) if community else False

    agents_registered = False
    try:
        agents = _list_agents(community_id=community_id)
        agents_registered = len(agents) > 0
    except Exception:
        pass

    missing: list[str] = []
    if not community_exists:
        missing.append("community_not_found")
    if not keypair_generated:
        missing.append("keypair_not_generated")
    if not audit_enabled:
        missing.append("audit_not_enabled")
    if not agents_registered:
        missing.append("no_agents_registered")

    return {
        "community_id":       community_id,
        "community_exists":   community_exists,
        "keypair_generated":  keypair_generated,
        "audit_enabled":      audit_enabled,
        "agents_registered":  agents_registered,
        "ready_to_trade":     community_exists and keypair_generated and audit_enabled and agents_registered,
        "missing_requirements": missing,
    }
