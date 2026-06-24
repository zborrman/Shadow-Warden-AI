"""warden/marketplace/api.py — Marketplace aggregator router.

All domain endpoints live in domain-specific sub-modules:
  api_agents.py       — /agents*
  api_assets.py       — /assets*
  api_listings.py     — /listings*, /purchases
  api_negotiations.py — /negotiations*
  api_escrow.py       — /escrow*, /escrows

This file owns: /stats, /analytics/*, /protocol, /action, /readiness/*.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

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


# ── M2M Market Environment Protocol ───────────────────────────────────────────

@router.get("/protocol")
async def get_market_protocol() -> dict:
    """Self-describing capability manifest for M2M agents.

    External agents call this once to discover supported actions, negotiation
    rules, pricing config, escrow parameters, and trust algorithms — without
    hardcoded integration knowledge.
    """
    return {
        "protocol_version": "1.0",
        "market_id": "shadow-warden-marketplace",
        "supported_actions": [
            "register_agent", "publish_listing", "purchase",
            "start_negotiation", "send_offer", "accept_offer",
            "create_escrow", "fund_escrow", "deliver_asset",
            "confirm_receipt", "raise_dispute",
        ],
        "negotiation": {
            "max_rounds": int(os.getenv("MARKETPLACE_MAX_NEGOTIATION_ROUNDS", "5")),
            "signature_type": "Ed25519",
            "message_format": "MCP-envelope-v1",
            "injection_guard": True,
            "min_offers_before_buy": int(os.getenv("MARKETPLACE_MIN_OFFERS_BEFORE_BUY", "3")),
        },
        "pricing": {
            "strategies": ["fixed", "dynamic"],
            "demand_factor": float(os.getenv("MARKETPLACE_DEMAND_FACTOR", "0.5")),
            "currencies": ["USD"],
        },
        "escrow": {
            "required": True,
            "chains": ["sepolia", "eth_tester"],
            "delivery_timeout_hours": int(os.getenv("ESCROW_DELIVERY_TIMEOUT_HOURS", "48")),
        },
        "governance": {
            "dao_enabled": os.getenv("DAO_GOVERNANCE_ENABLED", "false").lower() == "true",
            "quorum_pct": float(os.getenv("DAO_QUORUM_PCT", "0.15")),
        },
        "trust": {
            "algorithm": "weighted-pagerank",
            "sybil_guard": True,
            "maestro_threat_detection": True,
        },
    }


# ── POST /register — M2M first-contact (third required base endpoint) ─────────

class RegisterRequest(BaseModel):
    tenant_id:    str
    community_id: str
    public_key:   str
    capabilities: list[str] = ["marketplace_buy", "marketplace_sell", "marketplace_negotiate"]


@router.post("/register", status_code=201)
async def register_market_agent(body: RegisterRequest) -> dict:
    """M2M first-contact registration.

    Thin wrapper over /agents/register that serves as the canonical 'POST /register'
    entry point described in the M2M Market Environment protocol.  Runs the same
    federation deny-list check and DID derivation as the sub-router endpoint so
    external agents need only one discovery → register → protocol flow.
    """
    from warden.marketplace.api_agents import AgentRegisterRequest, register_agent
    return await register_agent(
        AgentRegisterRequest(
            tenant_id=body.tenant_id,
            community_id=body.community_id,
            public_key=body.public_key,
            capabilities=body.capabilities,
        )
    )


class MarketAction(BaseModel):
    action_type: Literal[
        "buy", "negotiate", "send_offer", "accept_offer",
        "create_escrow", "fund_escrow", "deliver_asset",
        "confirm_receipt", "raise_dispute",
    ]
    payload: dict[str, Any] = {}


_ACTION_ROUTES: dict[str, str] = {
    "buy":            "/marketplace/listings/{listing_id}/purchase",
    "negotiate":      "/marketplace/negotiations",
    "send_offer":     "/marketplace/negotiations/{negotiation_id}/offer",
    "accept_offer":   "/marketplace/negotiations/{negotiation_id}/accept",
    "create_escrow":  "/marketplace/escrow",
    "fund_escrow":    "/marketplace/escrow/{escrow_id}/fund",
    "deliver_asset":  "/marketplace/escrow/{escrow_id}/deliver",
    "confirm_receipt":"/marketplace/escrow/{escrow_id}/confirm",
    "raise_dispute":  "/marketplace/escrow/{escrow_id}/dispute",
}


@router.post("/action")
async def dispatch_action(body: MarketAction, request: Request) -> dict:
    """Unified M2M action dispatcher.

    Routes `action_type` to the appropriate sub-endpoint handler.
    All 29 existing endpoints remain unchanged; this is additive only.
    Payload keys must match the target endpoint's request body schema.
    """

    handlers: dict[str, Any] = {}
    try:
        from warden.marketplace import api_escrow, api_listings, api_negotiations
        handlers = {
            "buy":             api_listings.buy_listing,
            "negotiate":       api_negotiations.start_negotiation,
            "send_offer":      api_negotiations.send_offer,
            "accept_offer":    api_negotiations.accept_offer,
            "create_escrow":   api_escrow.create_escrow,
            "fund_escrow":     api_escrow.fund_escrow,
            "deliver_asset":   api_escrow.deliver_asset,
            "confirm_receipt": api_escrow.confirm_receipt,
            "raise_dispute":   api_escrow.raise_dispute,
        }
    except Exception as exc:
        log.warning("dispatch_action: failed to load sub-handlers: %s", exc)

    handler = handlers.get(body.action_type)
    if handler is None:
        return {
            "dispatched": False,
            "action_type": body.action_type,
            "route": _ACTION_ROUTES.get(body.action_type, "unknown"),
            "error": "Handler not available; call the sub-endpoint directly.",
        }

    try:
        result = await handler(**body.payload)  # type: ignore[operator]
        return {"dispatched": True, "action_type": body.action_type, "result": result}
    except Exception as exc:
        log.warning("dispatch_action %s failed: %s", body.action_type, exc)
        return {
            "dispatched": False,
            "action_type": body.action_type,
            "error": str(exc),
            "route": _ACTION_ROUTES.get(body.action_type),
        }


# ── Analytics query (SELECT-only, for MCP/SOVA tool #32) ──────────────────────

# Tables whose rows are partitioned by agent identity columns.
# Used by the Confused Deputy guard to detect cross-agent data access.
_AGENT_SCOPED_TABLES = frozenset({
    "marketplace_agents",
    "marketplace_listings",
    "marketplace_purchases",
    "marketplace_escrows",
    "marketplace_negotiations",
    "marketplace_offers",
})

# Column names that carry agent identity in those tables.
_AGENT_ID_COLUMNS = frozenset({
    "agent_id", "buyer_agent_id", "seller_agent_id", "from_agent_id",
})


def _confused_deputy_check(stmt: str, caller_agent_id: str) -> str | None:
    """Return an error string if the SQL references a foreign agent's DID.

    Scans for patterns like `agent_id = 'did:shadow:...'` where the literal
    value differs from the caller's own DID.  This is a first-layer heuristic
    guard; a proper implementation uses row-level security views.
    Returns None when the query is safe to execute.
    """
    import re
    col_pattern = "|".join(re.escape(c) for c in _AGENT_ID_COLUMNS)
    for match in re.finditer(
        rf"(?:{col_pattern})\s*=\s*['\"]([^'\"]+)['\"]",
        stmt,
        re.IGNORECASE,
    ):
        literal = match.group(1)
        if literal != caller_agent_id:
            return (
                f"Confused Deputy: query references agent '{literal}' "
                f"but caller is '{caller_agent_id}'. "
                "Scope your query to your own agent_id or omit the filter."
            )
    return None


class AnalyticsQuery(BaseModel):
    sql: str
    params: list[Any] = []
    caller_agent_id: str | None = None  # set by MCP client or SOVA tool


@router.post("/analytics/query")
async def analytics_sql_query(body: AnalyticsQuery, request: Request) -> dict:
    """Execute a read-only SQL SELECT against the marketplace DB.

    Used by SOVA tool #32 (query_marketplace_db) and MCP marketplace-db server.

    Security layers:
    1. SELECT-only gate — rejects any non-SELECT statement.
    2. Confused Deputy guard — if `caller_agent_id` is set (via body or
       X-Agent-ID header), rejects queries that reference a different agent's
       DID literal.  This prevents one MCP client from reading another agent's
       escrows, negotiations, or listings.
    """
    import sqlite3

    stmt = body.sql.strip()
    if not stmt.upper().startswith("SELECT"):
        return {"error": "Only SELECT statements are permitted.", "rows": []}

    # Resolve caller identity: body field takes priority over header.
    caller_id = body.caller_agent_id or request.headers.get("X-Agent-ID")
    if caller_id:
        err = _confused_deputy_check(stmt, caller_id)
        if err:
            log.warning("analytics_sql_query: confused deputy rejected caller=%s", caller_id[:40])
            return {"error": err, "rows": []}

    db_path = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    try:
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        cur = con.execute(stmt, body.params)
        rows = [dict(r) for r in cur.fetchmany(500)]  # cap at 500 rows
        con.close()
        return {"rows": rows, "count": len(rows), "scoped_by": caller_id}
    except Exception as exc:
        log.warning("analytics_sql_query error: %s", exc)
        return {"error": str(exc), "rows": []}


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


@router.get("/analytics/fairness")
async def marketplace_fairness_stats(
    period_days: int = Query(default=7, ge=1, le=90),
) -> dict:
    """First-Proposal Bias metrics — avg alternatives evaluated per purchase."""
    from warden.marketplace.analytics import fairness_stats
    return fairness_stats(period_days=period_days)


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

    community: object = None
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
