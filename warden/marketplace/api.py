"""warden/marketplace/api.py — Marketplace aggregator router.

All domain endpoints live in domain-specific sub-modules:
  api_agents.py       — /agents*
  api_assets.py       — /assets*
  api_listings.py     — /listings*, /purchases
  api_negotiations.py — /negotiations*
  api_escrow.py       — /escrow*, /escrows

This file owns: /stats, /analytics/*, /protocol, /protocol/schema, /action, /clear, /readiness/*.

4-stage M2M lifecycle:
  Stage 1: POST /register + GET /protocol (protocol discovery + Brand Agent registration)
  Stage 2: POST /action {action_type: "search"} (semantic listing search)
  Stage 3: POST /action {action_type: "send_proposal"|"send_message"|...} (multi-agent comms)
  Stage 4: POST /action {action_type: "sending_payments"} + POST /clear (clearing + escrow)
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time
import uuid
from typing import Any, Literal

from fastapi import APIRouter, Query, Request, Response
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
async def get_market_protocol(response: Response) -> dict:
    """Self-describing capability manifest for M2M agents.

    Agents call GET /protocol on startup and periodically to discover supported
    actions, negotiation rules, pricing config, escrow parameters, and trust
    algorithms.  X-Protocol-Version and Cache-Control headers allow agents to
    do conditional polling without re-parsing unchanged manifests.

    All 4 M2M lifecycle stages are represented in supported_actions.
    """
    response.headers["X-Protocol-Version"] = "1.1"
    response.headers["Cache-Control"] = "max-age=300"
    return {
        "protocol_version": "1.0",
        "protocol_manifest_version": "1.1",
        "market_id": "shadow-warden-marketplace",
        "updated_at": "2026-06-24T00:00:00Z",
        "supported_actions": [
            # Stage 1: Registration & discovery
            "register_agent", "publish_listing",
            # Stage 2: Intelligent search
            "search", "purchase",
            # Stage 3: Multi-agent communication
            "start_negotiation", "send_offer", "accept_offer",
            "send_message", "send_proposal",
            # Stage 4: Final transaction & clearing
            "create_escrow", "fund_escrow", "sending_payments",
            "deliver_asset", "confirm_receipt", "raise_dispute",
            "reject_proposal",
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
        "brand_agent": {
            "enabled": True,
            "min_trust_score": float(os.getenv("BRAND_AGENT_MIN_TRUST", "0.0")),
            "rate_limit_rpm": int(os.getenv("BRAND_AGENT_MAX_RPM", "60")),
        },
        "schema_discovery": "/marketplace/protocol/schema/{action_name}",
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
        # Stage 1: existing
        "buy", "negotiate", "send_offer", "accept_offer",
        "create_escrow", "fund_escrow", "deliver_asset",
        "confirm_receipt", "raise_dispute",
        # Stage 2: search
        "search",
        # Stage 3: multi-agent communication
        "send_message", "send_proposal",
        # Stage 4: clearing
        "sending_payments", "reject_proposal",
    ]
    payload: dict[str, Any] = {}


_ACTION_ROUTES: dict[str, str] = {
    "buy":             "/marketplace/listings/{listing_id}/purchase",
    "negotiate":       "/marketplace/negotiations",
    "send_offer":      "/marketplace/negotiations/{negotiation_id}/offer",
    "accept_offer":    "/marketplace/negotiations/{negotiation_id}/accept",
    "create_escrow":   "/marketplace/escrow",
    "fund_escrow":     "/marketplace/escrow/{escrow_id}/fund",
    "deliver_asset":   "/marketplace/escrow/{escrow_id}/deliver",
    "confirm_receipt": "/marketplace/escrow/{escrow_id}/confirm",
    "raise_dispute":   "/marketplace/escrow/{escrow_id}/dispute",
    # Stage 2
    "search":          "/marketplace/listings/search",
    # Stage 3
    "send_message":    "/marketplace/negotiations/{negotiation_id}/message",
    "send_proposal":   "/marketplace/proposals",
    # Stage 4
    "sending_payments": "/marketplace/escrow/{escrow_id}/fund",
    "reject_proposal":  "/marketplace/negotiations/{negotiation_id}/reject",
}

# Actions that are routed TO a seller — Brand Agent validates the buyer first.
_SELLER_FACING = frozenset({
    "send_proposal", "send_offer", "send_message", "negotiate", "buy",
})


# ── Inline handlers for Stage 2–4 actions ─────────────────────────────────────

async def _action_search(
    query: str = "",
    limit: int = 10,
    asset_type: str | None = None,
    **_: Any,
) -> dict:
    """Stage 2: semantic listing search via pgvector / SQLite fallback."""
    from warden.marketplace.vector_search import semantic_search  # noqa: PLC0415

    results = await semantic_search(query, limit=limit, asset_type=asset_type)
    return {"results": results, "count": len(results), "query": query}


def _ensure_table(db_path: str, ddl: str) -> None:
    con = sqlite3.connect(db_path)
    con.execute(ddl)
    con.commit()
    con.close()


async def _action_send_message(
    negotiation_id: str = "",
    from_agent_id: str = "",
    message: str = "",
    **_: Any,
) -> dict:
    """Stage 3: send a text message within an active negotiation channel."""
    db_path = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    _ensure_table(db_path, """
        CREATE TABLE IF NOT EXISTS marketplace_messages (
            msg_id          TEXT PRIMARY KEY,
            negotiation_id  TEXT NOT NULL,
            from_agent_id   TEXT NOT NULL,
            message         TEXT NOT NULL,
            created_at      REAL NOT NULL
        )
    """)
    msg_id = str(uuid.uuid4())[:12]
    con = sqlite3.connect(db_path)
    con.execute(
        "INSERT INTO marketplace_messages VALUES (?,?,?,?,?)",
        (msg_id, negotiation_id, from_agent_id, message[:5000], time.time()),
    )
    con.commit()
    con.close()
    return {"msg_id": msg_id, "negotiation_id": negotiation_id, "status": "sent"}


async def _action_send_proposal(
    buyer_agent_id: str = "",
    seller_agent_id: str = "",
    listing_id: str = "",
    quantity: int = 1,
    max_price_per_unit: float = 0.0,
    sla_hours: int = 24,
    message: str = "",
    **_: Any,
) -> dict:
    """Stage 3: send a structured order proposal (quantity + SLA + max price)."""
    db_path = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    _ensure_table(db_path, """
        CREATE TABLE IF NOT EXISTS marketplace_proposals (
            proposal_id         TEXT PRIMARY KEY,
            buyer_agent_id      TEXT NOT NULL,
            seller_agent_id     TEXT NOT NULL,
            listing_id          TEXT NOT NULL,
            quantity            INTEGER NOT NULL DEFAULT 1,
            max_price_per_unit  REAL    NOT NULL DEFAULT 0,
            sla_hours           INTEGER NOT NULL DEFAULT 24,
            message             TEXT    NOT NULL DEFAULT '',
            status              TEXT    NOT NULL DEFAULT 'pending',
            created_at          REAL    NOT NULL
        )
    """)
    proposal_id = str(uuid.uuid4())[:16]
    con = sqlite3.connect(db_path)
    con.execute(
        "INSERT INTO marketplace_proposals VALUES (?,?,?,?,?,?,?,?,'pending',?)",
        (
            proposal_id, buyer_agent_id, seller_agent_id, listing_id,
            quantity, max_price_per_unit, sla_hours, message[:5000], time.time(),
        ),
    )
    con.commit()
    con.close()
    return {
        "proposal_id":    proposal_id,
        "status":         "sent",
        "buyer_agent_id": buyer_agent_id,
        "seller_agent_id": seller_agent_id,
        "listing_id":     listing_id,
        "quantity":       quantity,
        "max_price_per_unit": max_price_per_unit,
        "sla_hours":      sla_hours,
    }


async def _action_reject_proposal(
    negotiation_id: str = "",
    buyer_agent_id: str = "",
    reason: str = "rejected_by_buyer",
    **_: Any,
) -> dict:
    """Stage 4: explicitly reject a single negotiation proposal."""
    db_path = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    try:
        con = sqlite3.connect(db_path)
        con.execute(
            "UPDATE marketplace_negotiations SET status=? "
            "WHERE negotiation_id=? AND buyer_agent_id=?",
            (reason, negotiation_id, buyer_agent_id),
        )
        con.commit()
        affected = con.execute("SELECT changes()").fetchone()[0]
        con.close()
        return {
            "negotiation_id": negotiation_id,
            "status":         reason,
            "updated":        affected > 0,
        }
    except Exception as exc:
        return {"negotiation_id": negotiation_id, "error": str(exc)}


@router.post("/action")
async def dispatch_action(body: MarketAction, request: Request) -> dict:
    """Unified M2M action dispatcher (all 4 lifecycle stages).

    Stage 1 (Registration) → POST /register (separate endpoint)
    Stage 2 (Search)       → action_type="search"
    Stage 3 (Negotiate)    → action_type="send_proposal"|"send_offer"|"send_message"|...
    Stage 4 (Clear)        → action_type="sending_payments"|"reject_proposal"

    For seller-facing actions (send_proposal, send_offer, send_message, negotiate, buy)
    the Brand Agent filter validates the buyer's identity, trust score, and rate before
    routing the request to the seller's catalog.
    """
    # Brand Agent gate — runs before any handler for seller-facing actions
    if body.action_type in _SELLER_FACING:
        buyer_did = (
            body.payload.get("buyer_agent_id")
            or body.payload.get("from_agent_id")
            or request.headers.get("X-Agent-ID", "")
        )
        if buyer_did:
            try:
                from warden.marketplace.brand_agent import BrandAgentFilter  # noqa: PLC0415

                verdict = await BrandAgentFilter().validate(
                    buyer_did, body.action_type, body.payload
                )
                if not verdict.allowed:
                    log.info(
                        "dispatch_action: Brand Agent blocked buyer=%s action=%s reason=%s",
                        buyer_did[:32], body.action_type, verdict.reason,
                    )
                    return {
                        "brand_agent_blocked": True,
                        "action_type":         body.action_type,
                        "reason":              verdict.reason,
                        "checks":              verdict.checks,
                    }
            except Exception as exc:
                log.debug("dispatch_action: brand agent fail-open: %s", exc)

    # Load sub-module handlers (existing 9 types)
    handlers: dict[str, Any] = {
        # Stage 2
        "search":          _action_search,
        # Stage 3
        "send_message":    _action_send_message,
        "send_proposal":   _action_send_proposal,
        # Stage 4
        "reject_proposal": _action_reject_proposal,
    }
    try:
        from warden.marketplace import api_escrow, api_listings, api_negotiations  # noqa: PLC0415

        handlers.update({
            "buy":             api_listings.buy_listing,
            "negotiate":       api_negotiations.start_negotiation,
            "send_offer":      api_negotiations.send_offer,
            "accept_offer":    api_negotiations.accept_offer,
            "create_escrow":   api_escrow.create_escrow,
            "fund_escrow":     api_escrow.fund_escrow,
            "sending_payments": api_escrow.fund_escrow,   # Stage 4 alias
            "deliver_asset":   api_escrow.deliver_asset,
            "confirm_receipt": api_escrow.confirm_receipt,
            "raise_dispute":   api_escrow.raise_dispute,
        })
    except Exception as exc:
        log.warning("dispatch_action: failed to load sub-handlers: %s", exc)

    handler = handlers.get(body.action_type)
    if handler is None:
        return {
            "dispatched":  False,
            "action_type": body.action_type,
            "route":       _ACTION_ROUTES.get(body.action_type, "unknown"),
            "error":       "Handler not available; call the sub-endpoint directly.",
        }

    # x402 nanopayment gate — search action only; fail-open
    if body.action_type == "search":
        try:
            from warden.marketplace.x402_gate import (  # noqa: PLC0415
                deduct_payment,
                require_payment,
            )

            gate_resp = await require_payment(request, "marketplace/search")
            if gate_resp is not None:
                return gate_resp  # type: ignore[return-value]
        except Exception as _x402_exc:
            log.debug("x402 gate fail-open: %s", _x402_exc)

    try:
        result = await handler(**body.payload)  # type: ignore[operator]

        # Queue deduction after successful search (batch settlement in v2)
        if body.action_type == "search":
            try:
                from warden.marketplace.x402_gate import deduct_payment  # noqa: PLC0415, F811

                _agent_id = (
                    body.payload.get("agent_id")
                    or request.headers.get("X-Agent-ID", "anonymous")
                )
                await deduct_payment(str(_agent_id), "marketplace/search")
            except Exception as _ded_exc:
                log.debug("x402 deduct fail-open: %s", _ded_exc)

        return {"dispatched": True, "action_type": body.action_type, "result": result}
    except Exception as exc:
        log.warning("dispatch_action %s failed: %s", body.action_type, exc)
        return {
            "dispatched":  False,
            "action_type": body.action_type,
            "error":       str(exc),
            "route":       _ACTION_ROUTES.get(body.action_type),
        }


# ── Protocol schema download (Stage 1: dynamic schema discovery) ──────────────

_PROTOCOL_SCHEMAS: dict[str, dict] = {
    "register_agent": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object", "required": ["tenant_id", "community_id", "public_key"],
        "properties": {
            "tenant_id":    {"type": "string"},
            "community_id": {"type": "string"},
            "public_key":   {"type": "string", "description": "Ed25519 public key (base64url)"},
            "capabilities": {"type": "array", "items": {"type": "string"},
                             "default": ["marketplace_buy", "marketplace_sell"]},
        },
    },
    "search": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object", "required": ["query"],
        "properties": {
            "query":      {"type": "string", "description": "Natural-language search query"},
            "limit":      {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            "asset_type": {"type": "string", "enum": ["rule", "model", "signals", "general"]},
        },
    },
    "send_proposal": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["buyer_agent_id", "seller_agent_id", "listing_id", "max_price_per_unit"],
        "properties": {
            "buyer_agent_id":     {"type": "string", "description": "DID of the buyer"},
            "seller_agent_id":    {"type": "string", "description": "DID of the seller"},
            "listing_id":         {"type": "string"},
            "quantity":           {"type": "integer", "minimum": 1, "default": 1},
            "max_price_per_unit": {"type": "number", "minimum": 0},
            "sla_hours":          {"type": "integer", "minimum": 1, "default": 24},
            "message":            {"type": "string", "maxLength": 1000},
        },
    },
    "send_message": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object", "required": ["negotiation_id", "from_agent_id", "message"],
        "properties": {
            "negotiation_id": {"type": "string"},
            "from_agent_id":  {"type": "string"},
            "message":        {"type": "string", "maxLength": 5000},
        },
    },
    "send_offer": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object", "required": ["negotiation_id", "from_agent_id", "price"],
        "properties": {
            "negotiation_id": {"type": "string"},
            "from_agent_id":  {"type": "string"},
            "price":          {"type": "number", "minimum": 0},
            "message":        {"type": "string", "maxLength": 1000},
        },
    },
    "sending_payments": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object", "required": ["escrow_id"],
        "description": "Stage 4 alias for fund_escrow — triggers escrow funding (payment).",
        "properties": {
            "escrow_id": {"type": "string"},
            "tx_hash":   {"type": "string", "description": "On-chain tx hash (optional)"},
        },
    },
    "reject_proposal": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object", "required": ["negotiation_id", "buyer_agent_id"],
        "properties": {
            "negotiation_id": {"type": "string"},
            "buyer_agent_id": {"type": "string"},
            "reason":         {"type": "string", "default": "rejected_by_buyer"},
        },
    },
}


@router.get("/protocol/schema/{action_name}")
async def get_action_schema(action_name: str) -> dict:
    """Download JSON Schema for a specific action type.

    Agents call this to validate payloads before sending POST /action.
    Returns 404 with available schemas list when action_name is unknown.
    """
    schema = _PROTOCOL_SCHEMAS.get(action_name)
    if schema is None:
        return {
            "error":     f"No schema for action '{action_name}'",
            "available": sorted(_PROTOCOL_SCHEMAS.keys()),
        }
    return {"action_name": action_name, "schema": schema}


# ── POST /clear — Stage 4: ClearingEngine ─────────────────────────────────────

class ClearRequest(BaseModel):
    winner_negotiation_id: str
    buyer_agent_id:        str


@router.post("/clear")
async def market_clear(body: ClearRequest) -> dict:
    """Stage 4: execute final market clearing.

    Accepts the winning negotiation, auto-rejects all other pending
    negotiations for the same buyer, and dual-writes the clearing record
    to SQLite + PostgreSQL.
    """
    from warden.marketplace.clearing import ClearingEngine  # noqa: PLC0415

    db_path = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    engine  = ClearingEngine(db_path=db_path)
    result  = await engine.clear_async(
        winner_neg_id=body.winner_negotiation_id,
        buyer_agent_id=body.buyer_agent_id,
    )
    return {
        "clearing_id":      result.clearing_id,
        "winner_neg_id":    result.winner_neg_id,
        "buyer_agent_id":   result.buyer_agent_id,
        "rejected_count":   len(result.rejected_neg_ids),
        "rejected_neg_ids": result.rejected_neg_ids,
        "cleared_at":       result.cleared_at,
        "pg_write_ok":      result.pg_write_ok,
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
    except Exception as exc:
        log.debug("readiness check: _list_agents fail-open: %s", exc)

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
