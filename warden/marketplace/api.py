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

import contextlib
import logging
import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from warden.auth_guard import AuthResult, require_api_key
from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.marketplace.analytics import get_agent_leaderboard
from warden.marketplace.service import VALID_ASSET_TYPES
from warden.marketplace.sybil_guard import SybilGuard
from warden.marketplace.trust_graph import TrustGraph
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.marketplace.api")

# NB: the router is created WITHOUT a built-in prefix. Callers include it with
# `include_router(router, prefix="/marketplace")`. Including a self-prefixed
# router (prefix baked into APIRouter) via `include_router(router)` triggers a
# FastAPI/Starlette _IncludedRouter drop on newer versions — the routes silently
# never reach app.routes. The sibling sub-routers already use the prefix-arg
# pattern for the same reason.
router = APIRouter(tags=["Marketplace"])


def _signed_offers_required() -> bool:
    """Whether unsigned offers are rejected, for the protocol manifest (MP-7)."""
    try:
        from warden.marketplace.negotiation import signed_offers_required
        return signed_offers_required()
    except Exception as exc:
        log.debug("manifest: signature-enforcement probe unavailable: %s", exc)
        return False


def _discover_chains() -> list[str]:
    """Chain names with an RPC URL configured, sorted. **Raises** if unreadable.

    The manifest used to advertise a hard-coded ``["sepolia", "eth_tester"]``,
    which described the developer's laptop rather than the running deployment —
    ``eth_tester`` is an in-process EVM, and a counterparty reading it as a
    settlement venue is reading a claim nothing backs. Derived, like the mode.

    Propagating a registry failure is the point: "we looked and found nothing"
    and "we could not look" are different facts, and only the caller knows which
    of the two its field is allowed to state.
    """
    from warden.web3.chains import VALID_CHAINS, get_chain
    found: list[str] = []
    failed = 0
    for chain in sorted(VALID_CHAINS):
        try:
            if get_chain(chain).get("rpc_url", ""):
                found.append(chain)
        except Exception:  # noqa: S112 - one bad chain entry must not hide the rest
            failed += 1
            continue
    # One bad entry is noise the loop above is allowed to skip. *Every* entry
    # failing is not a configuration finding, it is a broken registry — and
    # returning `[]` for it would report "nothing is configured" on the strength
    # of a lookup that never worked. Same defect this function was written to
    # fix, one level further down.
    if VALID_CHAINS and failed == len(VALID_CHAINS):
        raise RuntimeError(f"chain registry unreadable: all {failed} lookups failed")
    return found


def _configured_chains() -> list[str]:
    """``_discover_chains()`` for the manifest: empty list rather than a 500.

    A discovery endpoint must answer. An empty ``chains`` array understates what
    is configured, which is the safe direction for a claim — while
    ``settlement_mode`` carries the fact that the lookup failed at all.
    """
    try:
        return _discover_chains()
    except Exception as exc:
        log.debug("manifest: chain registry unavailable: %s", exc)
        return []


def _api_version_info() -> dict:
    """Versioning contract for the manifest; never breaks discovery if absent."""
    try:
        from warden.api_versioning import version_info
        return version_info()
    except Exception as exc:
        log.debug("manifest: version info unavailable: %s", exc)
        return {}


def _escrow_settlement_mode() -> str:
    """What kind of value this marketplace can actually settle (MP-7, P1a).

    Three states, because two could not tell the difference that matters:

    * ``"onchain"``   — a **mainnet** chain is configured; a trade moves real value.
    * ``"testnet"``   — only test chains are configured. The transaction is real,
      the money is not; test USDC is free and a settled testnet trade proves the
      plumbing, never the rail.
    * ``"simulated"`` — no RPC at all. ``EscrowService`` runs a deterministic
      in-process simulation: the state machine is real, the settlement is not.
    * ``"unknown"``   — the chain registry could not be read. Reserved for that
      case alone: reporting ``"simulated"`` when the lookup failed would state a
      fact about the configuration that was never established.

    This used to return ``"onchain"`` for any configured RPC, so production
    advertised on-chain settlement to every foreign agent on the strength of a
    Sepolia endpoint — and made "manifest reports onchain" unusable as the P1a
    exit gate, since it was already true with zero mainnet and $0 settled.
    ``MAINNET_CHAINS`` is the explicit list; membership is never inferred from
    a chain id or a name that happens to lack "sepolia" in it.

    Derived from **configuration**, never by probing. ``_check_rpc_with_retry()``
    is the reachability check, and it retries with 2/4/8s back-off — putting that
    behind a discovery endpoint would hand any caller a 14-second stall. A
    configured-but-currently-unreachable node is an availability problem for
    ``/health``, not a change in what this marketplace offers.
    """
    try:
        # Capability first, configuration second. An RPC URL says where we would
        # send a transaction, not that one can be sent: `BASE_RPC_URL` defaults
        # to the public Base endpoint, so "a mainnet RPC is configured" is true
        # on every deployment including a laptop, while `deploy_escrow()` has
        # always returned a simulated address. Production advertised `onchain`
        # on exactly that basis, with no contract, no signer and $0 settled.
        from warden.web3.chains import MAINNET_CHAINS
        from warden.web3.smart_contract import settlement_capability

        # Asked per chain, because capability is per chain: an escrow contract
        # deployed on Base says nothing about Sepolia. Asking only the default
        # chain would let one configured testnet vouch for a mainnet claim.
        configured = set(_discover_chains())
        capable = {c for c in configured if settlement_capability(c).get("can_settle")}
        if capable & MAINNET_CHAINS:
            return "onchain"
        if capable:
            return "testnet"
        # Configured but not capable is still simulated: an RPC URL says where a
        # transaction would go, not that one can be sent. `BASE_RPC_URL` defaults
        # to the public Base endpoint, so this is the ordinary case, and it read
        # `onchain` in production for a week.
        return "simulated"
    except Exception as exc:
        log.debug("manifest: escrow mode probe unavailable: %s", exc)
        return "unknown"


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
        # MP-7: a counterparty agent makes trust decisions from this manifest, so
        # every key here has to describe the running configuration rather than the
        # intended design. Two of these were false advertising until MP-1b/MP-2:
        # signatures were never verified (all offers stored signature='') and
        # `injection_guard` named a module with no production caller.
        "negotiation": {
            "max_rounds": int(os.getenv("MARKETPLACE_MAX_NEGOTIATION_ROUNDS", "5")),
            "signature_type": "Ed25519",
            # Whether an unsigned or badly-signed offer is actually REJECTED, as
            # opposed to verified-and-counted during the bake period. A partner
            # cannot infer this from `signature_type` alone.
            "signature_enforced": _signed_offers_required(),
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
            "chains": _configured_chains(),
            "delivery_timeout_hours": int(os.getenv("ESCROW_DELIVERY_TIMEOUT_HOURS", "48")),
            # "onchain" only for a mainnet chain; "testnet" when the configured
            # chains are all test networks; "simulated" when no RPC is set and
            # the escrow state machine runs in-process, settling nothing.
            # Advertising `chains` without this let a counterparty read an
            # on-chain guarantee that does not exist.
            "settlement_mode": _escrow_settlement_mode(),
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
        # A foreign agent that reads this manifest is exactly who needs to know
        # the unversioned paths have a date on them (P2).
        "api_version": _api_version_info(),
    }


# ── POST /register — M2M first-contact (third required base endpoint) ─────────

@router.get("/agent.json", include_in_schema=False)
async def agent_discovery_alias(response: Response) -> dict:
    """
    /.well-known/agent.json — the one discovery document, serving two protocols.

    Two specs want this path: the A2A v1.0 Agent Card and this marketplace
    protocol manifest. This handler is registered first, so for a long time it
    won outright and warden/protocols/a2a/api.py's card was unreachable — A2A
    agents doing spec discovery got a document with no `schema_version`, and the
    startup banner's "Agent Card: /.well-known/agent.json" was simply false.

    Rather than pick a winner and break one set of agents, both documents are
    returned merged. Their field sets are disjoint today and
    `test_agent_discovery_is_merged` fails if that ever stops being true, so a
    new field cannot silently shadow the other protocol's. On a collision the
    marketplace value wins, because those consumers exist in production now.
    """
    response.headers["Cache-Control"] = "public, max-age=3600"
    manifest = await get_market_protocol(response)
    try:
        from warden.protocols.a2a.agent_card import build_agent_card
        card = build_agent_card()
    except Exception:
        # Discovery must not fail because an optional subsystem is unavailable;
        # the marketplace half is what production has always returned.
        return manifest
    return {**card, **manifest}


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

    After DID assignment, creates a PENDING KYA record and runs initial screening.
    """
    from warden.marketplace.api_agents import AgentRegisterRequest, register_agent
    result = await register_agent(
        AgentRegisterRequest(
            tenant_id=body.tenant_id,
            community_id=body.community_id,
            public_key=body.public_key,
            capabilities=body.capabilities,
        )
    )

    # KYA: register and screen the newly issued DID (fail-open)
    agent_id = result.get("agent_id", "")
    if agent_id:
        try:
            from warden.marketplace.kya import register_agent as kya_register  # noqa: PLC0415
            from warden.marketplace.kya import screen_agent  # noqa: PLC0415
            kya_record = kya_register(agent_id, owner_tenant_id=body.tenant_id)
            kya_record = screen_agent(agent_id)
            result["kya_status"] = kya_record.kya_status
            result["kya_risk_score"] = round(kya_record.risk_score, 3)
        except Exception as exc:
            # Rule 18 fail-open by design — agent registers with kya_status=PENDING
            # when screening errors. Counter makes the unscreened path alertable.
            log.debug("kya registration fail-open: %s", exc)
            record_failopen("marketplace_kya", Reason.BACKEND_ERROR, exc)
            result["kya_status"] = "PENDING"

    return result


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
    """Stage 2: semantic listing search via pgvector / SQLite fallback.

    When KYA_VERIFIED_ONLY=true, results are filtered to listings whose
    seller agent has kya_status="VERIFIED".
    """
    from warden.marketplace.vector_search import semantic_search  # noqa: PLC0415

    results = await semantic_search(query, limit=limit, asset_type=asset_type)

    if os.getenv("KYA_VERIFIED_ONLY", "false").lower() == "true":
        try:
            from warden.marketplace.kya import get_kya_status  # noqa: PLC0415
            results = [r for r in results if get_kya_status(r.get("seller_agent", "")) == "VERIFIED"]
        except Exception as exc:
            # KYA_VERIFIED_ONLY guard: on error the unfiltered result set (incl.
            # non-VERIFIED sellers) is returned — a silent policy bypass, alertable.
            log.debug("kya filter fail-open in search: %s", exc)
            record_failopen("marketplace_kya", Reason.BACKEND_ERROR, exc)

    return {"results": results, "count": len(results), "query": query}


_MESSAGES_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_messages (
        msg_id          TEXT PRIMARY KEY,
        negotiation_id  TEXT NOT NULL,
        from_agent_id   TEXT NOT NULL,
        message         TEXT NOT NULL,
        created_at      REAL NOT NULL
    );
"""
register("marketplace", "warden.marketplace.api.messages", _MESSAGES_DDL)

_PROPOSALS_DDL = """
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
    );
"""
register("marketplace", "warden.marketplace.api.proposals", _PROPOSALS_DDL)


def _reject_if_injection(message: str) -> None:
    """Reject agent-authored free text carrying a prompt-injection attempt.

    HTTP 422, matching ``injection_guard``'s documented contract. Deliberately
    fail-CLOSED on the scan itself: if the guard cannot run we do not have a
    clean message, and this text is destined for an LLM agent with spend
    authority. That is the opposite posture from MAESTRO/KYA (rules #6/#18),
    which stay permissive on error because they are advisory scoring rather than
    content admission.
    """
    if not message:
        return
    from warden.marketplace.injection_guard import scan_negotiation_message
    if scan_negotiation_message(message):
        raise HTTPException(
            status_code=422,
            detail={"error": "prompt_injection_detected",
                    "message": "Message blocked: prompt injection detected."},
        )


async def _action_send_message(
    negotiation_id: str = "",
    from_agent_id: str = "",
    message: str = "",
    **_: Any,
) -> dict:
    """Stage 3: send a text message within an active negotiation channel."""
    # MP-2: this free text is authored by a counterparty agent and later read by
    # LLM-backed buyer/seller agents that hold spend authority. It was persisted
    # with no screening at all, while rule #1 claimed every offer body was
    # scanned. Same guard as send_offer, one implementation.
    _reject_if_injection(message)
    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    msg_id = str(uuid.uuid4())[:12]
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
    ) as con:
        con.execute(
            "INSERT INTO marketplace_messages VALUES (?,?,?,?,?)",
            (msg_id, negotiation_id, from_agent_id, message[:5000], time.time()),
        )
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
    _reject_if_injection(message)
    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    proposal_id = str(uuid.uuid4())[:16]
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
    ) as con:
        con.execute(
            "INSERT INTO marketplace_proposals VALUES (?,?,?,?,?,?,?,?,'pending',?)",
            (
                proposal_id, buyer_agent_id, seller_agent_id, listing_id,
                quantity, max_price_per_unit, sla_hours, message[:5000], time.time(),
            ),
        )
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
    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    try:
        with open_db(
            "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
        ) as con:
            # `buyer_agent`, not `buyer_agent_id` — the same column that broke
            # clearing. This one was invisible because the lifecycle test's
            # hand-rolled fixture declared `buyer_agent_id`, so the UPDATE
            # worked in the suite and raised in production, where it returned
            # `{"error": ...}` and no proposal was ever rejected.
            con.execute(
                "UPDATE marketplace_negotiations SET status=? "
                "WHERE negotiation_id=? AND buyer_agent=?",
                (reason, negotiation_id, buyer_agent_id),
            )
            affected = con.execute("SELECT changes()").fetchone()[0]
        return {
            "negotiation_id": negotiation_id,
            "status":         reason,
            "updated":        affected > 0,
        }
    except Exception as exc:
        return {"negotiation_id": negotiation_id, "error": str(exc)}


def _report_search_usage(tenant_id: str) -> None:
    """
    Background task: report one search-call usage event to Lemon Squeezy.

    Runs after the response is sent — adds zero latency to the M2M transaction.
    Uses MeterUsageAggregator for batching (flush after 100 events or 300s).
    Falls back to direct report_usage() when the aggregator buffer is full.
    Fail-open: any exception is logged and swallowed.
    """
    try:
        from warden.billing.pricing import MARKETPLACE_SEARCH_FEE_USD
        from warden.lemon_billing import get_meter_aggregator  # noqa: PLC0415
        get_meter_aggregator().record(tenant_id, MARKETPLACE_SEARCH_FEE_USD)
    except Exception as exc:
        log.debug("_report_search_usage fail-open: %s", exc)


@router.post("/action", dependencies=[Depends(require_api_key)])
async def dispatch_action(
    body: MarketAction,
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
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

    # Dynamic Model Router — score action complexity, select cheapest capable model
    _route_decision = None
    try:
        from warden.marketplace.model_router import route as _mr_route  # noqa: PLC0415

        _route_decision = _mr_route(
            body.action_type,
            body.payload,
            round_count=int(body.payload.get("round_count", 0)) if isinstance(body.payload, dict) else 0,
        )
        log.debug(
            "dispatch_action: model_router action=%s tier=%s score=%.2f model=%s",
            body.action_type, _route_decision.tier, _route_decision.score, _route_decision.model,
        )
        # OTel span attributes — GDPR-safe metadata only (no user content)
        try:
            from opentelemetry import trace as _otel_trace  # noqa: PLC0415

            _span = _otel_trace.get_current_span()
            _span.set_attribute("mkt.model_tier",    _route_decision.tier)
            _span.set_attribute("mkt.route_score",   _route_decision.score)
            _span.set_attribute("mkt.model_id",      _route_decision.model)
            _span.set_attribute("mkt.action_type",   body.action_type)
        except Exception:
            pass
    except Exception:
        pass  # router is advisory only — dispatch continues regardless

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
        result = await handler(**body.payload)

        # Queue deduction after successful search (batch settlement in v2)
        if body.action_type == "search":
            _agent_id = (
                body.payload.get("agent_id")
                or request.headers.get("X-Agent-ID", "anonymous")
            )
            try:
                from warden.marketplace.x402_gate import deduct_payment  # noqa: PLC0415
                await deduct_payment(str(_agent_id), "marketplace/search")
            except Exception as _ded_exc:
                log.debug("x402 deduct fail-open: %s", _ded_exc)
            # LS metered billing — offloaded to BackgroundTasks (zero latency impact)
            _tenant_id = request.headers.get("X-Tenant-ID", "")
            if _tenant_id:
                background_tasks.add_task(_report_search_usage, _tenant_id)

        resp: dict[str, Any] = {"dispatched": True, "action_type": body.action_type, "result": result}
        if _route_decision is not None:
            resp["routed_model"] = _route_decision.model
            resp["route_tier"]   = _route_decision.tier
            resp["route_score"]  = round(_route_decision.score, 3)
        return resp
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
            "asset_type": {"type": "string", "enum": sorted(VALID_ASSET_TYPES)},  # from the enforcer, never restated
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


@router.post("/clear", dependencies=[Depends(require_api_key)])
async def market_clear(body: ClearRequest) -> dict:
    """Stage 4: execute final market clearing.

    Authenticated. Clearing auto-rejects every other pending negotiation for the
    named buyer, so an anonymous caller could cancel a competitor's in-flight
    deals by clearing on their behalf. site/business-community/m2m-store.astro
    already documents this endpoint as auth: API Key.

    Accepts the winning negotiation, auto-rejects all other pending
    negotiations for the same buyer, and dual-writes the clearing record
    to SQLite + PostgreSQL.
    """
    from warden.marketplace.clearing import ClearingEngine  # noqa: PLC0415

    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    engine  = ClearingEngine(db_path=db_path)
    try:
        result = await engine.clear_async(
            winner_neg_id=body.winner_negotiation_id,
            buyer_agent_id=body.buyer_agent_id,
        )
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "clearing_id":      result.clearing_id,
        "winner_neg_id":    result.winner_neg_id,
        "buyer_agent_id":   result.buyer_agent_id,
        "rejected_count":   len(result.rejected_neg_ids),
        "rejected_neg_ids": result.rejected_neg_ids,
        "cleared_at":       result.cleared_at,
        "pg_write_ok":      result.pg_write_ok,
        "replayed":         result.replayed,
    }


# ── Analytics query (SELECT-only, for MCP/SOVA tool #32) ──────────────────────

# Tables whose rows are partitioned by agent identity columns.
# Used by the Confused Deputy guard to detect cross-agent data access.
_AGENT_SCOPED_TABLES = frozenset({
    "marketplace_agents",
    "marketplace_listings",
    "marketplace_purchases",
    "marketplace_escrow",
    "marketplace_negotiations",
    "marketplace_offers",
})

# Column names that carry agent identity in those tables.
_AGENT_ID_COLUMNS = frozenset({
    "agent_id", "buyer_agent_id", "seller_agent_id", "from_agent_id",
    # escrow table uses bare "buyer_agent" / "seller_agent" (no _id suffix)
    "buyer_agent", "seller_agent", "from_agent", "to_agent",
})


def _confused_deputy_check(stmt: str, caller_agent_id: str) -> str | None:
    """Return an error string if the SQL is not scoped to the caller's own DID.

    Two layers, and the second one used to be missing:

    1. **Foreign literal** — `buyer_agent = 'did:shadow:someone-else'` is
       rejected outright.
    2. **No scoping at all** — a query touching an agent-partitioned table
       (`_AGENT_SCOPED_TABLES`) must carry an equality filter on one of the
       agent-identity columns. Without this, `SELECT * FROM
       marketplace_escrow` matched no literal, fell through, and returned
       *every* agent's rows (capped at 500) to any authenticated caller. The
       endpoint docstring already promised that "a query that ... omits
       scoping entirely, is rejected"; only the promise existed.
       `_AGENT_SCOPED_TABLES` was declared for exactly this and never read by
       anything — a frozenset that looked like a control and was decoration.

    This is a first-layer heuristic guard; a proper implementation uses
    row-level security views. Returns None when the query is safe to execute.
    """
    import re
    col_pattern = "|".join(re.escape(c) for c in _AGENT_ID_COLUMNS)
    scoped = False
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
        scoped = True

    if scoped:
        return None

    lowered = stmt.lower()
    touched = sorted(t for t in _AGENT_SCOPED_TABLES if re.search(rf"\b{t}\b", lowered))
    if touched:
        return (
            f"Confused Deputy: query reads agent-partitioned table(s) "
            f"{', '.join(touched)} without scoping to an agent. Add a filter "
            f"such as buyer_agent = '{caller_agent_id}'."
        )
    return None


class AnalyticsQuery(BaseModel):
    sql: str
    params: list[Any] = []
    caller_agent_id: str | None = None  # set by MCP client or SOVA tool


@router.post("/analytics/query")
async def analytics_sql_query(
    body: AnalyticsQuery,
    request: Request,
    _: AuthResult = Depends(require_api_key),
) -> dict:
    """Execute a read-only SQL SELECT against the marketplace DB.

    Used by SOVA tool #32 (query_marketplace_db) and MCP marketplace-db server.

    Security layers:
    1. Authentication — requires a valid API key (require_api_key dependency).
    2. SELECT-only gate — rejects any non-SELECT statement, and additionally
       rejects statements that smuggle a second statement or a DDL/DML keyword.
    3. Confused Deputy guard — a `caller_agent_id` is MANDATORY (via body or
       X-Agent-ID header) and every query must be scoped to it; a query that
       references a different agent's DID literal, or omits scoping entirely,
       is rejected.  This prevents one caller from reading another agent's
       escrows, negotiations, credits, or x402 balances.
    """
    stmt = body.sql.strip()
    upper = stmt.upper()
    if not upper.startswith("SELECT"):
        return {"error": "Only SELECT statements are permitted.", "rows": []}
    # Defence-in-depth: reject multi-statement / DDL-DML smuggling even inside a SELECT.
    if ";" in stmt.rstrip(";"):
        return {"error": "Multiple statements are not permitted.", "rows": []}
    forbidden = (
        " INSERT ", " UPDATE ", " DELETE ", " DROP ", " ALTER ",
        " CREATE ", " ATTACH ", " PRAGMA ", " REPLACE ", " GRANT ",
    )
    padded = f" {upper} "
    if any(kw in padded for kw in forbidden):
        return {"error": "Only read-only SELECT statements are permitted.", "rows": []}

    # Resolve caller identity: body field takes priority over header.
    # Scoping is MANDATORY — an unscoped query could read every tenant's data.
    caller_id = body.caller_agent_id or request.headers.get("X-Agent-ID")
    if not caller_id:
        return {
            "error": "caller_agent_id (or X-Agent-ID header) is required to scope the query.",
            "rows": [],
        }
    err = _confused_deputy_check(stmt, caller_id)
    if err:
        log.warning("analytics_sql_query: confused deputy rejected caller=%s", caller_id[:40])
        return {"error": err, "rows": []}

    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    try:
        with open_db(
            "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
        ) as con:
            cur = con.execute(stmt, body.params)
            rows = [dict(r) for r in cur.fetchmany(500)]  # cap at 500 rows
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


@router.get("/analytics/model-tiers")
async def marketplace_model_tiers(
    period_days: int = Query(default=7, ge=1, le=90),
) -> dict:
    """Model router tier distribution for dispatched actions.

    Returns haiku/sonnet/opus counts and an estimated API cost savings
    percentage vs. always routing to Opus.  The ``estimated`` flag is True
    when the clearing-log sample is < 10 records (fallback proportions used).
    Wired into the Live Intelligence dashboard chart on the marketplace page.
    """
    from warden.marketplace.analytics import model_tier_distribution
    return model_tier_distribution(period_days=period_days)


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


# ── SOC 2 Type II compliance report ──────────────────────────────────────────

@router.get("/compliance/soc2-report")
async def get_soc2_report(
    period_days: int = Query(default=90, ge=1, le=365, description="Look-back window in days"),
    format: str   = Query(default="json", pattern="^(json|zip)$"),
    request: Request = None,
) -> Any:
    """Compile SOC 2 Type II evidence for the requesting tenant over the period.

    Returns JSON summary (default) or a ZIP archive of all daily snapshots.
    Gated to Pro+ tier. Evidence is GDPR-safe — all identifiers pseudonymised.

    Args:
        period_days: Look-back window (1–365 days). 90 = basic Type II window.
        format: "json" for summary dict; "zip" for downloadable evidence archive.
    """
    import io
    import json as _json
    import zipfile

    from fastapi.responses import StreamingResponse

    from warden.compliance.soc2_collector import load_evidence_range  # noqa: PLC0415

    # Tier gate — Pro+ required
    tier = (request.headers.get("X-Tenant-Tier") or "starter").lower() if request else "starter"
    _pro_tiers = {"pro", "enterprise"}
    if tier not in _pro_tiers:
        from fastapi import HTTPException  # noqa: PLC0415
        raise HTTPException(
            status_code=403,
            detail=f"SOC 2 Type II reports require Pro+ tier (current: {tier}).",
        )

    snapshots = load_evidence_range(days=period_days)

    if format == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for snap in snapshots:
                date_str = snap.get("period_start", "unknown")[:10]
                zf.writestr(
                    f"soc2_evidence/{date_str}_tsc.json",
                    _json.dumps(snap, indent=2, default=str),
                )
            # Summary manifest
            manifest = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "period_days":  period_days,
                "snapshots_included": len(snapshots),
                "tsc_covered": ["CC1-CC8 Security", "A1 Availability",
                                "PI1 Processing Integrity", "P1-P8 Privacy",
                                "C1 Confidentiality"],
            }
            zf.writestr("MANIFEST.json", _json.dumps(manifest, indent=2))
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="soc2_evidence_{period_days}d.zip"'
                )
            },
        )

    # JSON summary
    aggregated: dict[str, Any] = {
        "period_days":      period_days,
        "snapshots_found":  len(snapshots),
        "generated_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tsc_summary": {
            "security": {
                "total_confused_deputy_blocks": sum(
                    s.get("tsc_evidence", {}).get("security", {}).get("confused_deputy_block_count", 0)
                    for s in snapshots
                ),
                "total_pqc_auth_failures": sum(
                    s.get("tsc_evidence", {}).get("security", {}).get("pqc_auth_failure_count", 0)
                    for s in snapshots
                ),
            },
            "availability": {
                "avg_availability_pct": _safe_avg(
                    [s.get("tsc_evidence", {}).get("availability", {}).get("availability_pct")
                     for s in snapshots]
                ),
            },
            "processing_integrity": {
                "total_clearings": sum(
                    s.get("tsc_evidence", {}).get("processing_integrity", {}).get("clearings_in_window", 0)
                    for s in snapshots
                ),
                "total_decimal_violations": sum(
                    s.get("tsc_evidence", {}).get("processing_integrity", {}).get("decimal_violation_count", 0)
                    for s in snapshots
                ),
            },
            "privacy": {
                "total_gdpr_exports": sum(
                    s.get("tsc_evidence", {}).get("privacy", {}).get("gdpr_export_count", 0)
                    for s in snapshots
                ),
            },
            "confidentiality": {
                "total_pqc_ops": sum(
                    s.get("tsc_evidence", {}).get("confidentiality", {}).get("pqc_operations_count", 0)
                    for s in snapshots
                ),
            },
        },
        "daily_snapshots": [
            {"date": s.get("period_start", "")[:10], "collection_ms": s.get("collection_ms")}
            for s in snapshots
        ],
    }
    return aggregated


def _safe_avg(values: list) -> float | None:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 4) if vals else None


# ── SSE live-metrics stream ────────────────────────────────────────────────────

@router.get("/analytics/stream")
async def analytics_stream(request: Request) -> Any:
    """Server-Sent Events stream of live marketplace metrics (30 s interval).

    Emits a single JSON blob per event that drives the 4 hero stat counters and
    Chart.js instances on the /agentic landing page. Clients can reconnect
    automatically (browser EventSource retries on error; Last-Event-ID is
    forwarded so no tick is lost across brief reconnects).

    Compatible with any SSE consumer: native EventSource, eventsource npm,
    server-sent-events Python library.
    """
    import asyncio
    import json as _json

    from fastapi.responses import StreamingResponse

    from warden.marketplace.analytics import get_live_metrics  # noqa: PLC0415

    sse_interval = 30  # seconds

    async def _generator():
        event_id = 0
        while True:
            if await request.is_disconnected():
                break
            try:
                data = await get_live_metrics()
                payload = _json.dumps(data, default=str)
                yield f"id: {event_id}\ndata: {payload}\n\n"
                event_id += 1
            except Exception as exc:
                log.warning("SSE metrics error: %s", exc)
                yield "event: error\ndata: {}\n\n"
            try:
                await asyncio.sleep(sse_interval)
            except asyncio.CancelledError:
                break

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection":    "keep-alive",
            "X-Accel-Buffering": "no",   # disable nginx/Caddy buffering
        },
    )


@router.get("/analytics/recent-trades")
async def marketplace_recent_trades(
    limit: int = Query(default=6, ge=1, le=50),
) -> list[dict]:
    """Return the N most-recent cleared marketplace trades for the live ticker."""
    from warden.marketplace.analytics import get_recent_trades  # noqa: PLC0415
    return get_recent_trades(limit=limit) or []


@router.get("/analytics/chart-data")
async def marketplace_chart_data(period_days: int = Query(default=7, ge=1, le=90)) -> dict:
    """Combined chart data: volume series + payment breakdown + agent activity + summary.
    Single endpoint so the marketplace frontend makes one call for all charts.
    """
    from warden.marketplace.analytics import get_summary, get_volume_series  # noqa: PLC0415

    db = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    summary = get_summary(period_days=period_days, db_path=db)
    volume = get_volume_series(period_days=period_days, db_path=db)

    # Payment method breakdown.
    #
    # `marketplace_purchases` has no `payment_method` column and never has —
    # nothing writes which rail settled a purchase, so this cannot be measured
    # from the data we keep. It used to return three confident zeroes, which
    # reads as "no purchases on any rail" rather than "we do not record this".
    # `payment_breakdown` therefore stays None until a writer exists;
    # `payment_breakdown_evidence` says which of the two it is.
    payment_breakdown: dict[str, int] | None = None
    payment_breakdown_evidence = "not_instrumented"
    agent_activity: list[dict] = []
    kya_distribution: dict[str, int] = {"VERIFIED": 0, "PENDING": 0, "FLAGGED": 0, "REVOKED": 0}
    top_agents: list[dict] = []

    try:
        with open_db(
            "marketplace", db, turso_name="marketplace", module_default_path=db
        ) as con:
            # Daily agent activity (new registrations per day)
            try:
                rows = con.execute(
                    # `registered_at` does not exist on marketplace_agents; the
                    # column is `created_at` (marketplace/agent.py:91). Same
                    # swallowed failure as the KYA query above.
                    f"SELECT DATE(created_at) as d, COUNT(*) as cnt FROM marketplace_agents "
                    f"WHERE created_at >= date('now', '-{period_days} days') "
                    f"GROUP BY DATE(created_at) ORDER BY d"
                ).fetchall()
                agent_activity = [{"date": r["d"], "count": int(r["cnt"])} for r in rows]
            except Exception:
                pass

            # KYA distribution
            try:
                # `marketplace_kya` is a third name for this data and matches
                # nothing: the table in this database is `kya_agent_profiles`
                # (DDL in app_factory.py, owner warden/kya/profile.py), while
                # marketplace/kya.py declares a `marketplace_kya_records` that
                # has never been created in production. The read raised and the
                # `except` below swallowed it, so the KYA breakdown has always
                # been all-zeroes.
                rows = con.execute(
                    "SELECT kya_status, COUNT(*) as cnt FROM kya_agent_profiles "
                    "GROUP BY kya_status"
                ).fetchall()
                for r in rows:
                    s = str(r["kya_status"]).upper()
                    if s in kya_distribution:
                        kya_distribution[s] = int(r["cnt"])
            except Exception:
                pass

            # Top agents by volume
            try:
                rows = con.execute(
                    "SELECT buyer_agent as agent_id, COALESCE(SUM(price_paid),0) as vol, COUNT(*) as trades "
                    "FROM marketplace_purchases WHERE status='completed' "
                    "GROUP BY buyer_agent ORDER BY vol DESC LIMIT 8"
                ).fetchall()
                top_agents = [
                    {"agent_id": r["agent_id"], "volume_usd": round(float(r["vol"]), 2), "trades": int(r["trades"])}
                    for r in rows
                ]
            except Exception:
                pass
    except Exception:
        pass

    return {
        "period_days": period_days,
        "summary": summary,
        "volume_series": volume,
        "payment_breakdown": payment_breakdown,
        "payment_breakdown_evidence": payment_breakdown_evidence,
        "agent_activity": agent_activity,
        "kya_distribution": kya_distribution,
        "top_agents": top_agents,
    }


# ── KYA (Know Your Agent) endpoints ──────────────────────────────────────────

@router.get("/agents/{agent_id}/kya")
async def get_agent_kya(agent_id: str) -> dict:
    """Return the KYA compliance record for an agent DID."""
    from warden.marketplace.kya import get_kya_record  # noqa: PLC0415
    record = get_kya_record(agent_id)
    if record is None:
        from fastapi import HTTPException  # noqa: PLC0415
        raise HTTPException(status_code=404, detail=f"No KYA record for agent '{agent_id}'")
    return record.to_dict()


class KYARevokeRequest(BaseModel):
    reason: str = "admin_revoke"


@router.post("/agents/{agent_id}/kya/revoke", status_code=200)
async def revoke_agent_kya(agent_id: str, body: KYARevokeRequest, request: Request) -> dict:
    """Revoke KYA status for an agent. Requires X-Admin-Key header.

    MP-1c: this used to read ``if admin_key and provided != admin_key``, which
    skipped the check entirely whenever ``ADMIN_KEY`` was unset — any caller
    could revoke any agent's KYA status. It now fails closed (503 when no key is
    configured) and compares in constant time.
    """
    from warden.marketplace.admin_guard import require_admin_key
    require_admin_key(request.headers.get("X-Admin-Key"))
    from warden.marketplace.kya import revoke_agent  # noqa: PLC0415
    revoke_agent(agent_id, reason=body.reason)
    return {"agent_id": agent_id, "kya_status": "REVOKED", "reason": body.reason}


# ── Flex Credits endpoints ────────────────────────────────────────────────────

class CreditsPurchaseRequest(BaseModel):
    package_id: str   # e.g. "credits_100", "credits_1000"


@router.post("/credits/purchase", status_code=200)
async def purchase_credits_endpoint(
    body: CreditsPurchaseRequest,
    request: Request,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Purchase a credit package. In production, redirects to Lemon Squeezy checkout.

    For direct testing (integration tests, webhook simulation), grants credits immediately.
    Returns new balance and package details.

    Requires an ``Idempotency-Key`` header (FT-3): without one, a retried Lemon
    Squeezy webhook or a double-submitted checkout call granted credits TWICE —
    real money creation, since the credit balance is directly spendable. A
    replayed key returns the original balance unchanged and grants nothing new.
    """
    from fastapi import HTTPException  # noqa: PLC0415

    from warden.marketplace.credits import CREDIT_PACKAGES, purchase_credits  # noqa: PLC0415

    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not idempotency_key:
        raise HTTPException(
            status_code=400,
            detail={"error": "idempotency_key_required",
                    "message": "Send an Idempotency-Key header (e.g. the payment "
                               "provider's event/order ID) with every credit purchase."},
        )

    package = CREDIT_PACKAGES.get(body.package_id)
    if package is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "unknown_package",
                    "valid_packages": list(CREDIT_PACKAGES.keys())},
        )

    # MP-1a: credits are directly spendable, so the tenant they are granted to is
    # a security decision, not a routing hint. The authenticated tenant wins.
    # Previously this endpoint had no auth dependency at all and fell back to a
    # caller-supplied ``X-Tenant-ID`` header — an anonymous POST minted 1000
    # spendable credits to any tenant id the caller named, for free.
    #
    # The header is honoured only in dev/air-gapped mode (no API key configured
    # at all, where require_api_key resolves every caller to "default"), so local
    # and test ergonomics are unchanged while production has no bypass.
    tenant_id = auth.tenant_id
    if tenant_id == "default":
        state = getattr(request, "state", None)
        tenant_obj = getattr(state, "tenant", None)
        if isinstance(tenant_obj, dict):
            tenant_id = tenant_obj.get("tenant_id") or tenant_obj.get("id") or tenant_id
        else:
            tenant_id = request.headers.get("X-Tenant-ID", tenant_id)

    new_balance = purchase_credits(tenant_id, body.package_id, idempotency_key=idempotency_key)
    return {
        "ok":          True,
        "package_id":  body.package_id,
        "credits_added": package["credits"],
        "balance":     new_balance,
        "price_usd":   package["price_usd"],
    }


@router.get("/credits/balance")
async def get_credits_balance(request: Request) -> dict:
    """Return current credit balance and package catalog for the requesting tenant."""
    from warden.marketplace.credits import CREDIT_PACKAGES, get_balance  # noqa: PLC0415

    state = getattr(request, "state", None)
    tenant_obj = getattr(state, "tenant", None)
    if isinstance(tenant_obj, dict):
        tenant_id = tenant_obj.get("tenant_id") or tenant_obj.get("id") or "unknown"
    else:
        tenant_id = request.headers.get("X-Tenant-ID", "unknown")

    balance = get_balance(tenant_id)
    catalog = [
        {
            "package_id":   pkg_id,
            "display_name": pkg["display_name"],
            "credits":      pkg["credits"],
            "price_usd":    pkg["price_usd"],
        }
        for pkg_id, pkg in CREDIT_PACKAGES.items()
    ]
    return {"tenant_id": tenant_id, "balance": balance, "package_catalog": catalog}


# ── Autonomy policy endpoints ─────────────────────────────────────────────────

class AutonomyPolicyRequest(BaseModel):
    level:                      int
    max_spend_usd:              float = 0.0
    daily_spend_usd:            float = 0.0
    allowed_actions:            list[str] = ["search", "negotiate", "clear"]
    require_approval_above_usd: float = 0.01
    expires_at:                 str | None = None


@router.post("/autonomy/{agent_id}", status_code=201)
async def set_autonomy_policy(
    agent_id: str,
    body: AutonomyPolicyRequest,
    request: Request,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Register or update an autonomy policy for an agent.

    L1 = Shadow (all actions require approval)
    L2 = Supervised (low-value actions auto-approved)
    L3 = Autonomous (hard spend cap, no human in loop)

    Authenticated: this policy is what `payments/authorize.py::authorize_payment()`
    consults through `autonomy.check_action()`. Writing it anonymously would let a
    caller set any agent to L3 with an arbitrary spend cap — i.e. switch off the
    approval gate on money movement from outside.
    """
    from warden.marketplace.autonomy import AutonomyPolicy, set_policy  # noqa: PLC0415

    # `created_by` is attribution on a security policy, so it comes from the
    # verified key. The previous X-Tenant-ID header fallback was caller-supplied
    # and could be set to any value.
    tenant_id = getattr(auth, "tenant_id", None) or "unknown"
    state = getattr(request, "state", None)
    tenant_obj = getattr(state, "tenant", None)
    if tenant_id == "unknown" and isinstance(tenant_obj, dict):
        tenant_id = tenant_obj.get("tenant_id") or tenant_obj.get("id") or "unknown"

    policy = AutonomyPolicy(
        agent_id=agent_id,
        level=body.level,
        max_spend_usd=body.max_spend_usd,
        daily_spend_usd=body.daily_spend_usd,
        allowed_actions=body.allowed_actions,
        require_approval_above_usd=body.require_approval_above_usd,
        expires_at=body.expires_at,
        created_by=tenant_id,
    )
    result = set_policy(policy)
    return result.to_dict()


@router.get("/autonomy/{agent_id}")
async def get_autonomy_policy(agent_id: str) -> dict:
    """Return current autonomy policy for an agent."""
    from warden.marketplace.autonomy import get_policy  # noqa: PLC0415
    policy = get_policy(agent_id)
    if policy is None:
        return {
            "agent_id":  agent_id,
            "level":     1,
            "note":      "No policy registered; default L1 applies (all actions require approval).",
        }
    return policy.to_dict()


@router.delete("/autonomy/{agent_id}", status_code=200)
async def delete_autonomy_policy(
    agent_id: str,
    _: AuthResult = Depends(require_api_key),
) -> dict:
    """Remove autonomy policy; agent reverts to L1 default.

    Authenticated: deletion is a downgrade to L1 (everything needs approval), so
    it fails safe — but it is still a remote edit of a security policy.
    """
    from warden.marketplace.autonomy import delete_policy  # noqa: PLC0415
    deleted = delete_policy(agent_id)
    return {"agent_id": agent_id, "deleted": deleted, "fallback": "L1 default"}


# ── TrustRank leaderboard and graph (SW-11) ───────────────────────────────────
#
# The SOC dashboard has called `GET /marketplace/trust/leaderboard` and
# `GET /marketplace/trust/graph` since those pages were written, and
# `warden/protocols/a2a/agent_card.py` advertises the second one to other agents
# as a capability of this service. Neither route existed. The leaderboard table
# showed `trust_rank` under a "Trades" heading and a hardcoded em dash under
# "Volume" — which is what a table looks like when it was built for a response
# that never arrived.
#
# The machinery was all here: `TrustGraph` computes the ranks, `SybilGuard`
# holds the flags, and `analytics.get_agent_leaderboard` counts trades and
# volume. Only the two routes were missing.


def _trust_engines() -> tuple:
    """Built TrustGraph plus SybilGuard.

    The imports are deferred like every other route in this module (the graph
    pulls in networkx), and doing it once here keeps one suppression instead of
    one per route per import.
    """
    tg = TrustGraph()
    with contextlib.suppress(Exception):
        tg.build_graph()
    return tg, SybilGuard()


@router.get("/trust/leaderboard", summary="TrustRank leaderboard with trade counts")
async def marketplace_trust_leaderboard(
    limit: int = Query(default=20, ge=1, le=50),
    tenant_id: str | None = Query(default=None),
) -> list[dict]:
    """Top agents by TrustRank, joined to their completed-trade totals."""
    tg, sg = _trust_engines()

    # Trades and volume come from completed purchases, where an agent may appear
    # as either side. A "trade" for this table is any settled purchase the agent
    # took part in.
    totals: dict[str, dict[str, float]] = {}
    board = get_agent_leaderboard(tenant_id=tenant_id, limit=50)
    for side in ("top_sellers", "top_buyers"):
        for row in board.get(side, []):
            acc = totals.setdefault(row["agent_id"], {"trades": 0, "volume_usd": 0.0})
            acc["trades"] += int(row.get("trades", 0))
            acc["volume_usd"] += float(row.get("volume_usd", 0.0))

    out: list[dict] = []
    for entry in tg.top_agents(n=limit):
        agent_id = entry["agent_id"]
        counted = totals.get(agent_id, {"trades": 0, "volume_usd": 0.0})
        out.append({
            "agent_id":     agent_id,
            "trust_score":  round(float(entry["trust_rank"]), 4),
            "trust_rank":   round(float(entry["trust_rank"]), 4),
            "sybil_flag":   sg.is_flagged(agent_id),
            "sybil_reason": sg.get_flag_reason(agent_id),
            "trades":       int(counted["trades"]),
            "volume_usd":   round(float(counted["volume_usd"]), 2),
            "transitive_peers": [],
        })
    return out


@router.get("/trust/graph", summary="Trade trust graph — nodes and weighted edges")
async def marketplace_trust_graph(
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """The trade graph TrustRank is computed over.

    Advertised in the A2A agent card, so external agents fetch it to judge
    whether this marketplace's reputation signal is worth trusting.
    """
    tg, sg = _trust_engines()

    ranked = tg.top_agents(n=limit)
    keep = {e["agent_id"] for e in ranked}
    nodes = [
        {
            "id":          e["agent_id"],
            "trust_score": round(float(e["trust_rank"]), 4),
            "sybil_flag":  sg.is_flagged(e["agent_id"]),
        }
        for e in ranked
    ]

    edges = [e for e in tg.edges() if e["source"] in keep and e["target"] in keep]

    return {
        "nodes": nodes,
        "edges": edges,
        "computed_at": datetime.now(UTC).isoformat(),
    }
