"""
warden/semantic_layer/engine.py
────────────────────────────────
SQL generation engine for the Semantic Layer.

Rules
─────
  • Deterministic output for identical QueryObject inputs.
  • Parameterised literals via %s placeholders (safe for psycopg2 / asyncpg).
  • Access-rule enforcement: raises PermissionError for unauthorised metrics/dims.
  • No LLM calls — intent→QueryObject translation lives in api.py.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Any

from warden.semantic_layer.models import (
    Dimension,
    FilterClause,
    Metric,
    QueryObject,
    QueryResult,
    SemanticModel,
)

if TYPE_CHECKING:
    pass

log = logging.getLogger("warden.semantic_layer.engine")
_CACHE_TTL = int(os.getenv("SEMANTIC_CACHE_TTL", "600"))  # 10 min default


def _cache_key(query: QueryObject, tenant_id: str | None) -> str:
    payload = {
        "model_id":   query.model_id,
        "metrics":    sorted(query.metrics),
        "dimensions": sorted(query.dimensions),
        "filters":    [{"d": f.dimension, "o": f.operator, "v": str(f.value)} for f in query.filters],
        "limit":      query.limit,
        "tenant_id":  tenant_id or "",
    }
    return "sl:query:" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]


def _redis_get(key: str) -> QueryResult | None:
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if "memory://" in url:
            return None
        r = _r.from_url(url, decode_responses=True, socket_connect_timeout=1)
        raw = r.get(key)
        if raw and isinstance(raw, str):
            from warden.semantic_layer.models import QueryResult
            return QueryResult(**json.loads(raw))
    except Exception:
        pass
    return None


def _redis_set(key: str, result: QueryResult) -> None:
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if "memory://" in url:
            return
        r = _r.from_url(url, decode_responses=True, socket_connect_timeout=1)
        r.setex(key, _CACHE_TTL, result.model_dump_json())
    except Exception:
        pass

_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

# Operators allowed in a WHERE clause. Anything else is rejected — a filter can
# never smuggle arbitrary SQL through the operator field.
_ALLOWED_FILTER_OPS = frozenset({"=", "!=", "<>", ">", "<", ">=", "<=", "LIKE", "IN", "NOT IN"})


def _safe_ident(name: str) -> str:
    """Return *name* if it is a bare column/identifier, else raise ValueError."""
    if not isinstance(name, str) or not _SAFE_IDENT.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


def _sql_literal(value: Any) -> str:
    """Render *value* as a safe SQL literal (SQLi defence for string-built SQL).

    Strings are single-quoted with embedded quotes doubled; numbers/bools pass
    through as bare tokens; None becomes NULL. Non-scalar types are rejected so
    a dict/list can never reach the query text unescaped.
    """
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (str, bytes)):
        text = value.decode() if isinstance(value, bytes) else value
        return "'" + text.replace("'", "''") + "'"
    raise ValueError(f"Unsupported filter value type: {type(value).__name__}")

# ── Built-in models (shipped with warden) ────────────────────────────────────

_BUILTIN_MODELS: dict[str, SemanticModel] = {}

for _raw in [
    # ── Core security ──────────────────────────────────────────────────────────
    {
        "id": "filter_events",
        "name": "Filter Events",
        "source_table": "filter_log",
        "description": "Security filter decisions — one row per /filter request.",
        "metrics": [
            {"name": "total_requests",  "expression": "COUNT(*)",                      "description": "Total filter requests"},
            {"name": "block_count",     "expression": "COUNT(*) FILTER (WHERE verdict='BLOCK')", "description": "Blocked requests"},
            {"name": "flag_count",      "expression": "COUNT(*) FILTER (WHERE verdict='FLAG')",  "description": "Flagged requests"},
            {"name": "pass_count",      "expression": "COUNT(*) FILTER (WHERE verdict='PASS')",  "description": "Passed requests"},
            {"name": "block_rate",      "expression": "ROUND(100.0 * COUNT(*) FILTER (WHERE verdict='BLOCK') / NULLIF(COUNT(*),0), 2)", "description": "Block rate %", "format": "percent"},
            {"name": "avg_latency_ms",  "expression": "AVG(processing_ms)",            "description": "Avg processing time", "format": "duration_ms"},
            {"name": "p99_latency_ms",  "expression": "PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY processing_ms)", "description": "P99 latency", "format": "duration_ms"},
        ],
        "dimensions": [
            {"name": "tenant_id",   "column": "tenant_id",       "description": "Tenant"},
            {"name": "verdict",     "column": "verdict",         "description": "Decision (PASS/FLAG/BLOCK)"},
            {"name": "stage",       "column": "primary_stage",   "description": "Pipeline stage that triggered"},
            {"name": "date",        "column": "DATE(created_at)","description": "Calendar date"},
            {"name": "hour",        "column": "DATE_TRUNC('hour', created_at)", "description": "Hour bucket"},
            {"name": "week",        "column": "DATE_TRUNC('week', created_at)", "description": "ISO week"},
        ],
    },
    {
        "id": "ers_scores",
        "name": "Entity Risk Scores",
        "source_table": "ers_log",
        "description": "Per-session ERS sliding-window risk scores.",
        "metrics": [
            {"name": "avg_score",    "expression": "AVG(score)",        "description": "Average risk score"},
            {"name": "max_score",    "expression": "MAX(score)",        "description": "Peak risk score"},
            {"name": "shadow_bans",  "expression": "COUNT(*) FILTER (WHERE shadow_banned)", "description": "Shadow-ban events"},
            {"name": "high_risk_sessions", "expression": "COUNT(*) FILTER (WHERE score >= 0.75)", "description": "High-risk sessions (ERS ≥ 0.75)"},
        ],
        "dimensions": [
            {"name": "tenant_id",   "column": "tenant_id",   "description": "Tenant"},
            {"name": "date",        "column": "DATE(ts)",    "description": "Calendar date"},
        ],
    },
    # ── Billing & revenue ──────────────────────────────────────────────────────
    {
        "id": "billing_usage",
        "name": "Billing & Quota",
        "source_table": "billing_usage",
        "description": "Per-tenant request consumption vs quota.",
        "metrics": [
            {"name": "requests_used",  "expression": "SUM(requests)",     "description": "Requests consumed"},
            {"name": "cost_usd",       "expression": "SUM(cost_usd)",     "description": "Estimated cost", "format": "currency"},
            {"name": "quota_pct",      "expression": "AVG(quota_pct)",    "description": "Quota utilisation", "format": "percent"},
            {"name": "overage_usd",    "expression": "SUM(overage_usd)",  "description": "Overage charges", "format": "currency"},
        ],
        "dimensions": [
            {"name": "tenant_id",  "column": "tenant_id",   "description": "Tenant"},
            {"name": "plan",       "column": "plan",        "description": "Billing plan"},
            {"name": "month",      "column": "DATE_TRUNC('month', period_start)", "description": "Billing month"},
        ],
    },
    # ── Security incidents ──────────────────────────────────────────────────────
    {
        "id": "incidents",
        "name": "Security Incidents",
        "source_table": "ai_incidents",
        "description": "STIX-linked AI security incident journal (CM-35). One row per incident.",
        "metrics": [
            {"name": "incident_count",  "expression": "COUNT(*)",                                             "description": "Total incidents"},
            {"name": "high_count",      "expression": "COUNT(*) FILTER (WHERE severity='HIGH')",              "description": "HIGH severity incidents"},
            {"name": "critical_count",  "expression": "COUNT(*) FILTER (WHERE severity='CRITICAL')",          "description": "CRITICAL incidents"},
            {"name": "open_count",      "expression": "COUNT(*) FILTER (WHERE status='OPEN')",                "description": "Open incidents"},
            {"name": "avg_resolution_hrs", "expression": "AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600) FILTER (WHERE resolved_at IS NOT NULL)", "description": "Avg resolution time (hours)", "format": "duration_ms"},
        ],
        "dimensions": [
            {"name": "tenant_id",  "column": "tenant_id",             "description": "Tenant"},
            {"name": "severity",   "column": "severity",              "description": "Severity (LOW/MEDIUM/HIGH/CRITICAL)"},
            {"name": "status",     "column": "status",                "description": "Status (OPEN/RESOLVED/CLOSED)"},
            {"name": "category",   "column": "category",              "description": "Incident category"},
            {"name": "date",       "column": "DATE(created_at)",      "description": "Incident date"},
            {"name": "week",       "column": "DATE_TRUNC('week', created_at)", "description": "ISO week"},
        ],
    },
    # ── Vendor & DPA governance ────────────────────────────────────────────────
    {
        "id": "vendor_contracts",
        "name": "Vendor Contracts & DPA",
        "source_table": "vendor_dpa_records",
        "description": "AI vendor governance register — DPA status, expiry, risk tiers (BL-22).",
        "metrics": [
            {"name": "vendor_count",    "expression": "COUNT(DISTINCT vendor_id)",                                    "description": "Total vendors"},
            {"name": "active_dpas",     "expression": "COUNT(*) FILTER (WHERE status='ACTIVE')",                      "description": "Active DPAs"},
            {"name": "expiring_30d",    "expression": "COUNT(*) FILTER (WHERE expires_at BETWEEN NOW() AND NOW() + INTERVAL '30 days')", "description": "DPAs expiring in 30 days"},
            {"name": "high_risk_count", "expression": "COUNT(*) FILTER (WHERE risk_tier='HIGH')",                     "description": "High-risk vendors"},
        ],
        "dimensions": [
            {"name": "tenant_id",   "column": "tenant_id",   "description": "Tenant"},
            {"name": "risk_tier",   "column": "risk_tier",   "description": "Risk tier (LOW/MEDIUM/HIGH)"},
            {"name": "status",      "column": "status",      "description": "DPA status (ACTIVE/EXPIRED/PENDING)"},
            {"name": "provider_type","column": "provider_type","description": "Vendor type (LLM/Storage/Analytics)"},
        ],
    },
    # ── Agentic Commerce ───────────────────────────────────────────────────────
    {
        "id": "agentic_orders",
        "name": "Agentic Commerce Orders",
        "source_table": "commerce_orders",
        "description": "Purchases executed by AI agents via UCP/AP2/MCP protocols (CM-40).",
        "metrics": [
            {"name": "order_count",     "expression": "COUNT(*)",                                             "description": "Total orders"},
            {"name": "total_spent_usd", "expression": "SUM(total_usd)",                                      "description": "Total spend", "format": "currency"},
            {"name": "avg_order_usd",   "expression": "AVG(total_usd)",                                      "description": "Average order value", "format": "currency"},
            {"name": "approved_count",  "expression": "COUNT(*) FILTER (WHERE status='APPROVED')",            "description": "Approved orders"},
            {"name": "rejected_count",  "expression": "COUNT(*) FILTER (WHERE status='REJECTED')",           "description": "Rejected orders"},
        ],
        "dimensions": [
            {"name": "tenant_id",  "column": "tenant_id",              "description": "Tenant"},
            {"name": "merchant",   "column": "merchant_domain",        "description": "Merchant / store"},
            {"name": "status",     "column": "status",                 "description": "Order status"},
            {"name": "protocol",   "column": "protocol",               "description": "Protocol (UCP/AP2/MCP)"},
            {"name": "month",      "column": "DATE_TRUNC('month', created_at)", "description": "Order month"},
        ],
    },
    # ── Sovereign tunnel sessions ──────────────────────────────────────────────
    {
        "id": "tunnel_sessions",
        "name": "Sovereign Tunnel Sessions",
        "source_table": "sovereign_attestations",
        "description": "Data transfers through MASQUE tunnels per jurisdiction (Sovereign AI Cloud).",
        "metrics": [
            {"name": "transfer_count",   "expression": "COUNT(*)",                                             "description": "Total transfers"},
            {"name": "compliant_count",  "expression": "COUNT(*) FILTER (WHERE compliant=TRUE)",               "description": "Compliant transfers"},
            {"name": "blocked_count",    "expression": "COUNT(*) FILTER (WHERE compliant=FALSE)",              "description": "Blocked (non-compliant)"},
            {"name": "compliance_rate",  "expression": "ROUND(100.0 * COUNT(*) FILTER (WHERE compliant=TRUE) / NULLIF(COUNT(*),0), 2)", "description": "Compliance rate %", "format": "percent"},
        ],
        "dimensions": [
            {"name": "tenant_id",    "column": "tenant_id",    "description": "Tenant"},
            {"name": "jurisdiction", "column": "jurisdiction", "description": "Target jurisdiction (EU/US/UK/CA…)"},
            {"name": "data_class",   "column": "data_class",   "description": "Data classification (PII/PHI/FINANCIAL…)"},
            {"name": "date",         "column": "DATE(issued_at)", "description": "Attestation date"},
        ],
    },
    # ── Compliance & training ──────────────────────────────────────────────────
    {
        "id": "compliance_attestations",
        "name": "Compliance & Training",
        "source_table": "training_completions",
        "description": "Employee AI training completion records (CM-38) + HMAC attestations.",
        "metrics": [
            {"name": "completion_count",  "expression": "COUNT(*)",                                              "description": "Total completions"},
            {"name": "unique_employees",  "expression": "COUNT(DISTINCT employee_id)",                           "description": "Employees trained"},
            {"name": "overdue_count",     "expression": "COUNT(*) FILTER (WHERE expires_at < NOW() AND renewed=FALSE)", "description": "Overdue renewals"},
            {"name": "compliance_pct",    "expression": "ROUND(100.0 * COUNT(*) FILTER (WHERE renewed=TRUE OR expires_at > NOW()) / NULLIF(COUNT(*),0), 2)", "description": "Compliance %", "format": "percent"},
        ],
        "dimensions": [
            {"name": "tenant_id",    "column": "tenant_id",    "description": "Tenant"},
            {"name": "program",      "column": "program_name", "description": "Training program"},
            {"name": "department",   "column": "department",   "description": "Department"},
            {"name": "month",        "column": "DATE_TRUNC('month', completed_at)", "description": "Completion month"},
        ],
    },
    # ── Tax & spend allocation ─────────────────────────────────────────────────
    {
        "id": "ai_spend",
        "name": "AI Cost Allocation",
        "source_table": "cost_allocation_entries",
        "description": "Per-department AI spend tracking and budget vs actuals (BL-23).",
        "metrics": [
            {"name": "total_cost_usd",   "expression": "SUM(amount_usd)",             "description": "Total AI spend", "format": "currency"},
            {"name": "avg_cost_usd",     "expression": "AVG(amount_usd)",             "description": "Average transaction cost", "format": "currency"},
            {"name": "transaction_count","expression": "COUNT(*)",                    "description": "Cost entries"},
            {"name": "vendor_count",     "expression": "COUNT(DISTINCT vendor)",      "description": "Distinct AI vendors"},
        ],
        "dimensions": [
            {"name": "tenant_id",   "column": "tenant_id",   "description": "Tenant"},
            {"name": "department",  "column": "department",  "description": "Department"},
            {"name": "vendor",      "column": "vendor",      "description": "AI vendor / provider"},
            {"name": "cost_type",   "column": "cost_type",   "description": "Cost type (inference/storage/compute)"},
            {"name": "month",       "column": "DATE_TRUNC('month', recorded_at)", "description": "Month"},
        ],
    },
    # ── M2M Marketplace — SEM-02 (v6.8) ───────────────────────────────────────
    {
        "id": "marketplace_listings",
        "name": "Marketplace Listings",
        "source_table": "mp_listings",
        "description": "M2M Marketplace product listings — one row per listing (SEM-02).",
        "metrics": [
            {"name": "total_listings",  "expression": "COUNT(*)",                                                               "description": "Total listings created"},
            {"name": "active_listings", "expression": "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)",                     "description": "Currently active listings"},
            {"name": "avg_price",       "expression": "AVG(price)",                                                             "description": "Average listing price", "format": "currency"},
            {"name": "total_value",     "expression": "SUM(price * quantity)",                                                  "description": "Total value of all listings", "format": "currency"},
        ],
        "dimensions": [
            {"name": "listing_id",      "column": "id",               "description": "Listing ID"},
            {"name": "seller_agent_id", "column": "seller_agent_id",  "description": "Seller agent"},
            {"name": "community_id",    "column": "community_id",     "description": "Community"},
            {"name": "asset_type",      "column": "asset_type",       "description": "Asset type"},
            {"name": "chain",           "column": "chain",            "description": "Blockchain"},
            {"name": "date",            "column": "DATE(created_at)", "description": "Listing date"},
            {"name": "status",          "column": "status",           "description": "Listing status"},
        ],
    },
    {
        "id": "marketplace_trades",
        "name": "Marketplace Trades",
        "source_table": "mp_trades",
        "description": "Completed M2M trades — one row per purchase (SEM-02).",
        "metrics": [
            {"name": "total_trades",    "expression": "COUNT(*)",                        "description": "Total completed trades"},
            {"name": "trade_volume_usd","expression": "SUM(amount_usd)",                 "description": "Total trade volume", "format": "currency"},
            {"name": "avg_trade_value", "expression": "AVG(amount_usd)",                 "description": "Average trade value", "format": "currency"},
            {"name": "unique_buyers",   "expression": "COUNT(DISTINCT buyer_agent_id)",  "description": "Unique buyers"},
        ],
        "dimensions": [
            {"name": "trade_id",        "column": "id",               "description": "Trade ID"},
            {"name": "buyer_agent_id",  "column": "buyer_agent_id",   "description": "Buyer agent"},
            {"name": "seller_agent_id", "column": "seller_agent_id",  "description": "Seller agent"},
            {"name": "listing_id",      "column": "listing_id",       "description": "Source listing"},
            {"name": "community_id",    "column": "community_id",     "description": "Community"},
            {"name": "date",            "column": "DATE(purchased_at)","description": "Trade date"},
            {"name": "chain",           "column": "chain",            "description": "Blockchain"},
        ],
    },
    {
        "id": "marketplace_escrow",
        "name": "Marketplace Escrow",
        "source_table": "mp_escrow",
        "description": "M2M escrow contracts — one row per escrow (SEM-02).",
        "metrics": [
            {"name": "total_escrows",       "expression": "COUNT(*)",                                                                        "description": "Total escrow contracts"},
            {"name": "active_escrows",      "expression": "SUM(CASE WHEN status IN ('funded','delivered') THEN 1 ELSE 0 END)",               "description": "Active escrow contracts"},
            {"name": "disputed_escrows",    "expression": "SUM(CASE WHEN status = 'disputed' THEN 1 ELSE 0 END)",                            "description": "Disputed escrow contracts"},
            {"name": "avg_resolution_hours","expression": "AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600) FILTER (WHERE resolved_at IS NOT NULL)", "description": "Average resolution hours", "format": "duration_ms"},
        ],
        "dimensions": [
            {"name": "escrow_id",       "column": "id",               "description": "Escrow ID"},
            {"name": "buyer_agent_id",  "column": "buyer_agent_id",   "description": "Buyer agent"},
            {"name": "seller_agent_id", "column": "seller_agent_id",  "description": "Seller agent"},
            {"name": "community_id",    "column": "community_id",     "description": "Community"},
            {"name": "chain",           "column": "chain",            "description": "Blockchain"},
            {"name": "status",          "column": "status",           "description": "Escrow status"},
            {"name": "date",            "column": "DATE(created_at)", "description": "Creation date"},
        ],
    },
    {
        "id": "marketplace_negotiations",
        "name": "Marketplace Negotiations",
        "source_table": "mp_negotiations",
        "description": "Price negotiation sessions between M2M agents (SEM-02).",
        "metrics": [
            {"name": "total_negotiations", "expression": "COUNT(*)",                                                                          "description": "Total negotiation sessions"},
            {"name": "avg_rounds",         "expression": "AVG(rounds)",                                                                       "description": "Average negotiation rounds"},
            {"name": "success_rate",       "expression": "ROUND(1.0 * SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 4)", "description": "Negotiation success rate", "format": "percent"},
        ],
        "dimensions": [
            {"name": "negotiation_id",  "column": "id",               "description": "Negotiation ID"},
            {"name": "buyer_agent_id",  "column": "buyer_agent_id",   "description": "Buyer agent"},
            {"name": "seller_agent_id", "column": "seller_agent_id",  "description": "Seller agent"},
            {"name": "date",            "column": "DATE(created_at)", "description": "Negotiation date"},
            {"name": "status",          "column": "status",           "description": "Outcome (accepted/rejected/expired)"},
        ],
    },
    {
        "id": "marketplace_reputation",
        "name": "Marketplace Reputation Scores",
        "source_table": "mp_reputation",
        "description": "Per-agent composite reputation scores in M2M Marketplace (SEM-02).",
        "metrics": [
            {"name": "avg_reputation", "expression": "AVG(overall_score)",                                   "description": "Average reputation score", "format": "percent"},
            {"name": "top_agents",     "expression": "COUNT(CASE WHEN overall_score > 0.8 THEN 1 END)",      "description": "High-reputation agents (score > 0.8)"},
            {"name": "agent_count",    "expression": "COUNT(DISTINCT agent_id)",                             "description": "Agents with reputation scores"},
        ],
        "dimensions": [
            {"name": "agent_id",      "column": "agent_id",            "description": "Agent ID"},
            {"name": "community_id",  "column": "community_id",        "description": "Community"},
            {"name": "date",          "column": "DATE(calculated_at)", "description": "Score calculation date"},
        ],
    },
    {
        "id": "marketplace_governance",
        "name": "Marketplace DAO Governance",
        "source_table": "mp_proposals",
        "description": "DAO governance proposals and voting outcomes in M2M communities (SEM-02).",
        "metrics": [
            {"name": "total_proposals",    "expression": "COUNT(*)",                                                                     "description": "Total DAO proposals"},
            {"name": "passed_proposals",   "expression": "SUM(CASE WHEN status = 'passed' THEN 1 ELSE 0 END)",                           "description": "Passed proposals"},
            {"name": "avg_voter_turnout",  "expression": "AVG(1.0 * voter_count / NULLIF(eligible_voters, 0))",                         "description": "Average voter turnout", "format": "percent"},
        ],
        "dimensions": [
            {"name": "proposal_id",    "column": "id",               "description": "Proposal ID"},
            {"name": "community_id",   "column": "community_id",     "description": "Community"},
            {"name": "proposal_type",  "column": "proposal_type",    "description": "Proposal type (parameter/upgrade/policy/membership)"},
            {"name": "date",           "column": "DATE(created_at)", "description": "Proposal date"},
            {"name": "status",         "column": "status",           "description": "Proposal status"},
        ],
    },
    {
        "id": "marketplace_agents",
        "name": "Marketplace Registered Agents",
        "source_table": "mp_agents",
        "description": "M2M Marketplace registered AI agents registry (SEM-02).",
        "metrics": [
            {"name": "total_agents",  "expression": "COUNT(*)",                                             "description": "Total registered agents"},
            {"name": "active_agents", "expression": "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)",  "description": "Active agents"},
        ],
        "dimensions": [
            {"name": "agent_id",      "column": "id",                   "description": "Agent ID"},
            {"name": "community_id",  "column": "community_id",         "description": "Community"},
            {"name": "date",          "column": "DATE(registered_at)",  "description": "Registration date"},
            {"name": "capabilities",  "column": "capabilities",         "description": "Agent capabilities"},
        ],
    },
    {
        "id": "marketplace_assets",
        "name": "Marketplace Tokenized Assets",
        "source_table": "mp_assets",
        "description": "Tokenized assets traded in the M2M Marketplace (SEM-02).",
        "metrics": [
            {"name": "total_assets",  "expression": "COUNT(*)",                             "description": "Total tokenized assets"},
            {"name": "by_type",       "expression": "COUNT(*) FILTER (WHERE asset_type IS NOT NULL)", "description": "Assets by type"},
        ],
        "dimensions": [
            {"name": "asset_id",      "column": "id",               "description": "Asset ID"},
            {"name": "community_id",  "column": "community_id",     "description": "Community"},
            {"name": "asset_type",    "column": "asset_type",       "description": "Asset type (data/compute/model/api/other)"},
            {"name": "date",          "column": "DATE(created_at)", "description": "Creation date"},
        ],
    },
    {
        "id": "marketplace_maestro_flags",
        "name": "Marketplace MAESTRO Flags",
        "source_table": "mp_flags",
        "description": "MAESTRO security flags raised against M2M Marketplace agents (SEM-02).",
        "metrics": [
            {"name": "total_flags",  "expression": "COUNT(*)",                                                             "description": "Total MAESTRO flags"},
            {"name": "high_threats", "expression": "SUM(CASE WHEN threat_level IN ('high','critical') THEN 1 ELSE 0 END)", "description": "High/critical-level threats"},
        ],
        "dimensions": [
            {"name": "flag_id",       "column": "id",               "description": "Flag ID"},
            {"name": "agent_id",      "column": "agent_id",         "description": "Flagged agent"},
            {"name": "community_id",  "column": "community_id",     "description": "Community"},
            {"name": "flag_type",     "column": "flag_type",        "description": "Flag type"},
            {"name": "threat_level",  "column": "threat_level",     "description": "Threat level (low/medium/high/critical)"},
            {"name": "date",          "column": "DATE(created_at)", "description": "Flag date"},
        ],
    },
    {
        "id": "marketplace_cross_chain",
        "name": "Marketplace Cross-Chain Transactions",
        "source_table": "mp_cross_chain",
        "description": "Cross-chain bridge transactions in the M2M Marketplace (SEM-02).",
        "metrics": [
            {"name": "total_cross_chain",  "expression": "COUNT(*)",             "description": "Total cross-chain transactions"},
            {"name": "volume_usd",         "expression": "SUM(amount_usd)",      "description": "Cross-chain volume", "format": "currency"},
            {"name": "unique_agents",      "expression": "COUNT(DISTINCT agent_id)", "description": "Agents using cross-chain"},
        ],
        "dimensions": [
            {"name": "tx_id",         "column": "id",               "description": "Transaction ID"},
            {"name": "agent_id",      "column": "agent_id",         "description": "Initiating agent"},
            {"name": "community_id",  "column": "community_id",     "description": "Community"},
            {"name": "chain",         "column": "chain",            "description": "Target blockchain"},
            {"name": "status",        "column": "status",           "description": "Transaction status"},
            {"name": "date",          "column": "DATE(created_at)", "description": "Transaction date"},
        ],
    },
    # ── GSAM marketplace agent stats (GSAM-06) ─────────────────────────────────
    {
        "id": "gsam_agent_stats",
        "name": "GSAM Agent Statistics",
        # SQLite rollup (gsam DB) — NEVER ClickHouse. The engine emits Postgres/
        # SQLite dialect; the hourly rollup keeps this queryable when CH is down.
        "source_table": "gsam_agent_stats",
        "description": "Hourly per-agent marketplace rollup — cost, tokens, drift, trust (GSAM-06).",
        "metrics": [
            {"name": "total_events",  "expression": "SUM(events)",           "description": "Total agent events"},
            {"name": "agent_count",   "expression": "COUNT(DISTINCT agent_id)", "description": "Distinct agents"},
            {"name": "tokens_in",     "expression": "SUM(tokens_in)",        "description": "Input tokens"},
            {"name": "tokens_out",    "expression": "SUM(tokens_out)",       "description": "Output tokens"},
            {"name": "cost_usd",      "expression": "SUM(cost_usd)",         "description": "Total LLM cost", "format": "currency"},
            {"name": "avg_drift",     "expression": "AVG(drift)",            "description": "Average behavioural drift"},
            {"name": "max_drift",     "expression": "MAX(drift)",            "description": "Peak drift"},
            {"name": "avg_trust",     "expression": "AVG(trust)",            "description": "Average trust score"},
        ],
        "dimensions": [
            {"name": "agent_id",   "column": "agent_id",    "description": "Marketplace agent"},
            {"name": "tenant_id",  "column": "tenant_id",   "description": "Tenant"},
            {"name": "hour",       "column": "hour_bucket", "description": "Hour bucket (ISO, truncated)"},
        ],
    },
]:
    m = SemanticModel(**_raw)  # type: ignore[arg-type]
    _BUILTIN_MODELS[m.id] = m


class SemanticEngine:
    """Deterministic SQL generator for SemanticModel queries."""

    def __init__(self) -> None:
        self._models: dict[str, SemanticModel] = dict(_BUILTIN_MODELS)

    # ── Registry ──────────────────────────────────────────────────────────────

    def register_model(self, model: SemanticModel) -> None:
        self._models[model.id] = model

    def list_models(self) -> list[SemanticModel]:
        return list(self._models.values())

    def get_model(self, model_id: str) -> SemanticModel:
        m = self._models.get(model_id)
        if m is None:
            raise KeyError(f"Unknown semantic model: {model_id!r}")
        return m

    # ── Access control ────────────────────────────────────────────────────────

    def _check_access(
        self,
        model: SemanticModel,
        query: QueryObject,
        tenant_id: str | None,
    ) -> None:
        rules = [r for r in model.access_rules if r.tenant_id in (None, tenant_id)]
        if not rules:
            return  # no rules = open
        allowed_m: set[str] = set()
        allowed_d: set[str] = set()
        for r in rules:
            allowed_m.update(r.allowed_metrics)
            allowed_d.update(r.allowed_dimensions)
        for m in query.metrics:
            if allowed_m and m not in allowed_m:
                raise PermissionError(f"Metric {m!r} not permitted for tenant {tenant_id!r}")
        for d in query.dimensions:
            if allowed_d and d not in allowed_d:
                raise PermissionError(f"Dimension {d!r} not permitted for tenant {tenant_id!r}")

    # ── SQL generation ────────────────────────────────────────────────────────

    @staticmethod
    def _safe(name: str) -> str:
        if not _SAFE_IDENT.match(name):
            raise ValueError(f"Unsafe identifier: {name!r}")
        return name

    def _resolve_metric(self, model: SemanticModel, name: str) -> str:
        for m in model.metrics:
            if m.name == name:
                return m.effective_expression()
        raise KeyError(f"Unknown metric {name!r} in model {model.id!r}")

    def _resolve_dimension(self, model: SemanticModel, name: str) -> str:
        for d in model.dimensions:
            if d.name == name:
                return d.effective_column()
        raise KeyError(f"Unknown dimension {name!r} in model {model.id!r}")

    def _build_filter_sql(
        self,
        model: SemanticModel,
        filters: list[FilterClause],
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        allowed_ops = {"=", "!=", ">", "<", ">=", "<=", "LIKE", "IN"}
        for f in filters:
            col = self._resolve_dimension(model, f.dimension)
            op  = f.operator.upper()
            if op not in allowed_ops:
                raise ValueError(f"Unsupported operator: {op!r}")
            if op == "IN":
                vals = list(f.value)
                placeholders = ", ".join(["%s"] * len(vals))
                clauses.append(f"({col} IN ({placeholders}))")
                params.extend(vals)
            else:
                clauses.append(f"({col} {op} %s)")
                params.append(f.value)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        return where, params

    def generate(
        self,
        query: QueryObject,
        tenant_id: str | None = None,
        use_cache: bool = True,
    ) -> QueryResult:
        t0 = time.perf_counter()
        model = self.get_model(query.model_id)
        self._check_access(model, query, tenant_id)

        # Redis cache — skip for very short limits or when disabled
        cache_key = _cache_key(query, tenant_id) if use_cache and query.limit >= 10 else None
        if cache_key:
            cached = _redis_get(cache_key)
            if cached:
                cached.generation_ms = round((time.perf_counter() - t0) * 1000, 2)
                log.debug("semantic_layer cache HIT %s", cache_key)
                return cached

        select_parts: list[str] = []
        group_by: list[str] = []

        for dim_name in query.dimensions:
            col = self._resolve_dimension(model, dim_name)
            select_parts.append(f"{col} AS {self._safe(dim_name)}")
            group_by.append(col)

        for met_name in query.metrics:
            expr = self._resolve_metric(model, met_name)
            select_parts.append(f"{expr} AS {self._safe(met_name)}")

        where_clause, _params = self._build_filter_sql(model, query.filters)

        select_sql = ",\n    ".join(select_parts)
        table      = self._safe(model.source_table)
        group_sql  = f"GROUP BY {', '.join(group_by)}" if group_by else ""
        limit_sql  = f"LIMIT {query.limit}"

        sql = (
            f"SELECT\n    {select_sql}\nFROM {table}\n"
            f"{where_clause}\n{group_sql}\n{limit_sql}"
        ).strip()

        result = QueryResult(
            sql=sql,
            model_id=model.id,
            metrics=query.metrics,
            dimensions=query.dimensions,
            generation_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
        if cache_key:
            _redis_set(cache_key, result)
        return result


_engine = SemanticEngine()


def get_engine() -> SemanticEngine:
    return _engine


# ── SemanticQueryEngine — test-facing API ─────────────────────────────────────

class SemanticQueryEngine:
    """Higher-level engine: takes (QueryObject, SemanticModel) directly.

    Used by tests and the repository layer. `SemanticEngine` is the
    registry-aware engine used by the FastAPI router.
    """

    def compile_query(self, query: QueryObject, model: SemanticModel) -> str:
        """Return deterministic SQL for the given query against the given model."""
        select_parts: list[str] = []
        group_by: list[str] = []

        for dim_name in query.dimensions:
            # Column comes from the trusted model when the dim is known; the
            # bare-name fallback and the alias are validated so neither the
            # column nor the alias can inject SQL.
            col = next(
                (d.effective_column() for d in model.dimensions if d.name == dim_name),
                dim_name,
            )
            alias = _safe_ident(dim_name)
            select_parts.append(f"{_safe_ident(col)} AS {alias}")
            group_by.append(_safe_ident(col))

        for met_name in query.metrics:
            # Metric expressions are authored in the model (trusted); only the
            # alias is user-facing, so validate it. Unknown metrics fall back to
            # a bare identifier, which must also be a safe identifier.
            known = next((m for m in model.metrics if m.name == met_name), None)
            expr = known.effective_expression() if known else _safe_ident(met_name)
            select_parts.append(f"{expr} AS {_safe_ident(met_name)}")

        where_parts: list[str] = []
        for f in query.filters:
            col = next(
                (d.effective_column() for d in model.dimensions if d.name == f.dimension),
                f.dimension,
            )
            col = _safe_ident(col)
            op = f.sql_operator().upper()
            if op not in _ALLOWED_FILTER_OPS:
                raise ValueError(f"Unsupported filter operator: {op!r}")
            if op in ("IN", "NOT IN"):
                values = f.value if isinstance(f.value, (list, tuple, set)) else [f.value]
                vals = ", ".join(_sql_literal(v) for v in values)
                where_parts.append(f"({col} {op} ({vals}))")
            else:
                where_parts.append(f"({col} {op} {_sql_literal(f.value)})")

        select_sql  = ",\n    ".join(select_parts)
        table       = model.source_table
        where_sql   = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        group_sql   = f"GROUP BY {', '.join(group_by)}" if group_by else ""
        limit_sql   = f"LIMIT {query.limit}"

        return (
            f"SELECT\n    {select_sql}\nFROM {table}\n"
            f"{where_sql}\n{group_sql}\n{limit_sql}"
        ).strip()

    def validate_model(self, model: SemanticModel) -> tuple[bool, list[str]]:
        """Return (ok, errors). A model is valid if it has at least one metric."""
        errors: list[str] = []
        if not model.name:
            errors.append("Model must have a name.")
        if not model.metrics:
            errors.append("Model must define at least one metric.")
        for m in model.metrics:
            if not m.effective_expression():
                errors.append(f"Metric '{m.name}' has no expression.")
        for d in model.dimensions:
            if not d.effective_column():
                errors.append(f"Dimension '{d.name}' has no column/sql_field.")
        return (len(errors) == 0, errors)

    def get_context_for_llm(self, model: SemanticModel) -> dict[str, Any]:
        """Return model context safe for LLM prompts — no raw SQL exposed."""
        return {
            "model_id":    model.id,
            "model_name":  model.name,
            "description": model.description,
            "metrics": [
                {"name": m.name, "description": m.description, "format": m.format}
                for m in model.metrics
            ],
            "dimensions": [
                {"name": d.name, "description": d.description, "type": d.type}
                for d in model.dimensions
            ],
        }

    def export_osi(self, model: SemanticModel) -> dict[str, Any]:
        """Export model to OSI 1.0 interchange format."""
        return {
            "osi_version":   "1.0",
            "id":            model.id,
            "name":          model.name,
            "description":   model.description,
            "source_table":  model.source_table,
            "owner_tenant":  model.owner_tenant,
            "metrics": [
                {
                    "name":        m.name,
                    "expression":  m.effective_expression(),
                    "description": m.description,
                    "format":      m.format,
                }
                for m in model.metrics
            ],
            "dimensions": [
                {
                    "name":        d.name,
                    "column":      d.effective_column(),
                    "description": d.description,
                    "type":        d.type,
                }
                for d in model.dimensions
            ],
        }

    def import_osi(self, data: dict[str, Any], tenant_id: str) -> SemanticModel:
        """Import from OSI 1.0 interchange format into a SemanticModel."""
        return SemanticModel(
            id=data.get("id", ""),
            name=data["name"],
            description=data.get("description", ""),
            source_table=data.get("source_table", ""),
            owner_tenant=tenant_id,
            metrics=[
                Metric(
                    name=m["name"],
                    expression=m.get("expression", ""),
                    description=m.get("description", ""),
                    format=m.get("format", "number"),
                )
                for m in data.get("metrics", [])
            ],
            dimensions=[
                Dimension(
                    name=d["name"],
                    column=d.get("column", ""),
                    description=d.get("description", ""),
                    type=d.get("type", "string"),
                )
                for d in data.get("dimensions", [])
            ],
        )
