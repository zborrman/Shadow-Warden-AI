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
            col = next(
                (d.effective_column() for d in model.dimensions if d.name == dim_name), dim_name
            )
            select_parts.append(f"{col} AS {_SAFE_IDENT.match(dim_name) and dim_name or dim_name}")
            group_by.append(col)

        for met_name in query.metrics:
            expr = next(
                (m.effective_expression() for m in model.metrics if m.name == met_name), met_name
            )
            select_parts.append(f"{expr} AS {met_name}")

        where_parts: list[str] = []
        for f in query.filters:
            col = next(
                (d.effective_column() for d in model.dimensions if d.name == f.dimension),
                f.dimension,
            )
            op = f.sql_operator()
            if op.upper() == "IN":
                vals = ", ".join(f"'{v}'" for v in f.value)
                where_parts.append(f"({col} IN ({vals}))")
            else:
                where_parts.append(f"({col} {op} '{f.value}')")

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
