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

import re
import time
from typing import Any

from warden.semantic_layer.models import (
    FilterClause,
    QueryObject,
    QueryResult,
    SemanticModel,
)

_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

# ── Built-in models (shipped with warden) ────────────────────────────────────

_BUILTIN_MODELS: dict[str, SemanticModel] = {}

for _raw in [
    {
        "id": "filter_events",
        "name": "Filter Events",
        "source_table": "filter_log",
        "description": "Security filter decisions — one row per /filter request.",
        "metrics": [
            {"name": "total_requests",  "expression": "COUNT(*)",                      "description": "Total filter requests"},
            {"name": "block_count",     "expression": "COUNT(*) FILTER (WHERE verdict='BLOCK')", "description": "Blocked requests"},
            {"name": "flag_count",      "expression": "COUNT(*) FILTER (WHERE verdict='FLAG')",  "description": "Flagged requests"},
            {"name": "avg_latency_ms",  "expression": "AVG(processing_ms)",            "description": "Avg processing time", "format": "duration_ms"},
            {"name": "p99_latency_ms",  "expression": "PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY processing_ms)", "description": "P99 latency", "format": "duration_ms"},
        ],
        "dimensions": [
            {"name": "tenant_id",   "column": "tenant_id",   "description": "Tenant"},
            {"name": "verdict",     "column": "verdict",     "description": "Decision (PASS/FLAG/BLOCK)"},
            {"name": "stage",       "column": "primary_stage","description": "Pipeline stage that triggered"},
            {"name": "date",        "column": "DATE(created_at)", "description": "Calendar date"},
            {"name": "hour",        "column": "DATE_TRUNC('hour', created_at)", "description": "Hour bucket"},
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
        ],
        "dimensions": [
            {"name": "tenant_id",   "column": "tenant_id",   "description": "Tenant"},
            {"name": "date",        "column": "DATE(ts)",    "description": "Calendar date"},
        ],
    },
    {
        "id": "billing_usage",
        "name": "Billing & Quota",
        "source_table": "billing_usage",
        "description": "Per-tenant request consumption vs quota.",
        "metrics": [
            {"name": "requests_used",  "expression": "SUM(requests)",     "description": "Requests consumed"},
            {"name": "cost_usd",       "expression": "SUM(cost_usd)",     "description": "Estimated cost", "format": "currency"},
            {"name": "quota_pct",      "expression": "AVG(quota_pct)",    "description": "Quota utilisation", "format": "percent"},
        ],
        "dimensions": [
            {"name": "tenant_id",  "column": "tenant_id",   "description": "Tenant"},
            {"name": "plan",       "column": "plan",        "description": "Billing plan"},
            {"name": "month",      "column": "DATE_TRUNC('month', period_start)", "description": "Billing month"},
        ],
    },
]:
    m = SemanticModel(**_raw)
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
                return m.expression
        raise KeyError(f"Unknown metric {name!r} in model {model.id!r}")

    def _resolve_dimension(self, model: SemanticModel, name: str) -> str:
        for d in model.dimensions:
            if d.name == name:
                return d.column
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
    ) -> QueryResult:
        t0 = time.perf_counter()
        model = self.get_model(query.model_id)
        self._check_access(model, query, tenant_id)

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

        return QueryResult(
            sql=sql,
            model_id=model.id,
            metrics=query.metrics,
            dimensions=query.dimensions,
            generation_ms=round((time.perf_counter() - t0) * 1000, 2),
        )


_engine = SemanticEngine()


def get_engine() -> SemanticEngine:
    return _engine
