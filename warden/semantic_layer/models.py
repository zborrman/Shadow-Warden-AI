"""
warden/semantic_layer/models.py
────────────────────────────────
Pydantic models for the Semantic Layer (Headless BI).

Core concepts
─────────────
  SemanticModel   — named metric/dimension contract for a data source
  QueryObject     — structured query: model + metrics + dimensions + filters
  QueryResult     — generated SQL + optional rows preview
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ── Semantic model registry ───────────────────────────────────────────────────

class Dimension(BaseModel):
    name: str
    column: str = ""          # canonical field name
    sql_field: str = ""       # alias used by repository layer
    description: str = ""
    type: str = "string"      # string | number | time | boolean

    def effective_column(self) -> str:
        return self.column or self.sql_field


class Metric(BaseModel):
    name: str
    expression: str = ""      # canonical aggregation expression
    sql_expression: str = ""  # alias used by repository layer
    description: str = ""
    format: str = "number"    # number | currency | percent | duration_ms

    def effective_expression(self) -> str:
        return self.expression or self.sql_expression


class AccessRule(BaseModel):
    tenant_id: str | None = None   # None = global
    allowed_metrics: list[str] = Field(default_factory=list)
    allowed_dimensions: list[str] = Field(default_factory=list)


class SemanticModel(BaseModel):
    id: str = ""
    name: str
    source_table: str = ""
    description: str = ""
    owner_tenant: str = ""    # tenant that owns this model (repository layer)
    created_at: str = ""
    updated_at: str = ""
    metrics: list[Metric] = Field(default_factory=list)
    dimensions: list[Dimension] = Field(default_factory=list)
    access_rules: list[AccessRule] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    def metric_names(self) -> list[str]:
        return [m.name for m in self.metrics]

    def dimension_names(self) -> list[str]:
        return [d.name for d in self.dimensions]


# ── Query ─────────────────────────────────────────────────────────────────────

_OP_MAP: dict[str, str] = {
    "eq": "=", "ne": "!=", "neq": "!=",
    "gt": ">", "lt": "<", "gte": ">=", "lte": "<=",
    "like": "LIKE", "in": "IN",
}


class FilterClause(BaseModel):
    dimension: str
    operator: str = "="     # =, !=, >, <, IN, LIKE
    value: Any

    def sql_operator(self) -> str:
        return _OP_MAP.get(self.operator.lower(), self.operator)


# Alias used by tests
Filter = FilterClause


class QueryObject(BaseModel):
    model_id: str
    metrics: list[str]
    dimensions: list[str] = Field(default_factory=list)
    filters: list[FilterClause] = Field(default_factory=list)
    limit: int = Field(default=1000, ge=1, le=10_000)
    intent: str | None = None   # raw natural-language intent (for audit)


class QueryResult(BaseModel):
    sql: str
    params: list[Any] = Field(default_factory=list)  # bound values for the %s placeholders in `sql`
    model_id: str
    metrics: list[str]
    dimensions: list[str]
    row_count: int | None = None
    preview: list[dict[str, Any]] = Field(default_factory=list)
    generation_ms: float = 0.0
