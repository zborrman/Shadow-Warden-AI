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
    column: str
    description: str = ""


class Metric(BaseModel):
    name: str
    expression: str          # e.g. "COUNT(*)" or "SUM(cost_usd)"
    description: str = ""
    format: str = "number"   # number | currency | percent | duration_ms


class AccessRule(BaseModel):
    tenant_id: str | None = None   # None = global
    allowed_metrics: list[str] = Field(default_factory=list)
    allowed_dimensions: list[str] = Field(default_factory=list)


class SemanticModel(BaseModel):
    id: str
    name: str
    source_table: str
    description: str = ""
    metrics: list[Metric] = Field(default_factory=list)
    dimensions: list[Dimension] = Field(default_factory=list)
    access_rules: list[AccessRule] = Field(default_factory=list)


# ── Query ─────────────────────────────────────────────────────────────────────

class FilterClause(BaseModel):
    dimension: str
    operator: str = "="     # =, !=, >, <, IN, LIKE
    value: Any


class QueryObject(BaseModel):
    model_id: str
    metrics: list[str]
    dimensions: list[str] = Field(default_factory=list)
    filters: list[FilterClause] = Field(default_factory=list)
    limit: int = Field(default=1000, ge=1, le=10_000)
    intent: str | None = None   # raw natural-language intent (for audit)


class QueryResult(BaseModel):
    sql: str
    model_id: str
    metrics: list[str]
    dimensions: list[str]
    row_count: int | None = None
    preview: list[dict[str, Any]] = Field(default_factory=list)
    generation_ms: float = 0.0
