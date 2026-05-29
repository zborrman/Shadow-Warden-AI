"""
warden/semantic_layer/models.py  (FE-42)
Pydantic models for the Semantic Layer metric contract.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Metric(BaseModel):
    name: str
    sql_expression: str                      # e.g. "SUM(amount)", "COUNT(*)"
    description: str = ""
    format: str = "number"                   # number | currency | percent | duration


class Dimension(BaseModel):
    name: str
    sql_field: str                           # e.g. "tenant_id", "DATE(created_at)"
    type: Literal["string", "time", "numeric"] = "string"
    description: str = ""


class Join(BaseModel):
    table: str
    on: str                                  # e.g. "events.tenant_id = tenants.id"
    join_type: Literal["INNER", "LEFT", "RIGHT"] = "LEFT"


class SemanticModel(BaseModel):
    id: str = ""
    name: str
    description: str = ""
    owner_tenant: str
    source_table: str                        # primary FROM table
    metrics: list[Metric] = Field(default_factory=list)
    dimensions: list[Dimension] = Field(default_factory=list)
    joins: list[Join] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    def metric_names(self) -> list[str]:
        return [m.name for m in self.metrics]

    def dimension_names(self) -> list[str]:
        return [d.name for d in self.dimensions]


class Filter(BaseModel):
    dimension: str
    operator: Literal["eq", "neq", "gt", "lt", "gte", "lte", "in", "like"] = "eq"
    value: Any


class QueryObject(BaseModel):
    model_id: str
    metrics: list[str] = Field(default_factory=list)
    dimensions: list[str] = Field(default_factory=list)
    filters: list[Filter] = Field(default_factory=list)
    order_by: str = ""
    limit: int = 1000


class QueryResult(BaseModel):
    query_id: str = ""
    model_id: str
    sql: str
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
    execution_ms: float = 0.0
    columns: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()
