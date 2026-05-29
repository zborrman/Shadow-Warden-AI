"""
warden/semantic_layer/engine.py  (FE-42)
SemanticQueryEngine — compiles QueryObject → SQL → executes against DB.

Key design: LLM is never involved in SQL generation.  The engine is the
single source of truth for metric calculation.  LLM only produces the
QueryObject (metric/dimension selection) — the engine does the SQL.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import time
import uuid
from typing import Any

from warden.semantic_layer.models import (
    Filter,
    QueryObject,
    QueryResult,
    SemanticModel,
)

log = logging.getLogger("warden.semantic_layer.engine")

_ANALYTICS_DB = os.getenv("ANALYTICS_DB_PATH", "")
_SEMANTIC_DB  = os.getenv("SEMANTIC_DB_PATH", "/tmp/warden_semantic.db")

_OP_MAP: dict[str, str] = {
    "eq":  "=",  "neq": "!=", "gt":  ">",  "lt":  "<",
    "gte": ">=", "lte": "<=", "like": "LIKE",
}


def _safe_identifier(name: str) -> str:
    """Reject identifiers with SQL-injection characters."""
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_\(\)\*\,\s\.]*$', name):
        raise ValueError(f"Unsafe identifier: {name!r}")
    return name


class SemanticQueryEngine:

    # ── SQL compilation ───────────────────────────────────────────────────────

    def compile_query(self, query: QueryObject, model: SemanticModel) -> str:
        # SELECT clause
        select_parts: list[str] = []

        for dim_name in query.dimensions:
            dim = next((d for d in model.dimensions if d.name == dim_name), None)
            if not dim:
                raise ValueError(f"Unknown dimension: {dim_name!r}")
            select_parts.append(f"{_safe_identifier(dim.sql_field)} AS {dim_name}")

        for metric_name in query.metrics:
            metric = next((m for m in model.metrics if m.name == metric_name), None)
            if not metric:
                raise ValueError(f"Unknown metric: {metric_name!r}")
            select_parts.append(f"{metric.sql_expression} AS {metric_name}")

        if not select_parts:
            select_parts = ["*"]

        sql = f"SELECT {', '.join(select_parts)}\nFROM {_safe_identifier(model.source_table)}"

        # JOINs
        for join in model.joins:
            sql += f"\n{join.join_type} JOIN {_safe_identifier(join.table)} ON {join.on}"

        # WHERE
        where_parts = self._compile_filters(query.filters, model)
        if where_parts:
            sql += f"\nWHERE {' AND '.join(where_parts)}"

        # GROUP BY (only when mixing aggregates + dimensions)
        if query.dimensions and query.metrics:
            group_fields = []
            for dim_name in query.dimensions:
                dim = next((d for d in model.dimensions if d.name == dim_name), None)
                if dim:
                    group_fields.append(dim.sql_field)
            if group_fields:
                sql += f"\nGROUP BY {', '.join(group_fields)}"

        # ORDER BY
        if query.order_by:
            sql += f"\nORDER BY {_safe_identifier(query.order_by)}"

        # LIMIT
        sql += f"\nLIMIT {min(max(1, query.limit), 10_000)}"

        return sql

    def _compile_filters(self, filters: list[Filter], model: SemanticModel) -> list[str]:
        parts: list[str] = []
        for f in filters:
            dim = next((d for d in model.dimensions if d.name == f.dimension), None)
            if not dim:
                log.warning("Filter references unknown dimension %r — skipped", f.dimension)
                continue
            field = _safe_identifier(dim.sql_field)
            op    = _OP_MAP.get(f.operator, "=")
            if f.operator == "in":
                if isinstance(f.value, list):
                    placeholders = ",".join(f"'{v}'" for v in f.value)
                    parts.append(f"{field} IN ({placeholders})")
                else:
                    parts.append(f"{field} = '{f.value}'")
            elif dim.type == "string":
                parts.append(f"{field} {op} '{f.value}'")
            else:
                parts.append(f"{field} {op} {f.value}")
        return parts

    # ── Query execution ───────────────────────────────────────────────────────

    def execute_query(self, query: QueryObject, model: SemanticModel) -> QueryResult:
        sql = self.compile_query(query, model)
        start = time.perf_counter()
        rows: list[dict[str, Any]] = []
        columns: list[str] = []

        try:
            db_path = model.source_table  # if model has explicit db_path, use it
            # Fall back to SQLite semantic DB for demo/test purposes
            db = _ANALYTICS_DB or _SEMANTIC_DB
            con = sqlite3.connect(db, check_same_thread=False)
            con.row_factory = sqlite3.Row
            cur = con.execute(sql)
            columns = [d[0] for d in cur.description] if cur.description else []
            rows = [dict(r) for r in cur.fetchall()]
            con.close()
        except Exception as exc:
            log.warning("SemanticQueryEngine.execute_query failed: %s", exc)
            rows = []
            columns = []

        exec_ms = (time.perf_counter() - start) * 1000

        result = QueryResult(
            query_id=str(uuid.uuid4()),
            model_id=query.model_id,
            sql=sql,
            rows=rows,
            row_count=len(rows),
            execution_ms=round(exec_ms, 2),
            columns=columns,
        )

        # Log async (fire and forget)
        try:
            from warden.semantic_layer.repository import log_query
            log_query(
                tenant_id=model.owner_tenant,
                model_id=query.model_id,
                metrics=query.metrics,
                dimensions=query.dimensions,
                sql_text=sql,
                exec_ms=exec_ms,
                row_count=len(rows),
            )
        except Exception:
            pass

        return result

    # ── Validation ────────────────────────────────────────────────────────────

    def validate_model(self, model: SemanticModel) -> tuple[bool, list[str]]:
        errors: list[str] = []
        if not model.name:
            errors.append("Model name is required")
        if not model.source_table:
            errors.append("source_table is required")
        for m in model.metrics:
            if not m.sql_expression:
                errors.append(f"Metric {m.name!r} has empty sql_expression")
        for d in model.dimensions:
            if not d.sql_field:
                errors.append(f"Dimension {d.name!r} has empty sql_field")
        return len(errors) == 0, errors

    # ── LLM context ──────────────────────────────────────────────────────────

    def get_context_for_llm(self, model: SemanticModel) -> dict[str, Any]:
        """
        Returns a compact JSON description of the model for SOVA to
        convert natural language into a QueryObject.
        LLM sees metric/dimension names + descriptions — NOT raw SQL.
        """
        return {
            "model_id":   model.id,
            "model_name": model.name,
            "description": model.description,
            "metrics": [
                {"name": m.name, "description": m.description, "format": m.format}
                for m in model.metrics
            ],
            "dimensions": [
                {"name": d.name, "type": d.type, "description": d.description}
                for d in model.dimensions
            ],
            "example_query": {
                "model_id": model.id,
                "metrics": [model.metrics[0].name] if model.metrics else [],
                "dimensions": [model.dimensions[0].name] if model.dimensions else [],
                "filters": [],
                "limit": 100,
            },
        }

    # ── OSI export / import ───────────────────────────────────────────────────

    def export_osi(self, model: SemanticModel) -> dict[str, Any]:
        return {
            "osi_version": "1.0",
            "schema":      "semantic_model",
            "id":          model.id,
            "name":        model.name,
            "description": model.description,
            "source":      {"table": model.source_table},
            "metrics": [
                {"name": m.name, "expression": m.sql_expression,
                 "description": m.description, "format": m.format}
                for m in model.metrics
            ],
            "dimensions": [
                {"name": d.name, "field": d.sql_field, "type": d.type,
                 "description": d.description}
                for d in model.dimensions
            ],
            "joins": [
                {"table": j.table, "on": j.on, "type": j.join_type}
                for j in model.joins
            ],
        }

    def import_osi(self, data: dict[str, Any], tenant_id: str) -> SemanticModel:
        from warden.semantic_layer.models import Dimension, Join, Metric
        return SemanticModel(
            name=data["name"],
            description=data.get("description", ""),
            owner_tenant=tenant_id,
            source_table=data.get("source", {}).get("table", ""),
            metrics=[
                Metric(name=m["name"], sql_expression=m["expression"],
                       description=m.get("description", ""), format=m.get("format", "number"))
                for m in data.get("metrics", [])
            ],
            dimensions=[
                Dimension(name=d["name"], sql_field=d["field"], type=d.get("type", "string"),
                          description=d.get("description", ""))
                for d in data.get("dimensions", [])
            ],
            joins=[
                Join(table=j["table"], on=j["on"], join_type=j.get("type", "LEFT"))
                for j in data.get("joins", [])
            ],
        )
