"""
warden/semantic_layer/api.py  (FE-42)
FastAPI router for the Semantic Layer.
Prefix: /semantic-layer
Tier:   Pro+ (semantic_layer_enabled)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/semantic-layer", tags=["Semantic Layer"])
_Gate  = require_feature("semantic_layer_enabled")


# ── Request models ────────────────────────────────────────────────────────────

class ModelCreateRequest(BaseModel):
    name:         str
    description:  str = ""
    owner_tenant: str
    source_table: str
    metrics:    list[dict[str, Any]] = Field(default_factory=list)
    dimensions: list[dict[str, Any]] = Field(default_factory=list)
    joins:      list[dict[str, Any]] = Field(default_factory=list)


class QueryRequest(BaseModel):
    model_id:   str
    tenant_id:  str
    metrics:    list[str] = Field(default_factory=list)
    dimensions: list[str] = Field(default_factory=list)
    filters:    list[dict[str, Any]] = Field(default_factory=list)
    order_by:   str = ""
    limit:      int = 1000


class OSIImportRequest(BaseModel):
    tenant_id: str
    data:      dict[str, Any]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_model(body: ModelCreateRequest):
    from warden.semantic_layer.models import Dimension, Join, Metric, SemanticModel
    return SemanticModel(
        name=body.name,
        description=body.description,
        owner_tenant=body.owner_tenant,
        source_table=body.source_table,
        metrics=[Metric(**m) for m in body.metrics],
        dimensions=[Dimension(**d) for d in body.dimensions],
        joins=[Join(**j) for j in body.joins],
    )


def _parse_query(body: QueryRequest):
    from warden.semantic_layer.models import Filter, QueryObject
    return QueryObject(
        model_id=body.model_id,
        metrics=body.metrics,
        dimensions=body.dimensions,
        filters=[Filter(**f) for f in body.filters],
        order_by=body.order_by,
        limit=body.limit,
    )


# ── Model CRUD ────────────────────────────────────────────────────────────────

@router.post("/models", summary="Create semantic model", dependencies=[_Gate])
async def create_model(body: ModelCreateRequest) -> dict:
    from warden.semantic_layer.repository import create_model as _create
    from warden.semantic_layer.engine import SemanticQueryEngine
    model = _parse_model(body)
    ok, errors = SemanticQueryEngine().validate_model(model)
    if not ok:
        raise HTTPException(status_code=422, detail={"errors": errors})
    created = _create(model)
    return created.to_dict()


@router.get("/models", summary="List semantic models", dependencies=[_Gate])
async def list_models(tenant_id: str) -> dict:
    from warden.semantic_layer.repository import list_models as _list
    models = _list(tenant_id)
    return {"models": [m.to_dict() for m in models], "count": len(models)}


@router.get("/models/{model_id}", summary="Get semantic model", dependencies=[_Gate])
async def get_model(model_id: str, tenant_id: str) -> dict:
    from warden.semantic_layer.repository import get_model as _get
    model = _get(model_id, tenant_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return model.to_dict()


@router.put("/models/{model_id}", summary="Update semantic model", dependencies=[_Gate])
async def update_model(model_id: str, body: ModelCreateRequest) -> dict:
    from warden.semantic_layer.repository import get_model as _get, update_model as _upd
    from warden.semantic_layer.engine import SemanticQueryEngine
    existing = _get(model_id, body.owner_tenant)
    if not existing:
        raise HTTPException(status_code=404, detail="Model not found")
    model = _parse_model(body)
    model.id = model_id
    model.created_at = existing.created_at
    ok, errors = SemanticQueryEngine().validate_model(model)
    if not ok:
        raise HTTPException(status_code=422, detail={"errors": errors})
    updated = _upd(model)
    return updated.to_dict()


@router.delete("/models/{model_id}", summary="Delete semantic model", dependencies=[_Gate])
async def delete_model(model_id: str, tenant_id: str) -> dict:
    from warden.semantic_layer.repository import delete_model as _del
    ok = _del(model_id, tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Model not found")
    return {"deleted": True, "model_id": model_id}


# ── Query ─────────────────────────────────────────────────────────────────────

@router.post("/query", summary="Execute semantic query", dependencies=[_Gate])
async def run_query(body: QueryRequest) -> dict:
    from warden.semantic_layer.repository import get_model as _get
    from warden.semantic_layer.engine import SemanticQueryEngine
    model = _get(body.model_id, body.tenant_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    query  = _parse_query(body)
    result = SemanticQueryEngine().execute_query(query, model)
    return result.to_dict()


@router.post("/query/explain", summary="Explain query SQL without executing", dependencies=[_Gate])
async def explain_query(body: QueryRequest) -> dict:
    from warden.semantic_layer.repository import get_model as _get
    from warden.semantic_layer.engine import SemanticQueryEngine
    model = _get(body.model_id, body.tenant_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    query = _parse_query(body)
    try:
        sql = SemanticQueryEngine().compile_query(query, model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"sql": sql, "model_id": body.model_id}


# ── LLM context ───────────────────────────────────────────────────────────────

@router.get("/models/{model_id}/context", summary="Get LLM context for model", dependencies=[_Gate])
async def get_llm_context(model_id: str, tenant_id: str) -> dict:
    from warden.semantic_layer.repository import get_model as _get
    from warden.semantic_layer.engine import SemanticQueryEngine
    model = _get(model_id, tenant_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return SemanticQueryEngine().get_context_for_llm(model)


# ── OSI export / import ───────────────────────────────────────────────────────

@router.get("/models/{model_id}/export/osi", summary="Export model as OSI", dependencies=[_Gate])
async def export_osi(model_id: str, tenant_id: str) -> dict:
    from warden.semantic_layer.repository import get_model as _get
    from warden.semantic_layer.engine import SemanticQueryEngine
    model = _get(model_id, tenant_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return SemanticQueryEngine().export_osi(model)


@router.post("/models/import/osi", summary="Import model from OSI format", dependencies=[_Gate])
async def import_osi(body: OSIImportRequest) -> dict:
    from warden.semantic_layer.repository import create_model as _create
    from warden.semantic_layer.engine import SemanticQueryEngine
    engine = SemanticQueryEngine()
    model  = engine.import_osi(body.data, body.tenant_id)
    ok, errors = engine.validate_model(model)
    if not ok:
        raise HTTPException(status_code=422, detail={"errors": errors})
    created = _create(model)
    return created.to_dict()


# ── Analytics ─────────────────────────────────────────────────────────────────

@router.get("/usage", summary="Query usage statistics", dependencies=[_Gate])
async def usage_stats(tenant_id: str, limit: int = 20) -> dict:
    from warden.semantic_layer.repository import query_usage_stats
    stats = query_usage_stats(tenant_id, limit=limit)
    return {"stats": stats, "count": len(stats)}
