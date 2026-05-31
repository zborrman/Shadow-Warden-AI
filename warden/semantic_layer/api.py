"""
warden/semantic_layer/api.py
──────────────────────────────
Semantic Layer (Headless BI) — REST API.

Routes
──────
  GET  /semantic-layer/models              — list registered semantic models
  GET  /semantic-layer/models/{id}         — model detail (metrics + dimensions)
  POST /semantic-layer/models              — register a custom semantic model (Pro+)
  POST /semantic-layer/query               — generate SQL from QueryObject
  POST /semantic-layer/query/intent        — LLM translates NL intent → QueryObject → SQL
  GET  /semantic-layer/models/{id}/export/osi  — export model to OSI 1.0 format
  POST /semantic-layer/models/import/osi   — import model from OSI 1.0 format

Auth: standard X-API-Key.
Tier gate: Pro+ for /query/intent, /models (POST), OSI import.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException  # noqa: F401 (Depends used by AuthDep)
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.addons import require_addon_or_feature
from warden.semantic_layer.engine import get_engine
from warden.semantic_layer.models import QueryObject, QueryResult, SemanticModel

router = APIRouter(prefix="/semantic-layer", tags=["Semantic Layer"])

AuthDep = Depends(require_api_key)
_ProGate = require_addon_or_feature(feature="master_agent_enabled", addon_key="master_agent", min_tier="pro")


# ── Models registry ───────────────────────────────────────────────────────────

@router.get("/models", response_model=list[dict])
async def list_models(auth: AuthResult = AuthDep):
    engine = get_engine()
    return [
        {
            "id":          m.id,
            "name":        m.name,
            "source_table": m.source_table,
            "description": m.description,
            "metric_count":    len(m.metrics),
            "dimension_count": len(m.dimensions),
        }
        for m in engine.list_models()
    ]


@router.get("/models/{model_id}", response_model=dict)
async def get_model(model_id: str, auth: AuthResult = AuthDep):
    engine = get_engine()
    try:
        m = engine.get_model(model_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return m.model_dump()


@router.post("/models", response_model=dict, status_code=201, dependencies=[_ProGate])
async def register_model(
    model: SemanticModel,
    auth: AuthResult = AuthDep,
):
    engine = get_engine()
    engine.register_model(model)
    return {"registered": model.id}


# ── Query ─────────────────────────────────────────────────────────────────────

@router.post("/query", response_model=QueryResult)
async def query(body: QueryObject, auth: AuthResult = AuthDep):
    engine = get_engine()
    try:
        result = engine.generate(body, tenant_id=auth.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return result


# ── Natural-language intent → SQL ─────────────────────────────────────────────

class IntentRequest(BaseModel):
    model_id: str
    intent: str = Field(..., min_length=3, max_length=500)
    limit: int = Field(default=1000, ge=1, le=10_000)


@router.post("/query/intent", response_model=QueryResult, dependencies=[_ProGate])
async def query_intent(
    body: IntentRequest,
    auth: AuthResult = AuthDep,
):
    """Translate natural-language intent into a QueryObject via Claude, then generate SQL."""
    import os

    engine = get_engine()
    try:
        model = engine.get_model(body.model_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="ANTHROPIC_API_KEY not set — intent translation unavailable",
        )

    try:
        import anthropic
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="anthropic package not installed") from exc

    metric_names = [m.name for m in model.metrics]
    dim_names    = [d.name for d in model.dimensions]

    system = (
        "You are a Headless BI query builder. Given a user intent and a semantic model, "
        "output ONLY a JSON object matching this schema:\n"
        '{"metrics": [...], "dimensions": [...], "filters": [{"dimension": "...", "operator": "=", "value": "..."}]}\n'
        "Use only metric/dimension names listed. No explanation."
    )
    user = (
        f"Model: {model.name}\n"
        f"Available metrics: {metric_names}\n"
        f"Available dimensions: {dim_names}\n"
        f"Intent: {body.intent}"
    )

    t0 = time.perf_counter()
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=256,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    block = msg.content[0]
    raw = (block.text if hasattr(block, "text") else "").strip()

    import json
    import re as _re
    m = _re.search(r"\{.*\}", raw, _re.DOTALL)
    if not m:
        raise HTTPException(status_code=500, detail=f"LLM returned unparseable response: {raw[:200]}")
    parsed = json.loads(m.group())

    qobj = QueryObject(
        model_id=body.model_id,
        metrics=parsed.get("metrics", metric_names[:1]),
        dimensions=parsed.get("dimensions", []),
        filters=parsed.get("filters", []),
        limit=body.limit,
        intent=body.intent,
    )

    try:
        result = engine.generate(qobj, tenant_id=auth.tenant_id)
    except (KeyError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result.generation_ms = round((time.perf_counter() - t0) * 1000, 2)
    return result


# ── OSI export / import ───────────────────────────────────────────────────────

@router.get("/models/{model_id}/export/osi", response_model=dict)
async def export_osi(model_id: str, auth: AuthResult = AuthDep):
    """Export a registered model to OSI 1.0 interchange format (JSON)."""
    from warden.semantic_layer.engine import SemanticQueryEngine
    eng_direct = SemanticQueryEngine()
    base_engine = get_engine()
    try:
        model = base_engine.get_model(model_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return eng_direct.export_osi(model)


@router.post("/models/import/osi", response_model=dict, status_code=201,
             dependencies=[_ProGate])
async def import_osi(body: dict, auth: AuthResult = AuthDep):
    """Import a model from OSI 1.0 interchange format and register it."""
    from warden.semantic_layer.engine import SemanticQueryEngine
    eng_direct = SemanticQueryEngine()
    try:
        model = eng_direct.import_osi(body, tenant_id=auth.tenant_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    get_engine().register_model(model)
    return {"imported": model.id, "name": model.name, "metrics": len(model.metrics),
            "dimensions": len(model.dimensions)}
