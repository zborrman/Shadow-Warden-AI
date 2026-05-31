"""
warden/semantic_layer/catalog.py
──────────────────────────────────
Self-Service Model Catalog — tenants register their own SemanticModels
and they are hot-loaded into the running SemanticEngine.

Storage: SQLite via repository.py (SEMANTIC_DB_PATH).
At startup: pre-loads all persisted models back into the engine singleton.

Usage:
    from warden.semantic_layer.catalog import register_tenant_model, list_tenant_models

FastAPI dependency:
    Depends(require_api_key) + Pro+ gate on write endpoints.
"""
from __future__ import annotations

import logging
from typing import Any

from warden.semantic_layer.engine import get_engine
from warden.semantic_layer.models import SemanticModel
from warden.semantic_layer.repository import (
    create_model,
    delete_model,
    get_model,
    list_models,
    update_model,
)

log = logging.getLogger("warden.semantic_layer.catalog")


def bootstrap_tenant_models() -> int:
    """
    Load all persisted tenant models back into the engine on startup.
    Called once from FastAPI lifespan. Returns count loaded.
    """
    engine = get_engine()
    loaded = 0
    try:
        # list_models without tenant filters loads everything
        all_models = list_models(tenant_id="")  # empty = all tenants
        for m in all_models:
            if m.id not in {x.id for x in engine.list_models()}:
                engine.register_model(m)
                loaded += 1
        if loaded:
            log.info("Semantic Layer catalog: loaded %d tenant models", loaded)
    except Exception as exc:
        log.warning("Semantic Layer catalog bootstrap failed: %s", exc)
    return loaded


def register_tenant_model(model: SemanticModel, tenant_id: str) -> SemanticModel:
    """
    Persist + hot-load a new tenant model.
    Raises ValueError if model_id already exists for this tenant.
    """
    model.owner_tenant = tenant_id
    saved = create_model(model)
    get_engine().register_model(saved)
    log.info("Semantic Layer: tenant %s registered model %s", tenant_id, saved.id)
    return saved


def update_tenant_model(model: SemanticModel, tenant_id: str) -> SemanticModel:
    """Update a tenant model (must be owned by tenant_id)."""
    existing = get_model(model.id, tenant_id)
    if existing is None:
        raise KeyError(f"Model {model.id!r} not found for tenant {tenant_id!r}")
    model.owner_tenant = tenant_id
    saved = update_model(model)
    get_engine().register_model(saved)
    return saved


def delete_tenant_model(model_id: str, tenant_id: str) -> bool:
    """Remove a tenant model. Returns False if not found."""
    ok = delete_model(model_id, tenant_id)
    if ok:
        # Remove from in-memory engine registry
        engine = get_engine()
        engine._models.pop(model_id, None)  # noqa: SLF001 — internal access intentional
    return ok


def list_tenant_models(tenant_id: str) -> list[dict[str, Any]]:
    """List models owned by tenant_id."""
    models = list_models(tenant_id)
    return [
        {
            "id":            m.id,
            "name":          m.name,
            "source_table":  m.source_table,
            "description":   m.description,
            "metric_count":  len(m.metrics),
            "dimension_count": len(m.dimensions),
            "created_at":    m.created_at,
            "updated_at":    m.updated_at,
        }
        for m in models
    ]


def get_tenant_model(model_id: str, tenant_id: str) -> SemanticModel | None:
    return get_model(model_id, tenant_id)
