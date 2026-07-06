"""
warden/api/ers.py
━━━━━━━━━━━━━━━━━━
Entity Risk Score (ERS) / Shadow Ban admin REST API.

Endpoints
─────────
  GET  /ers/score  — ERS score for the calling entity (tenant + IP)
  POST /ers/reset  — clear ERS counters for a tenant+IP (false-positive clearance)

Extracted from ``warden/main.py`` (Phase 3). ERS is a stateless module
(``warden.entity_risk``) backed by Redis, so it is imported directly rather than
resolved via the runtime container.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from warden import entity_risk as _ers
from warden.auth_guard import AuthResult, require_api_key

router = APIRouter(prefix="/ers", tags=["security"])


def _ers_dominant_flag(counts: dict, total: int) -> str:
    """Return the ERS event type with the highest weighted contribution to the score."""
    if total == 0:
        return ""
    best = max(
        _ers._WEIGHTS,
        key=lambda e: _ers._WEIGHTS[e] * counts.get(e, 0) / total,
    )
    return best if counts.get(best, 0) > 0 else ""


@router.get(
    "/score",
    summary="Get ERS score for the current caller (tenant + IP)",
    dependencies=[Depends(require_api_key)],
)
async def ers_score_self(request: Request, auth: AuthResult = Depends(require_api_key)):
    """Return the ERS score for the caller's own entity key."""
    client_ip  = request.client.host if request.client else ""
    entity_key = _ers.make_entity_key(auth.tenant_id, client_ip)
    result    = _ers.score(entity_key)
    last_flag = _ers_dominant_flag(result.counts, result.total_1h)
    return {
        "entity_key": entity_key,
        "score":      result.score,
        "level":      result.level,
        "shadow_ban": result.shadow_ban,
        "last_flag":  last_flag,
        "total_1h":   result.total_1h,
        "counts":     result.counts,
        "window_secs": _ers.WINDOW_SECS,
    }


@router.post(
    "/reset",
    summary="Reset ERS score for a given tenant+IP (admin — false-positive clearance)",
    dependencies=[Depends(require_api_key)],
)
async def ers_reset(tenant_id: str, ip: str):
    """Clear all ERS signal counters for the specified entity."""
    entity_key = _ers.make_entity_key(tenant_id, ip)
    _ers.reset(entity_key)
    return {"entity_key": entity_key, "message": "ERS counters reset."}
