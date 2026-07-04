"""
warden/api/policy.py
━━━━━━━━━━━━━━━━━━━━━
Per-tenant data classification policy REST API.

Endpoints
─────────
  GET    /policy/{tenant_id}                    — full policy
  PUT    /policy/{tenant_id}/settings           — update settings
  POST   /policy/{tenant_id}/rules              — add a custom rule
  DELETE /policy/{tenant_id}/rules/{rule_id}    — delete a custom rule
  POST   /policy/{tenant_id}/classify           — dry-run classify text

Extracted from ``warden/main.py`` (Phase 3). The DataPolicyEngine singleton is
published to ``warden.runtime`` in the app lifespan and resolved here.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.runtime import runtime as _runtime

router = APIRouter(tags=["data-policy"])


class _PolicySettingsRequest(BaseModel):
    default_class:      str  = Field("green", pattern="^(green|yellow|red)$")
    block_cloud_yellow: bool = True


class _AddRuleRequest(BaseModel):
    data_class:   str = Field(..., pattern="^(green|yellow|red)$")
    trigger_type: str = Field(..., pattern="^(pattern|keyword)$")
    value:        str = Field(..., min_length=1)
    description:  str = ""


class _ClassifyRequest(BaseModel):
    text:     str = Field(..., min_length=1)
    provider: str = "openai"


def _require_policy():
    policy = _runtime.get("policy")
    if policy is None:
        raise HTTPException(503, detail="DataPolicyEngine not initialized.")
    return policy


@router.get(
    "/policy/{tenant_id}",
    summary="Get full data classification policy for a tenant",
)
async def get_policy(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Returns: settings (block_cloud_yellow), custom rules (RED/YELLOW/GREEN),
    and built-in category descriptions.
    """
    policy = _require_policy()
    return policy.get_full_policy(tenant_id)


@router.put(
    "/policy/{tenant_id}/settings",
    summary="Update tenant policy settings",
)
async def update_policy_settings(
    tenant_id: str,
    body: _PolicySettingsRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Set block_cloud_yellow=true to restrict YELLOW data to local AI only.
    Set block_cloud_yellow=false to allow YELLOW data to cloud AI (with advisory).
    """
    policy = _require_policy()
    policy.update_settings(
        tenant_id          = tenant_id,
        default_class      = body.default_class,
        block_cloud_yellow = body.block_cloud_yellow,
    )
    return {"tenant_id": tenant_id, "settings": body.model_dump()}


@router.post(
    "/policy/{tenant_id}/rules",
    summary="Add a custom classification rule",
    status_code=201,
)
async def add_policy_rule(
    tenant_id: str,
    body: _AddRuleRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Add a RED/YELLOW/GREEN rule for this tenant.

    trigger_type='keyword' accepts comma-separated keywords and converts them to
    a regex pattern automatically (e.g. 'client list, crm, contact database').
    trigger_type='pattern' accepts a raw Python regex string.
    """
    policy = _require_policy()
    try:
        rule_id = policy.add_rule(
            tenant_id    = tenant_id,
            data_class   = body.data_class,
            trigger_type = body.trigger_type,
            value        = body.value,
            description  = body.description,
        )
    except (ValueError, Exception) as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    return {"rule_id": rule_id, "tenant_id": tenant_id, "data_class": body.data_class}


@router.delete(
    "/policy/{tenant_id}/rules/{rule_id}",
    summary="Delete a custom classification rule",
)
async def delete_policy_rule(
    tenant_id: str,
    rule_id:   str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Delete a custom rule by ID. Built-in category patterns cannot be deleted."""
    policy = _require_policy()
    found = policy.delete_rule(rule_id, tenant_id)
    if not found:
        raise HTTPException(404, detail=f"Rule {rule_id!r} not found for tenant {tenant_id!r}.")
    return {"deleted": rule_id}


@router.post(
    "/policy/{tenant_id}/classify",
    summary="Test-classify a piece of text against the tenant's data policy",
)
async def classify_text(
    tenant_id: str,
    body: _ClassifyRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Dry-run the data policy against arbitrary text.
    Does NOT block the request — used by MSP admins to test rules before applying them.
    """
    policy = _require_policy()
    decision = policy.classify(body.text, body.provider, tenant_id)
    return decision.as_dict()
