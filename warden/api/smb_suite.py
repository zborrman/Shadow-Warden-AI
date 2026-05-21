"""
warden/api/smb_suite.py  (IN-25)
──────────────────────────────────────
FastAPI router for SMB AI Governance Suite.

Prefix: /smb-suite
Tier:   Community Business+ (smb_suite_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/smb-suite", tags=["SMB Governance Suite"])
_Gate  = require_feature("smb_suite_enabled")


class VendorConfig(BaseModel):
    display_name:  str
    website:       str = ""
    provider_type: str = "LLM"


class ProvisionRequest(BaseModel):
    tenant_id:          str
    community_id:       str
    monthly_budget_usd: float = Field(0.0, ge=0.0)
    vendors:            list[VendorConfig] = Field(default_factory=list)


@router.post("/provision", summary="Provision all 7 SMB governance modules", dependencies=[_Gate])
async def provision(body: ProvisionRequest) -> dict:
    from warden.integrations.smb_suite import provision_suite
    cfg = {
        "monthly_budget_usd": body.monthly_budget_usd,
        "vendors": [v.model_dump() for v in body.vendors],
    }
    result = provision_suite(
        tenant_id=body.tenant_id,
        community_id=body.community_id,
        config=cfg,
    )
    return result.to_dict()


@router.get("/status/{tenant_id}", summary="Provisioning result and current health", dependencies=[_Gate])
async def get_status(tenant_id: str, community_id: str = "") -> dict:
    from warden.integrations.smb_suite import get_suite_health
    return get_suite_health(tenant_id, community_id=community_id)


@router.get("/health", summary="All 7 modules health check", dependencies=[_Gate])
async def health_check(tenant_id: str, community_id: str = "") -> dict:
    from warden.integrations.smb_suite import get_suite_health
    return get_suite_health(tenant_id, community_id=community_id)
