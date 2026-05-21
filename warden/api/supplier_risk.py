"""
warden/api/supplier_risk.py  (CM-36)
──────────────────────────────────────
FastAPI router for Supplier AI Risk Assessment.

Prefix: /supplier-risk
Tier:   Community Business+ (supplier_risk_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/supplier-risk", tags=["Supplier Risk Assessment"])
_Gate  = require_feature("supplier_risk_enabled")


class AssessRequest(BaseModel):
    community_id: str
    vendor_id:    str
    tenant_id:    str = ""
    notes:        str = ""
    context:      dict = Field(default_factory=dict)


@router.post("/assess", summary="Run a supplier AI risk assessment", dependencies=[_Gate])
async def assess(body: AssessRequest) -> dict:
    from warden.communities.supplier_risk import assess_supplier
    return assess_supplier(
        community_id=body.community_id,
        vendor_id=body.vendor_id,
        tenant_id=body.tenant_id,
        context=body.context,
        notes=body.notes,
    )


@router.get("/assessments", summary="List assessments for a community", dependencies=[_Gate])
async def list_assessments(community_id: str, risk_label: str | None = None) -> dict:
    from warden.communities.supplier_risk import list_assessments as _list
    items = _list(community_id, risk_label=risk_label)
    return {"assessments": items, "count": len(items)}


@router.get("/report/{community_id}", summary="Community supplier risk report", dependencies=[_Gate])
async def get_report(community_id: str) -> dict:
    from warden.communities.supplier_risk import get_community_supplier_report
    return get_community_supplier_report(community_id)
