"""
warden/api/budget.py  (BL-24)
──────────────────────────────
FastAPI router for AI Budget Dashboard.

Prefix: /financial/budget
Tier:   Community Business+ (budget_dashboard_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/financial/budget", tags=["Budget Dashboard"])
_Gate  = require_feature("budget_dashboard_enabled")


class BudgetCapRequest(BaseModel):
    tenant_id:   str
    cap_usd:     float = Field(..., gt=0)
    department:  str   = "default"
    period_type: str   = "monthly"
    alert_pct:   float = Field(0.80, ge=0.0, le=1.0)


class ApprovalRequest(BaseModel):
    tenant_id:    str
    requested_by: str
    department:   str
    amount_usd:   float = Field(..., gt=0)
    reason:       str   = ""


class ApprovalResolveRequest(BaseModel):
    reviewed_by: str
    approve:     bool


@router.get("/status", summary="Real-time budget status for all departments", dependencies=[_Gate])
async def get_status(tenant_id: str) -> dict:
    from warden.financial.budget import get_realtime_status
    return get_realtime_status(tenant_id)


@router.post("/caps", summary="Set a budget cap for a department", dependencies=[_Gate])
async def set_cap(body: BudgetCapRequest) -> dict:
    from warden.financial.budget import set_budget_cap
    cap_id = set_budget_cap(
        tenant_id=body.tenant_id,
        cap_usd=body.cap_usd,
        department=body.department,
        period_type=body.period_type,
        alert_pct=body.alert_pct,
    )
    return {"cap_id": cap_id, "department": body.department, "cap_usd": body.cap_usd}


@router.get("/approvals", summary="List budget approval requests", dependencies=[_Gate])
async def list_approvals(tenant_id: str, status: str | None = None) -> dict:
    from warden.financial.budget import list_approvals as _list
    items = _list(tenant_id, status=status)
    return {"approvals": items, "count": len(items)}


@router.post("/approvals", summary="Request budget approval", dependencies=[_Gate])
async def request_approval(body: ApprovalRequest) -> dict:
    from warden.financial.budget import request_approval as _req
    approval_id = _req(
        tenant_id=body.tenant_id,
        requested_by=body.requested_by,
        department=body.department,
        amount_usd=body.amount_usd,
        reason=body.reason,
    )
    return {"approval_id": approval_id, "status": "pending"}


@router.put("/approvals/{approval_id}", summary="Approve or reject a budget request", dependencies=[_Gate])
async def resolve_approval(approval_id: str, body: ApprovalResolveRequest) -> dict:
    from warden.financial.budget import resolve_approval as _res
    ok = _res(approval_id, body.reviewed_by, body.approve)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id!r} not found or already resolved")
    return {"resolved": True, "approval_id": approval_id, "approved": body.approve}
