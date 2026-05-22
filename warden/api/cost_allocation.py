"""
warden/api/cost_allocation.py  (BL-23)
──────────────────────────────────────────
FastAPI router for AI Cost Allocation.

Prefix: /financial/allocation
Tier:   Community Business+ (cost_allocation_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/financial/allocation", tags=["Cost Allocation"])
_Gate  = require_feature("cost_allocation_enabled")


class CostRecordRequest(BaseModel):
    tenant_id:    str
    amount_usd:   float = Field(..., ge=0.0)
    vendor_id:    str   = ""
    department:   str   = "default"
    project:      str   = ""
    cost_type:    str   = "api_usage"
    currency:     str   = "USD"
    notes:        str   = ""
    period_month: str | None = None


@router.post("", summary="Record an AI cost entry", dependencies=[_Gate])
async def record_cost(body: CostRecordRequest) -> dict:
    from warden.financial.cost_allocation import record_cost as _rec
    alloc_id = _rec(
        tenant_id=body.tenant_id,
        amount_usd=body.amount_usd,
        vendor_id=body.vendor_id,
        department=body.department,
        project=body.project,
        cost_type=body.cost_type,
        currency=body.currency,
        notes=body.notes,
        period_month=body.period_month,
    )
    return {"alloc_id": alloc_id, "recorded": True}


@router.get("/summary", summary="Monthly cost summary for a tenant", dependencies=[_Gate])
async def get_summary(tenant_id: str, period_month: str | None = None) -> dict:
    from warden.financial.cost_allocation import get_monthly_summary
    return get_monthly_summary(tenant_id, period_month)


@router.get("/departments", summary="Per-department breakdown over N months", dependencies=[_Gate])
async def get_departments(tenant_id: str, months: int = 3) -> dict:
    from warden.financial.cost_allocation import get_department_breakdown
    return {"breakdowns": get_department_breakdown(tenant_id, months)}


@router.get("/vendors/{vendor_id}", summary="Vendor spend over N months", dependencies=[_Gate])
async def get_vendor_spend(vendor_id: str, tenant_id: str, months: int = 3) -> dict:
    from warden.financial.cost_allocation import get_vendor_spend as _spend
    return _spend(tenant_id, vendor_id, months)


@router.post("/import-logs", summary="Import cost entries from logs.json", dependencies=[_Gate])
async def import_logs(tenant_id: str, logs_path: str | None = None) -> dict:
    from warden.financial.cost_allocation import import_from_logs
    count = import_from_logs(tenant_id, logs_path)
    return {"imported": count}
