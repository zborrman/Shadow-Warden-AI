"""warden/api/usage_budgets.py  (ENT-04) — /billing/usage-budgets/* REST endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/billing/usage-budgets", tags=["AI Usage Budgets"])


class BudgetIn(BaseModel):
    department:    str
    monthly_limit: int
    warn_pct:      int  = 80
    block_at_pct:  int  = 100
    notify_slack:  str  = ""
    auto_approve:  bool = False


@router.post("/{tenant_id}", status_code=201)
async def create_budget(tenant_id: str, body: BudgetIn):
    from warden.billing.usage_budgets import set_budget  # noqa: PLC0415
    return set_budget(
        tenant_id=tenant_id,
        department=body.department,
        monthly_limit=body.monthly_limit,
        warn_pct=body.warn_pct,
        block_at_pct=body.block_at_pct,
        notify_slack=body.notify_slack,
        auto_approve=body.auto_approve,
    )


@router.get("/{tenant_id}")
async def list_budgets(tenant_id: str):
    from warden.billing.usage_budgets import list_budgets  # noqa: PLC0415
    return list_budgets(tenant_id)


@router.get("/{tenant_id}/{department}")
async def get_budget(tenant_id: str, department: str):
    from warden.billing.usage_budgets import get_budget, get_counter  # noqa: PLC0415
    budget = get_budget(tenant_id, department)
    if not budget:
        raise HTTPException(status_code=404, detail="Budget not configured for this department")
    used = get_counter(tenant_id, department)
    limit = budget.get("monthly_limit", 0)
    pct = used / limit * 100 if limit else 0.0
    return {**budget, "used": used, "pct_used": round(pct, 1)}


@router.get("/{tenant_id}/{department}/check")
async def check_budget(tenant_id: str, department: str):
    from warden.billing.usage_budgets import check_budget_gate  # noqa: PLC0415
    return check_budget_gate(tenant_id, department)


@router.delete("/{tenant_id}/{department}")
async def delete_budget(tenant_id: str, department: str):
    import os  # noqa: PLC0415

    import redis as rl  # noqa: PLC0415, F401
    try:
        import redis  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        r = redis.Redis.from_url(url, decode_responses=True)
        r.delete(f"usage_budget:{tenant_id}:{department}")
    except Exception:
        pass
    return {"deleted": f"{tenant_id}:{department}"}
