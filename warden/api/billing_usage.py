"""
warden/api/billing_usage.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Per-tenant usage, cost and quota REST API (BillingStore-backed).

Endpoints
─────────
  GET  /billing/{tenant_id}         — aggregated usage + cost
  GET  /billing/{tenant_id}/daily   — day-by-day breakdown
  POST /billing/{tenant_id}/quota   — set / remove monthly USD cap

Extracted from ``warden/main.py`` (Phase 3). The BillingStore singleton is
published to ``warden.runtime`` in the app lifespan and resolved here.

Distinct from ``warden/billing/router.py`` (tier catalog + add-on checkout);
this router only serves the tenant usage/quota endpoints that were inline in
main.py.
"""
from __future__ import annotations

import json
import logging
from contextlib import suppress

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from warden.auth_guard import require_api_key
from warden.runtime import runtime as _runtime

log = logging.getLogger("warden.api.billing_usage")

router = APIRouter(prefix="/billing", tags=["billing"])


class _QuotaRequest(BaseModel):
    quota_usd: float   # monthly USD cap; set to 0 to remove cap


def _require_billing():
    billing = _runtime.get("billing")
    if billing is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing store not available.",
        )
    return billing


@router.get(
    "/{tenant_id}",
    summary="Aggregated usage and cost for a tenant",
    dependencies=[Depends(require_api_key)],
)
async def get_billing(
    tenant_id: str,
    from_date: str | None = None,
    to_date:   str | None = None,
):
    """
    Return aggregated request counts and USD cost for *tenant_id* over the
    given date range (``from_date`` / ``to_date`` inclusive, format YYYY-MM-DD).
    Includes current-month cost and quota_remaining when a quota is set.
    """
    billing = _require_billing()
    return billing.get_usage(tenant_id, from_date=from_date, to_date=to_date)


@router.get(
    "/{tenant_id}/daily",
    summary="Day-by-day billing breakdown for a tenant",
    dependencies=[Depends(require_api_key)],
)
async def get_billing_daily(
    tenant_id: str,
    from_date: str | None = None,
    to_date:   str | None = None,
    limit:     int        = 90,
):
    billing = _require_billing()
    return {
        "tenant_id": tenant_id,
        "rows": billing.get_daily_breakdown(tenant_id, from_date, to_date, limit),
    }


@router.post(
    "/{tenant_id}/quota",
    summary="Set or update the monthly USD cost cap for a tenant",
    dependencies=[Depends(require_api_key)],
)
async def set_billing_quota(tenant_id: str, body: _QuotaRequest):
    """
    Set the monthly cost cap for *tenant_id*.  All subsequent filter requests
    from this tenant will receive HTTP 402 once the cap is reached.

    Set ``quota_usd=0`` to remove the cap (unlimited).
    """
    billing = _require_billing()
    if body.quota_usd <= 0:
        # Treat 0 / negative as "remove quota" — delete the row to restore unlimited.
        with suppress(Exception):
            billing._conn.execute(
                "DELETE FROM tenant_quotas WHERE tenant_id=?", (tenant_id,)
            )
            billing._conn.commit()
        log.info(json.dumps({"event": "quota_removed", "tenant_id": tenant_id}))
        return {"tenant_id": tenant_id, "quota_usd": None, "message": "Quota removed (unlimited)."}

    billing.set_quota(tenant_id, body.quota_usd)
    log.info(
        json.dumps({
            "event":     "quota_set",
            "tenant_id": tenant_id,
            "quota_usd": body.quota_usd,
        })
    )
    return {
        "tenant_id": tenant_id,
        "quota_usd": body.quota_usd,
        "message":   f"Monthly quota set to ${body.quota_usd:.4f} for tenant {tenant_id!r}.",
    }
