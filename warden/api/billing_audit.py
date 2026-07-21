"""
warden/api/billing_audit.py — Zero-Trust Billing Audit REST API.

Prefix: /billing/audit
Tier:   Pro+ (billing_audit_enabled)

Endpoints:
  GET    /billing/audit/chain/{tenant_id}        Paginated chain entries (newest first)
  GET    /billing/audit/verify/{tenant_id}       Integrity verification (re-hash full chain)
  GET    /billing/audit/summary/{tenant_id}      Spend totals + tip hash
  GET    /billing/audit/export/{tenant_id}       JSONL export (SIEM/auditor)
  GET    /billing/audit/evm/{tenant_id}          EVM anchor history
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from warden.billing.feature_gate import require_feature
from warden.config import data_path

router = APIRouter(prefix="/billing/audit", tags=["billing-audit"])
_Gate = require_feature("billing_audit_enabled")

_DB_PATH = data_path("warden_billing_audit.db", "BILLING_AUDIT_DB_PATH")


@router.get("/chain/{tenant_id}", dependencies=[_Gate])
async def get_chain(
    tenant_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """Return paginated audit chain entries (newest first)."""
    from warden.billing.audit_chain import get_chain as _get  # noqa: PLC0415
    entries = _get(tenant_id, limit=limit, offset=offset, db_path=_DB_PATH)
    return {"tenant_id": tenant_id, "entries": entries, "count": len(entries)}


@router.get("/verify/{tenant_id}", dependencies=[_Gate])
async def verify_chain(tenant_id: str) -> dict:
    """
    Re-hash the full chain and confirm integrity.

    Returns {valid, entries, tip_hash, first_broken_seq}.
    HTTP 409 if chain is tampered.
    """
    from warden.billing.audit_chain import verify_chain as _verify  # noqa: PLC0415
    result = _verify(tenant_id, db_path=_DB_PATH)
    if not result.get("valid"):
        raise HTTPException(
            409,
            detail={
                "message": "Billing audit chain integrity violation",
                **result,
            },
        )
    return result


@router.get("/summary/{tenant_id}", dependencies=[_Gate])
async def get_summary(tenant_id: str) -> dict:
    """Return total spend, entry count, and tip hash."""
    from warden.billing.audit_chain import get_summary as _summary  # noqa: PLC0415
    return _summary(tenant_id, db_path=_DB_PATH)


@router.get("/export/{tenant_id}", dependencies=[_Gate])
async def export_chain(tenant_id: str) -> PlainTextResponse:
    """
    Export full audit chain as JSONL (one entry per line).
    Content-Type: application/x-ndjson — import directly into Splunk/Elastic.
    """
    from warden.billing.audit_chain import export_jsonl  # noqa: PLC0415
    jsonl = export_jsonl(tenant_id, db_path=_DB_PATH)
    return PlainTextResponse(
        content=jsonl,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="billing_audit_{tenant_id}.jsonl"'},
    )


@router.get("/evm/{tenant_id}", dependencies=[_Gate])
async def get_evm_anchors(tenant_id: str) -> dict:
    """Return EVM attestation anchor history for the tenant."""
    from contextlib import closing  # noqa: PLC0415

    from warden.db.connect import open_db_readonly  # noqa: PLC0415
    try:
        with closing(open_db_readonly(_DB_PATH)) as con:
            rows = con.execute(
                "SELECT * FROM billing_audit_evm_anchors WHERE tenant_id=? ORDER BY tip_seq DESC LIMIT 100",
                (tenant_id,),
            ).fetchall()
        anchors = [dict(r) for r in rows]
    except Exception:
        anchors = []
    return {
        "tenant_id": tenant_id,
        "anchors":   anchors,
        "count":     len(anchors),
        "evm_enabled": os.getenv("BILLING_AUDIT_EVM_ATTESTATION", "false").lower() == "true",
        "chain_id":  84532,
        "network":   "Base Sepolia",
    }
