"""
warden/api/vendor_gov.py  (BL-22)
──────────────────────────────────
FastAPI router for AI Vendor Governance Register.

Prefix: /vendor-gov
Tier:   Individual+ (vendor_governance_enabled)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router  = APIRouter(prefix="/vendor-gov", tags=["Vendor Governance"])
_Gate   = require_feature("vendor_governance_enabled")


# ── Request / Response models ─────────────────────────────────────────────────

class VendorCreateRequest(BaseModel):
    tenant_id:     str
    display_name:  str = Field(..., min_length=1, max_length=200)
    website:       str = ""
    provider_type: str = "LLM"
    risk_tier:     str = "MEDIUM"
    contact_email: str = ""
    tags:          dict[str, Any] = Field(default_factory=dict)


class VendorUpdateRequest(BaseModel):
    display_name:  str | None = None
    website:       str | None = None
    risk_tier:     str | None = None
    status:        str | None = None
    contact_email: str | None = None
    tags:          dict[str, Any] | None = None


class DPACreateRequest(BaseModel):
    tenant_id:  str
    dpa_type:   str  = "GDPR_ART28"
    signed_at:  str | None = None
    expires_at: str | None = None
    doc_ref:    str  = ""
    notes:      str  = ""


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/vendors", summary="Register an AI vendor", dependencies=[_Gate])
async def create_vendor(body: VendorCreateRequest) -> dict:
    from warden.vendor_gov.registry import register_vendor
    v = register_vendor(
        tenant_id=body.tenant_id,
        display_name=body.display_name,
        website=body.website,
        provider_type=body.provider_type,
        risk_tier=body.risk_tier,
        contact_email=body.contact_email,
        tags=body.tags,
    )
    return v.to_dict()


@router.get("/vendors", summary="List AI vendors for a tenant", dependencies=[_Gate])
async def list_vendors(
    tenant_id: str,
    status: str | None = None,
    risk_tier: str | None = None,
    provider_type: str | None = None,
) -> dict:
    from warden.vendor_gov.registry import list_vendors as _list
    vendors = _list(tenant_id, status=status, risk_tier=risk_tier, provider_type=provider_type)
    return {"vendors": [v.to_dict() for v in vendors], "count": len(vendors)}


@router.get("/vendors/{vendor_id}", summary="Get a specific vendor", dependencies=[_Gate])
async def get_vendor(vendor_id: str, tenant_id: str) -> dict:
    from warden.vendor_gov.registry import get_vendor as _get
    v = _get(vendor_id, tenant_id)
    if not v:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id!r} not found")
    return v.to_dict()


@router.put("/vendors/{vendor_id}", summary="Update a vendor record", dependencies=[_Gate])
async def update_vendor(vendor_id: str, tenant_id: str, body: VendorUpdateRequest) -> dict:
    from warden.vendor_gov.registry import update_vendor as _upd
    updated = _upd(
        vendor_id=vendor_id,
        tenant_id=tenant_id,
        display_name=body.display_name,
        website=body.website,
        risk_tier=body.risk_tier,
        status=body.status,
        contact_email=body.contact_email,
        tags=body.tags,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id!r} not found")
    return {"updated": True, "vendor_id": vendor_id}


@router.post("/vendors/{vendor_id}/dpa", summary="Add a DPA record to a vendor", dependencies=[_Gate])
async def add_dpa(vendor_id: str, body: DPACreateRequest) -> dict:
    from warden.vendor_gov.registry import add_dpa as _add
    from warden.vendor_gov.registry import get_vendor
    if not get_vendor(vendor_id, body.tenant_id):
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id!r} not found")
    dpa = _add(
        vendor_id=vendor_id,
        tenant_id=body.tenant_id,
        dpa_type=body.dpa_type,
        signed_at=body.signed_at,
        expires_at=body.expires_at,
        doc_ref=body.doc_ref,
        notes=body.notes,
    )
    return dpa.to_dict()


@router.get("/vendors/{vendor_id}/dpa", summary="List DPA records for a vendor", dependencies=[_Gate])
async def list_dpas(vendor_id: str, tenant_id: str) -> dict:
    from warden.vendor_gov.registry import list_dpas as _list
    dpas = _list(vendor_id, tenant_id)
    return {"dpas": [d.to_dict() for d in dpas], "count": len(dpas)}


@router.get("/dpa/expiring", summary="List DPAs expiring within N days", dependencies=[_Gate])
async def get_expiring_dpas(tenant_id: str, within_days: int = 30) -> dict:
    from warden.vendor_gov.registry import get_expiring_dpas as _exp
    dpas = _exp(tenant_id, within_days=within_days)
    return {"expiring": [d.to_dict() for d in dpas], "count": len(dpas), "within_days": within_days}


@router.get("/stats", summary="Vendor governance stats for a tenant", dependencies=[_Gate])
async def get_stats(tenant_id: str) -> dict:
    from warden.vendor_gov.registry import get_vendor_stats
    return get_vendor_stats(tenant_id)
