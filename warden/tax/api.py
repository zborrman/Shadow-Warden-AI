"""
warden/tax/api.py
FastAPI router for tax calculation and invoice retrieval.
Prefix: /tax
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/tax", tags=["Tax & Compliance"])
_Gate  = require_feature("agentic_commerce_enabled")


class TaxRequest(BaseModel):
    net_amount:     float
    seller_country: str = "US"
    buyer_country:  str
    buyer_region:   str | None = None
    is_b2b:         bool = False
    buyer_vat_id:   str | None = None


@router.post("/calculate", summary="Calculate applicable tax", dependencies=[_Gate])
async def calculate_tax(body: TaxRequest) -> dict:
    from warden.tax.calculator import TaxCalculator
    result = TaxCalculator().calculate(
        net_amount=body.net_amount,
        seller_country=body.seller_country,
        buyer_country=body.buyer_country,
        buyer_region=body.buyer_region,
        is_b2b=body.is_b2b,
        buyer_vat_id=body.buyer_vat_id,
    )
    return result.to_dict()


@router.get("/orders/{order_id}/invoice", summary="Download PDF invoice", dependencies=[_Gate])
async def get_invoice(order_id: str, tenant_id: str) -> Response:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    from warden.tax.calculator import TaxCalculator
    from warden.tax.invoice_generator import InvoiceGenerator

    orders = AgenticCommerceService().get_order_history(tenant_id, limit=1000)
    order  = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    tax = TaxCalculator().calculate(
        net_amount=order.get("total", 0),
        seller_country="US",
        buyer_country=order.get("buyer_country", "US"),
    )
    invoice = InvoiceGenerator().create(order, tax)

    return Response(
        content=b"",   # actual PDF fetched from S3 in production
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{invoice["invoice_number"]}.pdf"',
                 "X-Invoice-Number": invoice["invoice_number"],
                 "X-S3-Key": invoice["s3_key"]},
    )


@router.get("/reports", summary="Quarterly tax compliance report", dependencies=[_Gate])
async def quarterly_report(tenant_id: str, year: int = 2026, quarter: int = 2) -> dict:
    from warden.tax.calculator import TaxCalculator
    # In production: load records from DB. Return empty summary for now.
    return TaxCalculator().quarterly_summary([], year=year, quarter=quarter)
