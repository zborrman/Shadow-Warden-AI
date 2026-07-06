"""
warden/api/discovery.py
───────────────────────
FastAPI router for agent-discovery well-known endpoints.

Endpoints
─────────
  GET /.well-known/ai-market.json   — M2M marketplace descriptor
  GET /.well-known/mcp.json         — MCP capability advertisement
  GET /mcp/pricing                  — MCP tool pricing table
"""
from __future__ import annotations

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from warden.discovery.well_known import build_ai_market, build_mcp_descriptor

router = APIRouter(tags=["Discovery"])


@router.get("/.well-known/ai-market.json")
async def ai_market(x_tenant_id: str = Header("")) -> JSONResponse:
    doc = build_ai_market(tenant_id=x_tenant_id or None)
    return JSONResponse(content=doc, media_type="application/json")


@router.get("/.well-known/mcp.json")
async def mcp_well_known(x_tenant_id: str = Header("")) -> JSONResponse:
    doc = build_mcp_descriptor(tenant_id=x_tenant_id or None)
    return JSONResponse(content=doc, media_type="application/json")


@router.get("/mcp/pricing")
async def mcp_pricing() -> dict:
    from warden.mcp.pricing import DEFAULT_PRICE_USD, TOOL_PRICES_USD  # noqa: PLC0415
    return {
        "default_price_usd": DEFAULT_PRICE_USD,
        "tools": TOOL_PRICES_USD,
        "payment_methods": ["x402", "l402", "flex-credits"],
    }
