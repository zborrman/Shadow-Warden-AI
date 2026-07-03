"""
warden/discovery/well_known.py
───────────────────────────────
Dynamic generators for agent-discovery well-known documents.

Spec refs
─────────
  /.well-known/ai-market.json  — Shadow Warden M2M marketplace descriptor
  /.well-known/mcp.json        — MCP server capability advertisement
"""
from __future__ import annotations

import os
from typing import Any

_GATEWAY_URL = os.getenv("WARDEN_GATEWAY_URL", "https://api.shadow-warden-ai.com")
_MARKET_VERSION = "1.0"
_MCP_VERSION = "2025-11-05"


def build_ai_market(
    *,
    tenant_id: str | None = None,
    extra_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build `/.well-known/ai-market.json` descriptor.

    Advertises Shadow Warden's M2M marketplace to discovery crawlers
    (e.g. agent registries, BeeKeeperAI, Nevermined, 0x).
    """
    capabilities: list[str] = [
        "agent-registration",
        "agent-search",
        "negotiation",
        "escrow",
        "kya-compliance",
        "x402-payments",
        "l402-lightning",
        "mcp-gateway",
        "acp-protocol",
        "did:shadow",
    ]
    if extra_capabilities:
        capabilities.extend(extra_capabilities)

    doc: dict[str, Any] = {
        "version": _MARKET_VERSION,
        "name": "Shadow Warden AI — M2M Marketplace",
        "description": (
            "GDPR-compliant AI security gateway with built-in M2M marketplace, "
            "KYA compliance, progressive autonomy, and multi-protocol payments."
        ),
        "gateway": f"{_GATEWAY_URL}",
        "protocol_endpoint": f"{_GATEWAY_URL}/marketplace/protocol",
        "registration_endpoint": f"{_GATEWAY_URL}/marketplace/register",
        "kya_endpoint": f"{_GATEWAY_URL}/kya/register",
        "mcp_endpoint": f"{_GATEWAY_URL}/mcp/",
        "capabilities": capabilities,
        "payment_methods": [
            {"type": "x402", "version": "1.0", "currency": "USDC", "network": "base-sepolia"},
            {"type": "l402",  "version": "1.0", "currency": "BTC",  "network": "lightning"},
            {"type": "flex-credits", "currency": "internal"},
        ],
        "trust": {
            "did_method": "did:shadow",
            "kya_required": os.getenv("KYA_VERIFIED_ONLY", "false").lower() == "true",
            "trust_registry": f"{_GATEWAY_URL}/kya/list",
        },
        "contact": "mailto:security@shadow-warden-ai.com",
        "openapi": f"{_GATEWAY_URL}/openapi.json",
    }
    if tenant_id:
        doc["tenant_id"] = tenant_id
    return doc


def build_mcp_descriptor(
    *,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """
    Build `/.well-known/mcp.json` capability advertisement.

    Follows the emerging MCP Discovery specification so that
    MCP clients can auto-discover this server.
    """
    from warden.mcp.pricing import MCP_EXPOSED_TOOLS  # noqa: PLC0415

    tools = [
        {"name": t, "endpoint": f"{_GATEWAY_URL}/mcp/", "method": "POST"}
        for t in sorted(MCP_EXPOSED_TOOLS)
    ]

    return {
        "schema_version": _MCP_VERSION,
        "name": "Shadow Warden MCP Gateway",
        "description": "Paid MCP gateway — x402 USDC + L402 Lightning + Flex Credits",
        "url": f"{_GATEWAY_URL}/mcp/",
        "protocol": "MCP/2025-11-05",
        "auth": {
            "schemes": [
                {"type": "bearer",   "header": "Authorization"},
                {"type": "api-key",  "header": "X-API-Key"},
                {"type": "x402",     "header": "PAYMENT-SIGNATURE"},
                {"type": "l402",     "header": "Authorization", "scheme": "L402"},
            ]
        },
        "payment": {
            "required": os.getenv("MCP_DEV_MODE", "false").lower() != "true",
            "methods": ["x402", "l402", "flex-credits"],
            "pricing_endpoint": f"{_GATEWAY_URL}/mcp/pricing",
        },
        "tools": tools,
        "kya": {
            "did_method": "did:shadow",
            "registration_endpoint": f"{_GATEWAY_URL}/kya/register",
        },
        "tenant_id": tenant_id or "public",
    }
