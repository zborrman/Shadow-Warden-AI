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
_SITE_URL = os.getenv("WARDEN_SITE_URL", "https://shadow-warden-ai.com")
_MARKET_VERSION = "1.0"


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
    Build the `/.well-known/mcp.json` server descriptor.

    Three things were wrong with the previous document, and each of them is the
    kind of error that makes an automated client give up silently rather than
    complain:

      * it advertised protocol "2025-11-05", which is not a revision that has
        ever existed, so a client matching it against its own list found nothing;
      * it never named the transport, which is the first thing a client needs in
        order to know how to speak to the endpoint at all;
      * it listed only the paid staff tools, so a client that connected to use
        the security gateway found no tool that filters anything.

    Every field here is derived from what ``warden/mcp/gateway.py`` actually
    implements — ``warden/tests/test_mcp_manifest.py`` holds the two in
    agreement.
    """
    from warden.mcp.gateway import SUPPORTED_PROTOCOL_VERSIONS  # noqa: PLC0415
    from warden.mcp.pricing import MCP_EXPOSED_TOOLS, price_for  # noqa: PLC0415
    from warden.mcp.product_tools import FREE_TOOLS  # noqa: PLC0415

    endpoint = f"{_GATEWAY_URL}/mcp/"
    tools = [
        {"name": t, "endpoint": endpoint, "method": "POST", "price_usd": "0"}
        for t in sorted(FREE_TOOLS)
    ] + [
        {"name": t, "endpoint": endpoint, "method": "POST", "price_usd": str(price_for(t))}
        for t in sorted(MCP_EXPOSED_TOOLS)
    ]

    return {
        "schema_version": SUPPORTED_PROTOCOL_VERSIONS[0],
        "name": "Shadow Warden AI MCP Server",
        "description": (
            "Zero-trust AI security gateway as MCP tools. filter_text screens text "
            "through the nine-stage pipeline (prompt injection, obfuscation decoding, "
            "secret and PII redaction) and is free against the caller's own gateway "
            "quota; the staff business tools are billed per call via Flex Credits, "
            "x402 USDC or L402 Lightning."
        ),
        "url": endpoint,
        "transport": "streamable-http",
        "protocol": f"MCP/{SUPPORTED_PROTOCOL_VERSIONS[0]}",
        "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
        "documentation": f"{_SITE_URL}/mcp",
        "auth": {
            "schemes": [
                {"type": "bearer",   "header": "Authorization"},
                {"type": "api-key",  "header": "X-API-Key"},
                {"type": "x402",     "header": "PAYMENT-SIGNATURE"},
                {"type": "l402",     "header": "Authorization", "scheme": "L402"},
            ]
        },
        "payment": {
            # Free tools are never gated, so "required" describes the paid ones.
            "required": os.getenv("MCP_DEV_MODE", "false").lower() != "true",
            "free_tools": sorted(FREE_TOOLS),
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
