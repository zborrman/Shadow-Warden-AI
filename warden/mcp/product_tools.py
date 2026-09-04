"""
warden/mcp/product_tools.py
────────────────────────────
The gateway's own API, exposed as MCP tools.

Until this existed, ``tools/list`` on the MCP endpoint returned twelve *staff*
tools — CRM lookups, KYC scoring, ad-budget adjustment — every one of them
billed per call. An MCP client that connected in order to use Shadow Warden
found nothing that filters a prompt, which is the product. A readiness audit
recorded the gap as "MCP mentioned on site but no standard manifest endpoint
found", and the manifest it could not find would have described the wrong tools
anyway.

These three are free, and they are the ones an agent actually reaches for:

  filter_text     run text through the nine-stage pipeline — the product
  gateway_health  liveness, version, pipeline readiness
  list_pricing    plans, request allowances and prices

Why free
────────
``filter_text`` is already metered: it goes through ``POST /filter`` like every
other caller, so it consumes the caller's monthly quota and per-minute window
and is refused the same way. Charging an x402 nanopayment *on top* would bill
twice for one request. The other two read published facts.

Why an HTTP hop rather than an in-process call
───────────────────────────────────────────────
``POST /filter`` is where authentication, the tenant rate limit, the monthly
quota, the ERS shadow-ban check and the audit trail live — as route
dependencies and ASGI middleware, none of which run if the pipeline is invoked
directly. Calling the endpoint over loopback is what makes an MCP call
indistinguishable from a REST call, which is the whole point of exposing the
API as tools. ``warden/agent/tools.py`` reaches the same conclusion for the
same reason.

The caller's own ``X-API-Key`` is forwarded — never the gateway's internal key.
An MCP client without a key gets the same 401/403 it would get from REST,
rather than quietly spending someone else's quota.
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("warden.mcp.product_tools")

_TIMEOUT = 30.0


def _base_url() -> str:
    """Loopback by default; overridable for tests and non-default ports."""
    return os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001").rstrip("/")


#: Tools served without payment. ``gateway.py`` consults this before the x402 gate.
FREE_TOOLS: frozenset[str] = frozenset({"filter_text", "gateway_health", "list_pricing"})


PRODUCT_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "filter_text",
        "description": (
            "Screen text with the Shadow Warden nine-stage security pipeline before it "
            "reaches a model, a tool or a log. Detects prompt injection and jailbreaks, "
            "decodes obfuscated instructions (base64, hex, ROT13, Caesar, word-split, "
            "UUencode, homoglyphs, to depth 3) and redacts secrets and PII. Returns a "
            "verdict, a risk score, the flags that fired and the redacted text. "
            "Requires the caller's Shadow Warden API key in the X-API-Key header; "
            "consumes the caller's own request quota. Content is never logged."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "The text to screen. Up to 100000 characters.",
                },
                "strict": {
                    "type": "boolean",
                    "description": "Raise the sensitivity of the secret scanner. Default false.",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "gateway_health",
        "description": (
            "Report Shadow Warden gateway liveness, version and pipeline readiness. "
            "No authentication, no quota. Use it to decide whether to route traffic "
            "through the gateway before you depend on it."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_pricing",
        "description": (
            "List Shadow Warden plans with their monthly price, included request "
            "allowance and headline features. No authentication. Prices are read from "
            "the same table the checkout charges from."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


async def _call_filter(api_key: str | None, arguments: dict) -> dict:
    import httpx  # noqa: PLC0415

    content = arguments.get("content")
    if not isinstance(content, str) or not content:
        return {"error": "invalid_arguments", "detail": "content must be a non-empty string"}
    if not api_key:
        # The same refusal REST gives, phrased so an agent knows what to do next.
        return {
            "error": "authentication_required",
            "detail": (
                "filter_text runs against your own gateway quota. Send your Shadow "
                "Warden API key in the X-API-Key header of the MCP request. "
                "Get one at https://shadow-warden-ai.com/pricing"
            ),
        }

    body: dict[str, Any] = {"content": content}
    if arguments.get("strict") is not None:
        body["strict"] = bool(arguments["strict"])

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        response = await client.post(
            f"{_base_url()}/filter",
            json=body,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        )
    if response.status_code >= 400:
        # Surfaced, not swallowed: a 429 here is the caller's own rate limit and
        # they need to see it to back off.
        return {
            "error": "gateway_error",
            "status": response.status_code,
            "detail": response.text[:500],
        }
    return response.json()


async def _call_health(_api_key: str | None, _arguments: dict) -> dict:
    import httpx  # noqa: PLC0415

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        response = await client.get(f"{_base_url()}/health")
    if response.status_code >= 400:
        return {"error": "gateway_error", "status": response.status_code}
    return response.json()


async def _call_pricing(_api_key: str | None, _arguments: dict) -> dict:
    """Read the canonical price table in-process — it is a constant, not a call.

    ``TIER_PRICE_USD_MONTH`` is the single place a list price is written down
    (see the module it lives in for why), and ``TIER_LIMITS`` owns the request
    allowance. Reading anything else here would re-create the drift that table
    exists to prevent.
    """
    from warden.billing.feature_gate import TIER_LIMITS  # noqa: PLC0415
    from warden.billing.pricing import (  # noqa: PLC0415
        ANNUAL_DISCOUNT,
        TIER_PRICE_USD_MONTH,
    )

    plans = []
    for tier, price in TIER_PRICE_USD_MONTH.items():
        if tier == "trial":
            continue
        limits = TIER_LIMITS.get(tier, {})
        requests = limits.get("req_per_month")
        plans.append({
            "id": tier,
            "name": tier.replace("_", " ").title(),
            "price_usd_month": round(price, 2),
            "price_usd_year": round(price * 12 * (1 - ANNUAL_DISCOUNT), 2),
            # None means unlimited, which is not the same as zero.
            "requests_per_month": requests,
            "unlimited_requests": requests is None,
        })
    return {
        "currency": "USD",
        "annual_discount": ANNUAL_DISCOUNT,
        "plans": plans,
        "details": "https://shadow-warden-ai.com/pricing",
    }


PRODUCT_TOOL_HANDLERS = {
    "filter_text": _call_filter,
    "gateway_health": _call_health,
    "list_pricing": _call_pricing,
}
