"""
MCP Paid Tools Gateway — Shadow Warden staff tools over Streamable HTTP.

Protocol: MCP 2024-11-05 (JSON-RPC 2.0, Streamable HTTP transport)
Endpoint: POST /mcp/

Payment flow per tools/call:
  1. Flex Credits fast-path (X-Tenant-ID header, 1 credit per call)
  2. x402 USDC balance (PAYMENT-SIGNATURE: base64({"agent_id": "..."}))
  3. L402 Lightning (Authorization: L402 <macaroon>:<preimage>)
  4. Otherwise → 402 JSON-RPC error (WWW-Authenticate: L402 + x402 headers)

DPI (Deep Packet Inspection):
  All tools/call argument strings are scanned by ObfuscationDecoder +
  SemanticGuard before payment.  BLOCKED params → -32602 error.
  Fail-open: DPI exceptions never block tool execution.

Fail-open: gate exceptions never block tool execution.

Registration:  POST /marketplace/register  →  DID + KYA screening
Fund balance:  POST /marketplace/x402/fund →  pre-fund USDC credits
Discover:      POST /mcp/  {"method":"tools/list"}
Call:          POST /mcp/  {"method":"tools/call","params":{"name":"score_kyc_profile",...}}
               with PAYMENT-SIGNATURE: base64({"agent_id":"<did:shadow:...>"})
               or   Authorization: L402 <macaroon>:<preimage>
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from warden.mcp.pricing import DEFAULT_PRICE_USD, MCP_EXPOSED_TOOLS, TOOL_PRICES_USD, price_for
from warden.mcp.product_tools import (
    FREE_TOOLS,
    PRODUCT_TOOL_HANDLERS,
    PRODUCT_TOOL_SCHEMAS,
)

log = logging.getLogger("warden.mcp.gateway")

router = APIRouter(prefix="/mcp", tags=["mcp"])

# Protocol revisions this endpoint answers, newest first.
#
# The descriptor used to advertise "MCP/2025-11-05", which is not a revision
# that has ever existed (the real ones are 2024-11-05, 2025-03-26, 2025-06-18,
# 2025-11-25, 2026-07-28) — an MCP client comparing it against its own list
# would find no match. The endpoint implements the initialization-based
# Streamable HTTP shape: one endpoint, POST, a JSON-RPC request per POST, a
# single JSON object in reply. That is 2025-06-18 and back; the per-request
# `_meta` negotiation and `server/discover` of 2026-07-28 are NOT implemented,
# so 2026-07-28 is deliberately absent from this list rather than claimed.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-06-18", "2025-03-26", "2024-11-05")
_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
_PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
_SERVER_INFO = {"name": "shadow-warden", "version": "7.9.0"}

# MCP error codes (JSON-RPC standard + MCP extensions)
_PARSE_ERROR     = -32700
_INVALID_REQUEST = -32600
_NOT_FOUND       = -32601
_INVALID_PARAMS  = -32602
_PAYMENT_REQUIRED = -32099   # MCP extension: payment required


def negotiate_version(requested: str | None) -> str:
    """The revision this exchange runs at.

    Echo what the client asked for when it is supported; otherwise answer with
    the newest one we implement and let the client decide whether to continue.
    That is the lifecycle rule for initialization-based revisions, and it is
    also why an unknown version is not an error here.
    """
    if requested and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return _PROTOCOL_VERSION


def _stamp(response: JSONResponse, version: str | None = None) -> JSONResponse:
    """Every response names the revision it was produced under.

    Required from 2025-06-18 onward, and cheap insurance before that: an
    intermediary that has to route or log MCP traffic should not have to parse
    the body to learn the version.
    """
    response.headers[_PROTOCOL_VERSION_HEADER] = version or _PROTOCOL_VERSION
    return response


def _ok(req_id: Any, result: Any, version: str | None = None) -> JSONResponse:
    return _stamp(
        JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result}), version
    )


def _err(req_id: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    e: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    status = 402 if code == _PAYMENT_REQUIRED else 200
    return _stamp(
        JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": e}, status_code=status)
    )


def _dpi_scan(req_id: Any, tool_name: str, arguments: dict) -> JSONResponse | None:
    """
    MCP Deep Packet Inspection — scan argument strings for injection / obfuscation.

    Runs ObfuscationDecoder then SemanticGuard on all string argument values.
    Returns a JSON-RPC error response if any value is BLOCKED; None otherwise.
    Fail-open: exceptions are logged and scan is skipped.
    """
    try:
        from warden.obfuscation import decode as obf_decode  # noqa: PLC0415
        from warden.semantic_guard import SemanticGuard  # noqa: PLC0415

        guard = SemanticGuard()

        for key, val in arguments.items():
            if not isinstance(val, str):
                continue
            decoded = obf_decode(val)
            text    = decoded.decoded_extra or val
            result  = guard.analyse(text)
            if result.risk_level == "BLOCK":
                log.warning(
                    "mcp: DPI BLOCK tool=%s arg=%s risk=%s",
                    tool_name, key, result.risk_level,
                )
                return _err(
                    req_id,
                    _INVALID_PARAMS,
                    f"Argument '{key}' blocked by Deep Packet Inspection",
                    {"rule": result.top_flag, "risk_level": result.risk_level},
                )
            if result.risk_level in ("HIGH", "MEDIUM"):
                log.warning(
                    "mcp: DPI FLAG tool=%s arg=%s risk=%s (allow)",
                    tool_name, key, result.risk_level,
                )
    except Exception as exc:  # noqa: BLE001
        log.debug("mcp: DPI scan error (fail-open): %s", exc)
    return None


def _tool_schema(tool: dict) -> dict:
    """Convert staff tool Anthropic-schema → MCP tool schema."""
    name = tool["name"]
    price = TOOL_PRICES_USD.get(name, DEFAULT_PRICE_USD)
    return {
        "name": name,
        "description": f"{tool['description']} — ${price:.4f}/call via Flex Credits or x402 USDC",
        "inputSchema": tool["input_schema"],
    }


async def _check_payment(request: Request, tool_name: str) -> tuple[str | None, JSONResponse | None]:
    """Gate the call. Returns (agent_id, None) on success, (None, error_response) on deny.

    Priority:
      0. X402_GATE_ENABLED=false → pass through (dev/test mode)
      1. Flex Credits balance ≥ 1 → deduct 1 credit, allow
      2. x402 USDC balance ≥ price → queue deduction, allow
      3. Otherwise → 402 JSON-RPC error
    """
    if os.getenv("X402_GATE_ENABLED", "false").lower() != "true":
        return "dev", None

    try:
        from warden.marketplace.x402_gate import (  # noqa: PLC0415
            _build_payment_required_header,
            _extract_agent_id,
            _has_sufficient_balance,
            deduct_payment,
        )

        sig       = request.headers.get("PAYMENT-SIGNATURE", "")
        agent_id  = _extract_agent_id(sig)
        tenant_id = request.headers.get("X-Tenant-ID", agent_id or "unknown")

        # 1. Flex Credits
        try:
            from warden.marketplace.credits import deduct_credits, get_balance  # noqa: PLC0415
            if get_balance(tenant_id) >= 1:
                deduct_credits(tenant_id, 1)
                log.debug("mcp: credits OK tenant=%s tool=%s", tenant_id, tool_name)
                return agent_id, None
        except Exception:  # noqa: BLE001
            pass

        # 2. x402 USDC
        price = price_for(tool_name)
        if agent_id is None or not _has_sufficient_balance(agent_id):
            pay_hdr = _build_payment_required_header(f"mcp:tools/call:{tool_name}")
            resp = _err(
                None,
                _PAYMENT_REQUIRED,
                "payment_required",
                {
                    "tool":         tool_name,
                    "price_usd":    str(price),
                    "instructions": (
                        "Fund your balance via POST /marketplace/x402/fund, "
                        "then retry with PAYMENT-SIGNATURE: base64({\"agent_id\": \"<did>\"}). "
                        "Alternatively use Flex Credits: POST /marketplace/credits/purchase."
                    ),
                },
            )
            resp.headers["PAYMENT-REQUIRED"] = pay_hdr
            return None, resp

        # 3. L402 Lightning (check before issuing 402)
        authz = request.headers.get("Authorization", "")
        if authz.upper().startswith("L402 "):
            try:
                from warden.payments.l402 import (  # noqa: PLC0415
                    parse_authorization_header,
                    verify_macaroon,
                )
                mac, preimage = parse_authorization_header(authz)
                ok, claims = verify_macaroon(mac, preimage)
                if ok:
                    log.debug("mcp: L402 OK agent=%s tool=%s", claims.get("agent_id"), tool_name)
                    return claims.get("agent_id", "l402"), None
            except Exception as l402_exc:  # noqa: BLE001
                log.warning("mcp: L402 verify error (continuing to 402): %s", l402_exc)

        if agent_id is None or not _has_sufficient_balance(agent_id):
            # Issue L402 challenge alongside x402 payment-required
            www_auth = ""
            try:
                from warden.payments.l402 import (  # noqa: PLC0415
                    build_www_authenticate,
                    create_invoice,
                    issue_macaroon,
                )
                invoice_data = await create_invoice(float(price), description=f"mcp:{tool_name}")
                mac_tok = issue_macaroon(
                    agent_id or "anon",
                    tool_name,
                    invoice_data["amount_sat"],
                    payment_hash=invoice_data["payment_hash"],
                )
                www_auth = build_www_authenticate(mac_tok, invoice_data["payment_request"])
            except Exception as l402_exc:  # noqa: BLE001
                log.warning("mcp: L402 challenge build error: %s", l402_exc)

            pay_hdr = _build_payment_required_header(f"mcp:tools/call:{tool_name}")
            resp = _err(
                None,
                _PAYMENT_REQUIRED,
                "payment_required",
                {
                    "tool":         tool_name,
                    "price_usd":    str(price),
                    "instructions": (
                        "Fund your balance via POST /marketplace/x402/fund, "
                        "then retry with PAYMENT-SIGNATURE: base64({\"agent_id\": \"<did>\"}). "
                        "Or pay via Lightning: use the L402 macaroon+invoice in WWW-Authenticate. "
                        "Or use Flex Credits: POST /marketplace/credits/purchase."
                    ),
                },
            )
            resp.headers["PAYMENT-REQUIRED"] = pay_hdr
            if www_auth:
                resp.headers["WWW-Authenticate"] = www_auth
            return None, resp

        await deduct_payment(agent_id, f"mcp:tools/call:{tool_name}", price)
        return agent_id, None

    except Exception as exc:  # noqa: BLE001
        log.warning("mcp: payment gate error (fail-open): %s", exc)
        return "unknown", None


_DEFAULT_ALLOWED_ORIGINS = (
    "https://shadow-warden-ai.com",
    "https://www.shadow-warden-ai.com",
    "https://app.shadow-warden-ai.com",
    "https://docs.shadow-warden-ai.com",
)


def origin_allowed(origin: str) -> bool:
    """Streamable HTTP: validate Origin, to block DNS-rebinding.

    A request with no Origin is a server-to-server call — every MCP client and
    every curl — and is allowed. A request *with* an Origin came from a browser
    context, and the only browser contexts entitled to reach a paid tool
    endpoint are our own pages. Anything else is refused with 403, which is what
    the transport specification requires.
    """
    if not origin:
        return True
    allowed = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    if not allowed:
        allowed = list(_DEFAULT_ALLOWED_ORIGINS)
    return origin in allowed


@router.get("/", summary="MCP server discovery")
async def mcp_info(request: Request) -> JSONResponse:
    """Server metadata for a human or a crawler; 405 for an MCP client.

    Streamable HTTP reserves GET on the MCP endpoint for opening an SSE stream,
    and a server that does not offer one must answer 405 — returning a JSON blob
    instead leaves a conforming client parsing a body that is not a JSON-RPC
    message. So the answer depends on who is asking: a client that says it
    accepts ``text/event-stream`` is an MCP client probing for a stream and gets
    405 with ``Allow: POST``; anything else (a browser, curl, a crawler) keeps
    the descriptive payload this endpoint has always returned.
    """
    if not origin_allowed(request.headers.get("origin", "")):
        return JSONResponse({"error": "origin_not_allowed"}, status_code=403)

    if "text/event-stream" in request.headers.get("accept", "").lower():
        return _stamp(
            JSONResponse(
                {"error": "method_not_allowed",
                 "detail": "This MCP endpoint has no GET stream. POST JSON-RPC to /mcp/."},
                status_code=405,
                headers={"Allow": "POST"},
            )
        )

    return _stamp(JSONResponse({
        "server": _SERVER_INFO,
        "protocol": _PROTOCOL_VERSION,
        "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
        "transport": "streamable-http",
        "endpoint": "POST /mcp/",
        "manifest": "/.well-known/mcp.json",
        "documentation": "https://shadow-warden-ai.com/mcp",
        "tools_count": len(MCP_EXPOSED_TOOLS) + len(FREE_TOOLS),
        "free_tools": sorted(FREE_TOOLS),
        "billing": {
            "model":        "per-call, on paid tools only",
            "free":         sorted(FREE_TOOLS),
            "methods":      ["Flex Credits", "x402 USDC (polygon-amoy)"],
            "price_range":  "$0.001 – $0.10 per call",
            "registration": "POST /marketplace/register",
            "fund":         "POST /marketplace/x402/fund",
        },
    }))


@router.post("/", summary="MCP Streamable HTTP transport (JSON-RPC 2.0)")
async def mcp_endpoint(request: Request) -> JSONResponse:
    """
    Dispatch MCP JSON-RPC 2.0 messages.

    Free methods:  initialize, ping, notifications/initialized, tools/list
    Paid methods:  tools/call  (x402 or Flex Credits required)
    """
    if not origin_allowed(request.headers.get("origin", "")):
        # Transport requirement: an invalid Origin is 403, before anything else.
        return JSONResponse({"error": "origin_not_allowed"}, status_code=403)

    try:
        body = await request.json()
    except Exception:
        return _err(None, _PARSE_ERROR, "Parse error: body must be JSON")

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}
    version = negotiate_version(
        params.get("protocolVersion") or request.headers.get(_PROTOCOL_VERSION_HEADER)
    )

    # ── Free tier ──────────────────────────────────────────────────────────────

    if method == "initialize":
        return _ok(req_id, {
            "protocolVersion": version,
            "capabilities":    {"tools": {"listChanged": False}},
            "serverInfo":      _SERVER_INFO,
            "instructions":    (
                "Shadow Warden AI is a zero-trust AI security gateway. "
                "filter_text screens text through the nine-stage pipeline "
                "(prompt injection, obfuscation, secrets, PII) and is free — it "
                "runs against your own gateway quota, so send your API key in the "
                "X-API-Key header. gateway_health and list_pricing need no key. "
                "The remaining tools are staff business tools and are billed per "
                "call: register at POST /marketplace/register for a DID, then fund "
                "at POST /marketplace/x402/fund, or buy Flex Credits. "
                "Full documentation: https://shadow-warden-ai.com/mcp"
            ),
        }, version)

    if method == "ping":
        return _ok(req_id, {}, version)

    if method == "notifications/initialized":
        # A JSON-RPC notification: 202 with no body, per the transport.
        return _stamp(JSONResponse({}, status_code=202), version)

    if method == "tools/list":
        from warden.staff.tools import STAFF_TOOLS  # noqa: PLC0415
        # Product tools first: an agent that truncates the list must still see
        # the ones that do what this product does.
        exposed = list(PRODUCT_TOOL_SCHEMAS) + [
            _tool_schema(t) for t in STAFF_TOOLS if t["name"] in MCP_EXPOSED_TOOLS
        ]
        return _ok(req_id, {"tools": exposed}, version)

    # ── Paid: tools/call ───────────────────────────────────────────────────────

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}

        if tool_name not in MCP_EXPOSED_TOOLS and tool_name not in FREE_TOOLS:
            return _err(req_id, _NOT_FOUND, f"Tool not found or not exposed: {tool_name}")

        # ── Product tools ─────────────────────────────────────────────────────
        # No payment gate: filter_text is metered by POST /filter against the
        # caller's own quota, and billing it twice for one request would be a
        # double charge. DPI is skipped too — filter_text *is* the inspector, and
        # scanning its argument would refuse the very payload it was called to
        # judge, which is the one input an attacker gets to choose.
        if tool_name in FREE_TOOLS:
            try:
                product_handler = PRODUCT_TOOL_HANDLERS[tool_name]
                result = await product_handler(request.headers.get("x-api-key"), arguments)
                return _ok(req_id, {
                    "content": [{"type": "text", "text": json.dumps(result)}],
                    "isError": bool(result.get("error")),
                }, version)
            except Exception as exc:
                log.error("mcp: product tool error tool=%s err=%s", tool_name, exc)
                return _ok(req_id, {
                    "content": [{"type": "text", "text": f"Tool error: {exc}"}],
                    "isError": True,
                }, version)

        # DPI: scan argument strings for injection / obfuscation before payment
        dpi_err = _dpi_scan(req_id, tool_name, arguments)
        if dpi_err is not None:
            return dpi_err

        _agent_id, pay_err = await _check_payment(request, tool_name)
        if pay_err is not None:
            return pay_err

        try:
            from warden.staff.tools import STAFF_TOOL_HANDLERS  # noqa: PLC0415
            handler: Any = STAFF_TOOL_HANDLERS[tool_name]
            result = await handler(**arguments)
            return _ok(req_id, {
                "content": [{"type": "text", "text": json.dumps(result)}],
                "isError": False,
            }, version)
        except TypeError as exc:
            return _err(req_id, _INVALID_PARAMS, f"Invalid arguments: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.error("mcp: tool error tool=%s err=%s", tool_name, exc)
            return _ok(req_id, {
                "content": [{"type": "text", "text": f"Tool error: {exc}"}],
                "isError": True,
            }, version)

    return _err(req_id, _NOT_FOUND, f"Method not found: {method}")
