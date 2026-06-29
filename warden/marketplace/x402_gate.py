"""
warden/marketplace/x402_gate.py
x402 Nanopayment Gate for Marketplace Search.

Per x402/1.0 spec:
  - Server returns payment requirements in PAYMENT-REQUIRED response header (base64 JSON).
  - Client sends signed payment authorization in PAYMENT-SIGNATURE request header (base64 JSON).
  - Pre-funded balance model in v1 (channel-based); on-chain USDC batch settlement via Circle
    Gateway is the target for v2 (deductions queued in x402_pending_deductions).
  - Fail-open: gate exceptions must NEVER block legitimate search traffic.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from decimal import Decimal

from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger("warden.marketplace.x402_gate")

_X402_ENABLED   = os.getenv("X402_GATE_ENABLED", "false").lower() == "true"
_SEARCH_FEE_USD = Decimal(os.getenv("MARKETPLACE_SEARCH_FEE_USD", "0.000001"))
_DB_PATH        = os.getenv("MARKETPLACE_X402_DB_PATH", "/tmp/warden_x402_marketplace.db")
_PAYMENT_ADDR   = os.getenv("MARKETPLACE_X402_PAYMENT_ADDRESS", "0x0000000000000000000000000000000000000000")
_db_lock        = threading.RLock()


# ── Schema ─────────────────────────────────────────────────────────────────────

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS x402_balances (
            agent_id    TEXT PRIMARY KEY,
            balance_usd REAL NOT NULL DEFAULT 0.0,
            updated_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS x402_pending_deductions (
            deduction_id TEXT PRIMARY KEY,
            agent_id     TEXT NOT NULL,
            amount_usd   REAL NOT NULL,
            resource     TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            queued_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_x402_pending_agent
            ON x402_pending_deductions(agent_id, status);
    """)


# ── x402 header helpers ────────────────────────────────────────────────────────

def _build_payment_required_header(resource: str) -> str:
    """Return base64-encoded payment requirements per x402 spec PAYMENT-REQUIRED header."""
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300))
    payload = {
        "version": "x402/1.0",
        "resource": resource,
        "schemes": [
            {
                "scheme": "usdc",
                "amount": str(_SEARCH_FEE_USD),
                "currency": "USDC",
                "network": "polygon-amoy",
                "payment_address": _PAYMENT_ADDR,
            }
        ],
        "expires_at": expires,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _extract_agent_id(sig_header: str) -> str | None:
    """Parse agent_id from base64-encoded PAYMENT-SIGNATURE header. Returns None on error."""
    if not sig_header:
        return None
    try:
        decoded = json.loads(base64.b64decode(sig_header).decode())
        return str(decoded.get("agent_id", "")) or None
    except Exception:
        return None


def _has_sufficient_balance(agent_id: str) -> bool:
    """Check whether agent's pre-funded balance covers the search fee."""
    with _db_lock:
        con = sqlite3.connect(_DB_PATH, check_same_thread=False)
        try:
            _ensure_schema(con)
            row = con.execute(
                "SELECT balance_usd FROM x402_balances WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            balance = Decimal(str(row[0])) if row else Decimal("0")
            return balance >= _SEARCH_FEE_USD
        finally:
            con.close()


# ── Public gate API ────────────────────────────────────────────────────────────

def _get_tenant_id(request: Request) -> str:
    state = getattr(request, "state", None)
    tenant = getattr(state, "tenant", None)
    if isinstance(tenant, dict):
        return tenant.get("tenant_id") or tenant.get("id") or "unknown"
    return request.headers.get("X-Tenant-ID", "unknown")


async def require_payment(request: Request, resource: str) -> JSONResponse | None:
    """x402 gate — call before executing a paid resource.

    Priority order:
      1. Flex Credits (no crypto required) — deduct 1 credit and allow
      2. Autonomy check — REQUIRE_APPROVAL → 202; BLOCK → 403
      3. x402 USDC signature balance check → 402 if insufficient

    Returns a JSONResponse(402/403/202) when access is denied or pending,
    or None when access is allowed. Always fail-open on internal errors.
    """
    if not _X402_ENABLED:
        return None
    try:
        sig_header = request.headers.get("PAYMENT-SIGNATURE", "")
        agent_id   = _extract_agent_id(sig_header)
        tenant_id  = _get_tenant_id(request)

        # ── 1. Credits fast-path (enterprise budget-predictable access) ───────
        try:
            from warden.marketplace.credits import deduct_credits, get_balance  # noqa: PLC0415
            if get_balance(tenant_id) >= 1:
                deduct_credits(tenant_id, 1)
                log.debug("x402: credits deducted tenant=%s resource=%s", tenant_id, resource)
                return None   # access granted via credits — skip x402
        except Exception as exc:
            log.debug("x402: credits check error (fail-open): %s", exc)

        # ── 2. Autonomy gate ──────────────────────────────────────────────────
        if agent_id:
            try:
                from warden.marketplace.autonomy import check_action  # noqa: PLC0415
                decision = check_action(agent_id, "search", float(_SEARCH_FEE_USD))
                if decision == "REQUIRE_APPROVAL":
                    resp = JSONResponse(
                        status_code=202,
                        content={
                            "status":   "pending_approval",
                            "resource": resource,
                            "message":  "Action queued for human review per autonomy policy.",
                        },
                    )
                    resp.headers["X-Requires-Approval"] = "pending"
                    return resp
                if decision == "BLOCK":
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error":   "autonomy_blocked",
                            "resource": resource,
                            "message":  "Action exceeds autonomy policy spend limit.",
                        },
                    )
            except Exception as exc:
                log.debug("x402: autonomy check error (fail-open): %s", exc)

        # ── 3. x402 USDC balance check ────────────────────────────────────────
        if agent_id is None or not _has_sufficient_balance(agent_id):
            payment_header = _build_payment_required_header(resource)
            resp = JSONResponse(
                status_code=402,
                content={
                    "error":        "payment_required",
                    "resource":     resource,
                    "instructions": (
                        "Fund your balance via POST /marketplace/x402/fund, "
                        "then retry with PAYMENT-SIGNATURE: base64({\"agent_id\": \"...\"})"
                    ),
                },
            )
            resp.headers["PAYMENT-REQUIRED"] = payment_header
            return resp
        return None
    except Exception as exc:
        log.warning("x402 gate error (fail-open): %s", exc)
        return None


async def deduct_payment(agent_id: str, resource: str, amount_usd: Decimal | None = None) -> bool:
    """Queue a deduction to x402_pending_deductions for batch settlement.

    Deductions are batched and flushed via Circle Gateway USDC rail (future v2).
    The pre-funded balance is deducted immediately to enforce spend controls.
    Fail-open: never blocks the caller.
    """
    if not _X402_ENABLED:
        return True
    try:
        amount = amount_usd if amount_usd is not None else _SEARCH_FEE_USD
        now    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                con.execute(
                    "INSERT INTO x402_pending_deductions "
                    "(deduction_id, agent_id, amount_usd, resource, status, queued_at) "
                    "VALUES (?, ?, ?, ?, 'pending', ?)",
                    (str(uuid.uuid4()), agent_id, float(amount), resource, now),
                )
                # Deduct from pre-funded balance immediately
                con.execute(
                    "UPDATE x402_balances "
                    "SET balance_usd = MAX(0, balance_usd - ?), updated_at = ? "
                    "WHERE agent_id = ?",
                    (float(amount), now, agent_id),
                )
                con.commit()
            finally:
                con.close()
        log.debug("x402 deduction queued: agent=%s resource=%s amount=%s", agent_id[:24], resource, amount)
        return True
    except Exception as exc:
        log.warning("x402 deduct error (fail-open): %s", exc)
        return True
