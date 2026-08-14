"""
warden/marketplace/x402_gate.py
x402 Nanopayment Gate for Marketplace Search.

Per x402/1.0 spec:
  - Server returns payment requirements in PAYMENT-REQUIRED response header (base64 JSON).
  - Client sends signed payment authorization in PAYMENT-SIGNATURE request header (base64 JSON).
  - Pre-funded balance model in v1 (channel-based); on-chain USDC batch settlement via Circle
    Gateway is the target for v2 (deductions queued in x402_pending_deductions).
  - Fail-open: gate exceptions must NEVER block legitimate search traffic.

Replay protection (v7.4):
  PAYMENT-SIGNATURE payload MUST include:
    {"agent_id": "...", "nonce": "<uuid4>", "issued_at": <unix_ts>}
  Server validates: issued_at within 5 min, nonce not previously seen.
  Old clients without nonce/issued_at are allowed through with a warning.
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
from contextlib import suppress
from datetime import UTC, datetime
from decimal import Decimal

from fastapi import Request
from fastapi.responses import JSONResponse

from warden.billing.pricing import MARKETPLACE_SEARCH_FEE_USD
from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.payments.x402_balance import X402_BALANCES_DDL, deduct_floor, get_balance

log = logging.getLogger("warden.marketplace.x402_gate")
_x402_audit_log = logging.getLogger("warden.x402.audit")

_X402_ENABLED      = os.getenv("X402_GATE_ENABLED", "false").lower() == "true"
# Same price as one prepaid credit — the payment rail an agent picks must not
# change what a search is worth. See warden/billing/pricing.py.
_SEARCH_FEE_USD    = Decimal(
    os.getenv("MARKETPLACE_SEARCH_FEE_USD", str(MARKETPLACE_SEARCH_FEE_USD))
)
_DB_PATH           = data_path("warden_x402_marketplace.db", "MARKETPLACE_X402_DB_PATH")
_PAYMENT_ADDR      = os.getenv("MARKETPLACE_X402_PAYMENT_ADDRESS", "0x0000000000000000000000000000000000000000")
_db_lock           = threading.RLock()
_NONCE_TTL_SECONDS = 300  # 5 minutes — must match PAYMENT-REQUIRED expires_at window


# ── Schema ─────────────────────────────────────────────────────────────────────

_X402_DDL = f"""
    {X402_BALANCES_DDL}
    CREATE TABLE IF NOT EXISTS x402_pending_deductions (
        deduction_id TEXT PRIMARY KEY,
        agent_id     TEXT NOT NULL,
        amount_usd   REAL NOT NULL,
        resource     TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'pending',
        queued_at    TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS x402_used_nonces (
        nonce      TEXT PRIMARY KEY,
        agent_id   TEXT NOT NULL,
        used_at    INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_x402_pending_agent
        ON x402_pending_deductions(agent_id, status);
    CREATE INDEX IF NOT EXISTS idx_x402_nonces_expiry
        ON x402_used_nonces(expires_at);
"""
register("marketplace_x402", "warden.marketplace.x402_gate", _X402_DDL)


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


def _extract_sig_payload(sig_header: str) -> dict | None:
    """Decode PAYMENT-SIGNATURE header → dict. Returns None on error."""
    if not sig_header:
        return None
    try:
        return json.loads(base64.b64decode(sig_header).decode())
    except Exception:
        return None


# Whether the payer identity MUST be cryptographically proven. Default true —
# an unsigned PAYMENT-SIGNATURE is exactly the forgery Strix demonstrated
# (vuln-0004 / CWE-345: anyone knowing a victim's public DID drained its balance).
_X402_REQUIRE_SIGNED = os.getenv("X402_REQUIRE_SIGNED_PAYMENT", "true").lower() == "true"


def _canonical_payment_msg(agent_id: str, nonce: str, issued_at: int) -> bytes:
    """Deterministic message the payer signs to authorize a payment intent."""
    return f"x402/1.0:{agent_id}:{nonce}:{issued_at}".encode()


def _verify_payment_identity(payload: dict | None) -> str | None:
    """Return the payer's agent_id ONLY when the payload cryptographically proves
    control of it, else None (no trusted payer — never charge a claimed id).

    The DID is self-authenticating: agent_id must equal
    ``pubkey_to_agent_id(public_key)`` (did:shadow:{hash(pubkey)}), and the
    Ed25519 signature over the canonical payment message must verify against that
    key. So a caller cannot spend a balance held under a DID whose private key it
    does not possess — knowing the public DID is not enough.

    Fails CLOSED on a bad/absent signature (returns None); an actual crypto/import
    error also returns None (deny), never raises — the *gate* stays fail-open on
    infra faults, but a forged identity is never trusted.
    """
    if not payload:
        return None
    agent_id = str(payload.get("agent_id", "")) or None
    if not agent_id:
        return None

    if not _X402_REQUIRE_SIGNED:
        # Explicit, documented opt-out (legacy/dev only) — insecure by design.
        return agent_id

    pub_b64 = payload.get("public_key")
    sig_b64 = payload.get("signature")
    nonce = payload.get("nonce")
    issued_at = payload.get("issued_at")
    if not (pub_b64 and sig_b64 and nonce and issued_at is not None):
        log.warning("x402: PAYMENT-SIGNATURE missing public_key/signature — identity not trusted")
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from warden.marketplace.agent import pubkey_to_agent_id
        if pubkey_to_agent_id(str(pub_b64)) != agent_id:
            log.warning("x402: agent_id does not derive from supplied public_key — rejected")
            return None
        msg = _canonical_payment_msg(agent_id, str(nonce), int(issued_at))
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), msg
        )
        return agent_id
    except Exception as exc:  # noqa: BLE001
        log.warning("x402: payment signature verification failed (rejected): %s", exc)
        return None


def _extract_agent_id(sig_header: str) -> str | None:
    """Return the VERIFIED payer agent_id from the PAYMENT-SIGNATURE header, or
    None when the signature is absent/invalid. Used by mcp/gateway too, so both
    x402 call sites reject a forged identity through this one seam."""
    return _verify_payment_identity(_extract_sig_payload(sig_header))


def _consume_nonce(agent_id: str, nonce: str, issued_at: int) -> bool:
    """Validate and consume a nonce for replay prevention.

    Returns True  — nonce is fresh and unused (access allowed).
    Returns False — nonce already used or issued_at outside 5-min window (replay).
    Fail-open: any DB error returns True to avoid blocking legitimate traffic.
    """
    now = int(time.time())
    if abs(now - issued_at) > _NONCE_TTL_SECONDS:
        log.warning("x402 replay: issued_at out of window agent=%s delta=%ds", agent_id[:24], now - issued_at)
        return False
    expires = now + _NONCE_TTL_SECONDS
    try:
        with _db_lock, open_db("marketplace_x402", _DB_PATH, module_default_path=_DB_PATH) as con:
            con.execute("DELETE FROM x402_used_nonces WHERE expires_at < ?", (now,))
            try:
                con.execute(
                    "INSERT INTO x402_used_nonces (nonce, agent_id, used_at, expires_at) "
                    "VALUES (?, ?, ?, ?)",
                    (nonce, agent_id, now, expires),
                )
                return True
            except sqlite3.IntegrityError:
                log.warning("x402 replay: nonce already used agent=%s nonce=%.8s...", agent_id[:24], nonce)
                return False
    except Exception as exc:
        log.debug("x402 nonce check error (fail-open): %s", exc)
        return True


def _log_payment_bypassed(tenant_id: str, resource: str, reason: str) -> None:
    """Emit structured JSON audit line when x402 gate fails open."""
    line = json.dumps({
        "ts":                datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
        "event":             "payment_bypassed",
        "tenant_id":         tenant_id,
        "resource":          resource,
        "reason":            reason,
        "payment_bypassed":  True,
    }, separators=(",", ":"))
    _x402_audit_log.warning(line)


def _has_sufficient_balance(agent_id: str) -> bool:
    """Check whether agent's pre-funded balance covers the search fee."""
    with _db_lock, open_db("marketplace_x402", _DB_PATH, module_default_path=_DB_PATH) as con:
        balance = Decimal(str(get_balance(con, agent_id)))
        return balance >= _SEARCH_FEE_USD


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
        sig_header  = request.headers.get("PAYMENT-SIGNATURE", "")
        sig_payload = _extract_sig_payload(sig_header)
        # Payer identity must be cryptographically proven — a forged/unsigned
        # agent_id resolves to None and is never charged (vuln-0004 / CWE-345).
        agent_id    = _verify_payment_identity(sig_payload)
        tenant_id   = _get_tenant_id(request)

        # Replay protection — only enforced when client sends nonce + issued_at
        if sig_payload and agent_id:
            nonce     = sig_payload.get("nonce")
            issued_at = sig_payload.get("issued_at")
            if nonce and issued_at is not None:
                if not _consume_nonce(agent_id, str(nonce), int(issued_at)):
                    return JSONResponse(
                        status_code=402,
                        content={
                            "error":    "replay_detected",
                            "resource": resource,
                            "message":  "PAYMENT-SIGNATURE nonce already used or issued_at expired.",
                        },
                    )
            else:
                log.debug("x402: no nonce in sig (old client) — replay protection skipped")

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
                        "Fund your balance via POST /marketplace/x402/fund, then retry with "
                        "PAYMENT-SIGNATURE: base64({\"agent_id\",\"public_key\",\"signature\","
                        "\"nonce\",\"issued_at\"}) — agent_id must be did:shadow:{hash(public_key)} "
                        "and signature an Ed25519 sig over x402/1.0:agent_id:nonce:issued_at"
                    ),
                },
            )
            resp.headers["PAYMENT-REQUIRED"] = payment_header
            return resp
        return None
    except Exception as exc:
        log.warning("x402 gate error (fail-open): %s", exc)
        with suppress(Exception):
            _log_payment_bypassed(
                tenant_id=_get_tenant_id(request),
                resource=resource,
                reason=f"gate_exception:{type(exc).__name__}",
            )
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
        with _db_lock, open_db("marketplace_x402", _DB_PATH, module_default_path=_DB_PATH) as con:
            con.execute(
                "INSERT INTO x402_pending_deductions "
                "(deduction_id, agent_id, amount_usd, resource, status, queued_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (str(uuid.uuid4()), agent_id, float(amount), resource, now),
            )
            # Deduct from pre-funded balance immediately
            deduct_floor(con, agent_id, float(amount))
        log.debug("x402 deduction queued: agent=%s resource=%s amount=%s", agent_id[:24], resource, amount)

        # Billing audit chain — fail-open
        try:
            from warden.billing.audit_chain import MCP_CALL, append_billing_event  # noqa: PLC0415
            append_billing_event(
                tenant_id=agent_id,    # x402 uses agent_id as the billing identity
                event_type=MCP_CALL,
                amount_usd=amount,
                agent_id=agent_id,
                tool_name=resource,
            )
        except Exception as _exc:  # noqa: BLE001
            log.debug("billing_audit x402 hook failed (fail-open): %s", _exc)

        return True
    except Exception as exc:
        log.warning("x402 deduct error (fail-open): %s", exc)
        return True
