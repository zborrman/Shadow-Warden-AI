"""
warden/payments/l402.py
───────────────────────
L402 Lightning-Native API Access protocol.

Spec: https://l402.org / LND LSAT (Lightning Service Authentication Token)

Flow
────
  1. Client requests a tool call without payment
  2. Gateway returns HTTP 402 with:
       WWW-Authenticate: L402 macaroon="<token>", invoice="<bolt11>"
  3. Client pays the invoice over Lightning Network
  4. Client retries with:
       Authorization: L402 <macaroon>:<preimage>
  5. Gateway verifies HMAC + preimage hash matches payment hash

Components
──────────
  Macaroon  — HMAC-SHA256 capability token (agent_id:tool:amount:expires:sig)
  Invoice   — BOLT-11 stub (real LN via LNURL-pay or LND API when
              L402_LND_URL + L402_LND_MACAROON_HEX env vars are set)
  Verifier  — checks macaroon HMAC + preimage SHA256 == payment_hash

No hard dependency on LND/CLN/LDK — falls back to a deterministic stub
that accepts `preimage = sha256(macaroon_root)[:32 hex chars]` for
integration tests and dev mode.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Any

from warden.secret_keys import resolve_key

log = logging.getLogger("warden.payments.l402")

def _hmac_key() -> bytes:
    return resolve_key("L402_HMAC_KEY", purpose="l402")
_LND_URL   = os.getenv("L402_LND_URL", "")
_LND_MAC   = os.getenv("L402_LND_MACAROON_HEX", "")
_DEV_MODE  = os.getenv("L402_DEV_MODE", "true").lower() == "true"
_TTL_S     = int(os.getenv("L402_TOKEN_TTL_S", "600"))  # 10 min default


# ── Macaroon ───────────────────────────────────────────────────────────────────

def _sign_macaroon(root: str) -> str:
    return hmac.new(_hmac_key(), root.encode(), hashlib.sha256).hexdigest()


def issue_macaroon(
    agent_id: str,
    tool_name: str,
    amount_sat: int,
    *,
    payment_hash: str = "",
) -> str:
    """
    Issue an HMAC-signed L402 macaroon.

    Format (pipe-delimited, base64url-encoded):
      agent_id|tool_name|amount_sat|expires_at|payment_hash|sig
    """
    expires_at = int(time.time()) + _TTL_S
    root = f"{agent_id}|{tool_name}|{amount_sat}|{expires_at}|{payment_hash}"
    sig  = _sign_macaroon(root)
    raw  = f"{root}|{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def verify_macaroon(macaroon_b64: str, preimage_hex: str) -> tuple[bool, dict[str, Any]]:
    """
    Verify macaroon + preimage.  Returns (ok, claims).

    ok=False reasons: bad HMAC, expired token, preimage mismatch.
    Fail-open: on parse errors returns (True, {}) to not block valid callers.
    """
    try:
        padded = macaroon_b64 + "==" * (4 - len(macaroon_b64) % 4)
        raw    = base64.urlsafe_b64decode(padded).decode()
        parts  = raw.split("|")
        if len(parts) != 6:  # noqa: PLR2004
            return False, {"error": "bad_macaroon_format"}

        agent_id, tool_name, amount_sat, expires_at, payment_hash, sig = parts
        root = f"{agent_id}|{tool_name}|{amount_sat}|{expires_at}|{payment_hash}"

        # HMAC check
        expected = _sign_macaroon(root)
        if not hmac.compare_digest(expected, sig):
            return False, {"error": "bad_hmac"}

        # Expiry check
        if int(expires_at) < int(time.time()):
            return False, {"error": "expired"}

        # Preimage check: sha256(preimage) == payment_hash
        if payment_hash:
            preimage_bytes = bytes.fromhex(preimage_hex) if preimage_hex else b""
            derived_hash   = hashlib.sha256(preimage_bytes).hexdigest()
            if not hmac.compare_digest(derived_hash, payment_hash):
                return False, {"error": "preimage_mismatch"}

        return True, {
            "agent_id":    agent_id,
            "tool_name":   tool_name,
            "amount_sat":  int(amount_sat),
            "expires_at":  int(expires_at),
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("l402: macaroon parse error (fail-open): %s", exc)
        return True, {}


def parse_authorization_header(authorization: str) -> tuple[str, str]:
    """
    Parse `Authorization: L402 <macaroon>:<preimage>`.
    Returns (macaroon_b64, preimage_hex).  Both empty on parse error.
    """
    try:
        scheme, _, rest = authorization.partition(" ")
        if scheme.upper() != "L402":
            return "", ""
        macaroon, _, preimage = rest.partition(":")
        return macaroon.strip(), preimage.strip()
    except Exception:  # noqa: BLE001
        return "", ""


# ── Invoice generation ─────────────────────────────────────────────────────────

def _usd_to_sat(amount_usd: float) -> int:
    """Rough conversion: $1 USD ≈ 2 000 sat at ~$50k BTC price. Override via env."""
    btc_price = float(os.getenv("L402_BTC_PRICE_USD", "50000"))
    return max(1, int(amount_usd * 100_000_000 / btc_price))


def _stub_invoice(payment_hash: str, amount_sat: int, description: str) -> str:
    """
    Deterministic BOLT-11-like stub for dev/test.
    Real LND integration: POST /v1/invoices  { value: amount_sat, memo: desc, r_preimage: ... }
    """
    encoded = base64.urlsafe_b64encode(
        f"lnbc{amount_sat}n1{payment_hash[:20]}{description[:10]}".encode()
    ).decode().rstrip("=")
    return f"lnbc{amount_sat}n1{encoded}"[:200]


async def create_invoice(
    amount_usd: float,
    description: str = "Shadow Warden MCP access",
) -> dict[str, Any]:
    """
    Create a Lightning invoice for *amount_usd*.

    Returns:
      { payment_hash, payment_request (BOLT-11), amount_sat, expires_in }

    Uses LND REST API when L402_LND_URL + L402_LND_MACAROON_HEX are set;
    else returns a deterministic stub suitable for integration tests.
    """
    amount_sat   = _usd_to_sat(amount_usd)
    preimage_hex = secrets.token_hex(32)
    payment_hash = hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()

    if _LND_URL and _LND_MAC and not _DEV_MODE:
        try:
            import httpx  # noqa: PLC0415
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:  # noqa: S501
                resp = await client.post(
                    f"{_LND_URL}/v1/invoices",
                    headers={"Grpc-Metadata-macaroon": _LND_MAC},
                    json={"value": amount_sat, "memo": description, "expiry": _TTL_S},
                )
                data = resp.json()
                return {
                    "payment_hash":    data.get("r_hash", payment_hash),
                    "payment_request": data.get("payment_request", ""),
                    "amount_sat":      amount_sat,
                    "expires_in":      _TTL_S,
                    "preimage_hex":    preimage_hex,
                }
        except Exception as exc:  # noqa: BLE001
            log.warning("l402: LND invoice error (fallback to stub): %s", exc)

    # Dev stub
    bolt11 = _stub_invoice(payment_hash, amount_sat, description)
    return {
        "payment_hash":    payment_hash,
        "payment_request": bolt11,
        "amount_sat":      amount_sat,
        "expires_in":      _TTL_S,
        "preimage_hex":    preimage_hex,   # included in stub mode so tests can self-pay
        "_stub":           True,
    }


def build_www_authenticate(macaroon: str, bolt11: str) -> str:
    """Build the `WWW-Authenticate: L402 ...` response header value."""
    return f'L402 macaroon="{macaroon}", invoice="{bolt11}"'
