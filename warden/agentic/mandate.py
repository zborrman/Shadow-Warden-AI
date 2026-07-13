"""
warden/agentic/mandate.py
─────────────────────────
AP2-style mandate validator for Shadow Warden AI.

A "mandate" is a signed, TTL-bounded, amount-capped payment instruction
submitted by an AI agent on behalf of a user.

Security checks (in order)
───────────────────────────
  1. Agent status == 'active'
  2. invoice_hash present and not expired (anti-replay)
  3. HMAC-SHA256 signature — ALWAYS required (fail-CLOSED, see below)
  4. amount ≤ invoice price (anti-hallucination / anti-manipulation)
  5. amount ≤ agent max_per_item
  6. monthly_spend + amount ≤ agent monthly_budget

Key hygiene (Phase 7)
─────────────────────
The signing key comes from ``resolve_key("MANDATE_SECRET", purpose="agentic_mandate")``:
an explicit MANDATE_SECRET wins (unchanged for deployments that set it), otherwise the
key is derived from the boot-validated VAULT_MASTER_KEY.

This check used to be skipped entirely when MANDATE_SECRET was unset — i.e. any
deployment that forgot to set it accepted **unsigned** mandates and let a caller spend
against an agent's budget. Signature verification is now unconditional: if no key can
be resolved the mandate is DENIED, never waved through.

Invoice lifecycle
─────────────────
  POST /mcp/quote → create_invoice() → returns {invoice_hash, valid_until}
  POST /mcp/mandate/execute → validate_mandate() → one-time consumption

GDPR: invoice store holds only sku, price, expiry, agent_id — no PII.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
import uuid

from warden.secret_keys import InsecureKeyError, resolve_key

log = logging.getLogger("warden.agentic.mandate")


def _mandate_key() -> bytes:
    """Signing key for agent payment mandates. Resolved per-call (never at import,
    so tests/operators can set the env late). Raises InsecureKeyError in production
    when neither MANDATE_SECRET nor VAULT_MASTER_KEY is configured."""
    return resolve_key("MANDATE_SECRET", purpose="agentic_mandate")


def sign_mandate(invoice_hash: str, sku: str, amount: float, agent_id: str) -> str:
    """Produce the canonical HMAC-SHA256 signature for a mandate.

    Exposed so agents (and tests) sign with exactly the same canonical form the
    validator checks — a divergence here would silently reject every mandate.
    """
    canonical = f"{invoice_hash}:{sku}:{amount}:{agent_id}"
    return hmac.new(_mandate_key(), canonical.encode(), hashlib.sha256).hexdigest()

# In-memory invoice store: invoice_hash → {sku, price, expiry, agent_id}
_invoices:      dict[str, dict] = {}
_invoice_lock = threading.Lock()


# ── Result type ───────────────────────────────────────────────────────────────

class MandateResult:
    __slots__ = ("valid", "reason", "transaction_id")

    def __init__(self, valid: bool, reason: str = "", transaction_id: str = "") -> None:
        self.valid          = valid
        self.reason         = reason
        self.transaction_id = transaction_id


# ── Invoice creation ──────────────────────────────────────────────────────────

def create_invoice(
    sku: str,
    price: float,
    agent_id: str,
    ttl_seconds: int = 300,
) -> dict:
    """
    Create a one-time invoice.

    Returns {invoice_hash, valid_until, sku, price}.
    The agent must present invoice_hash in the mandate payload.
    invoice_hash is a 64-char hex token (32 bytes = 256 bits of randomness).
    """
    invoice_hash = secrets.token_hex(32)
    expiry_ts    = time.time() + ttl_seconds
    with _invoice_lock:
        _invoices[invoice_hash] = {
            "sku":      sku,
            "price":    float(price),
            "expiry":   expiry_ts,
            "agent_id": agent_id,
        }
    log.info(
        "Invoice created: hash=%.12s… sku=%r price=%.2f agent=%s ttl=%ds",
        invoice_hash, sku, price, agent_id, ttl_seconds,
    )
    return {
        "invoice_hash": invoice_hash,
        "valid_until":  int(expiry_ts),
        "sku":          sku,
        "price":        price,
    }


def _purge_expired() -> None:
    """Drop all expired invoices (called under _invoice_lock)."""
    now     = time.time()
    expired = [h for h, v in _invoices.items() if v["expiry"] < now]
    for h in expired:
        _invoices.pop(h, None)


# ── Mandate validation ────────────────────────────────────────────────────────

def validate_mandate(mandate: dict, agent_record: dict) -> MandateResult:
    """
    Validate a mandate dict against the agent record.

    Expected mandate keys
    ─────────────────────
      invoice_hash  — str
      sku           — str
      amount        — float
      currency      — str
      agent_id      — str
      signature     — str (HMAC-SHA256 hex; required when MANDATE_SECRET is set)

    agent_record extra key injected by caller
    ─────────────────────────────────────────
      _monthly_spend — float (current month's approved spend for this agent)
    """
    # 1 ── Agent must be active ────────────────────────────────────────────────
    if agent_record.get("status") != "active":
        return MandateResult(False, f"Agent is {agent_record.get('status', 'unknown')}.")

    # 2 ── Mandatory fields ────────────────────────────────────────────────────
    invoice_hash = mandate.get("invoice_hash", "")
    sku          = str(mandate.get("sku", ""))
    agent_id_in  = str(mandate.get("agent_id", ""))
    signature    = str(mandate.get("signature", ""))
    try:
        amount = float(mandate.get("amount", -1))
    except (TypeError, ValueError):
        return MandateResult(False, "Invalid amount field.")
    if not invoice_hash:
        return MandateResult(False, "Missing invoice_hash.")
    if amount < 0:
        return MandateResult(False, "Amount must be non-negative.")

    # 3 ── HMAC signature — unconditional, fail-CLOSED ─────────────────────────
    # Never skip this. An unsigned mandate is an unauthorized spend instruction;
    # if the key cannot be resolved we deny rather than wave the payment through.
    try:
        expected_sig = sign_mandate(invoice_hash, sku, amount, agent_id_in)
    except InsecureKeyError:
        log.error(
            "mandate: no signing key (set MANDATE_SECRET or VAULT_MASTER_KEY) — denying mandate"
        )
        return MandateResult(False, "Mandate signing key not configured.")
    if not signature or not hmac.compare_digest(expected_sig, signature):
        return MandateResult(False, "Invalid mandate signature.")

    # 4 ── Invoice existence + expiry ─────────────────────────────────────────
    with _invoice_lock:
        _purge_expired()
        invoice = _invoices.get(invoice_hash)
        if invoice is None:
            return MandateResult(False, "Invoice not found or expired.")

        # 4a. Invoice belongs to this agent
        if invoice["agent_id"] != agent_record.get("agent_id", ""):
            return MandateResult(False, "Invoice agent mismatch.")
        # 4b. SKU unchanged since quoting
        if invoice["sku"] != sku:
            return MandateResult(False, "SKU mismatch between invoice and mandate.")

        invoice_price = float(invoice["price"])

    # 5 ── Anti-manipulation: amount must not exceed quoted price ──────────────
    if amount > invoice_price + 1e-9:
        return MandateResult(
            False,
            f"Mandate amount {amount} exceeds invoice price {invoice_price}.",
        )

    # 6 ── Per-item budget ─────────────────────────────────────────────────────
    max_per_item = float(agent_record.get("max_per_item", 0.0))
    if max_per_item > 0 and amount > max_per_item + 1e-9:
        return MandateResult(
            False,
            f"Amount {amount} exceeds agent per-item limit {max_per_item}.",
        )

    # 7 ── Monthly budget ──────────────────────────────────────────────────────
    monthly_budget = float(agent_record.get("monthly_budget", 0.0))
    current_spend  = float(agent_record.get("_monthly_spend", 0.0))
    if monthly_budget > 0 and (current_spend + amount) > monthly_budget + 1e-9:
        return MandateResult(
            False,
            f"Monthly budget exhausted "
            f"(spend={current_spend:.2f} + amount={amount:.2f} > budget={monthly_budget:.2f}).",
        )

    # 8 ── All checks passed — consume invoice (one-time use) ──────────────────
    with _invoice_lock:
        _invoices.pop(invoice_hash, None)

    txn_id = str(uuid.uuid4())
    log.info(
        "Mandate approved: txn=%s agent=%s sku=%r amount=%.2f",
        txn_id, agent_id_in, sku, amount,
    )
    return MandateResult(True, reason="", transaction_id=txn_id)
