"""
warden/agent/accounting.py
───────────────────────────
LLM spend accounting for the agent subsystem (SOVA, MasterAgent, Healer).

Converts Anthropic token usage to USD and records it against the tenant in
the cost-allocation ledger so agent spend is no longer invisible.

Prices are USD per 1,000,000 tokens (list prices, updated 2026-09).
`cache_read` tokens are billed at 10% of the input rate.
"""
from __future__ import annotations

import logging

log = logging.getLogger("warden.agent.accounting")

# USD per 1M tokens: (input, output)
_MODEL_PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4-6":            (15.0, 75.0),
    "claude-opus-4-8":            (15.0, 75.0),
    "claude-sonnet-5":            (3.0, 15.0),
    "claude-haiku-4-5-20251001":  (1.0, 5.0),
}
_DEFAULT_PRICE = (15.0, 75.0)   # assume Opus-class if unknown (never undercount)
_CACHE_READ_MULT = 0.10


def estimate_usd(model: str, usage: dict) -> float:
    """Return the USD cost of one call given a token-usage dict."""
    in_rate, out_rate = _MODEL_PRICES.get(model, _DEFAULT_PRICE)
    inp   = int(usage.get("input_tokens", 0) or 0)
    out   = int(usage.get("output_tokens", 0) or 0)
    cache = int(usage.get("cache_read_tokens", 0) or 0)
    return (
        inp   / 1_000_000 * in_rate
        + out / 1_000_000 * out_rate
        + cache / 1_000_000 * in_rate * _CACHE_READ_MULT
    )


def record_llm_spend(tenant_id: str, agent: str, model: str, usage: dict) -> float:
    """
    Record agent LLM spend to the cost-allocation ledger. Best-effort:
    never raises into the caller. Returns the estimated USD amount.
    """
    amount = 0.0
    try:
        amount = estimate_usd(model, usage)
        if amount <= 0:
            return 0.0
        from warden.financial.cost_allocation import record_cost
        record_cost(
            tenant_id=tenant_id or "default",
            amount_usd=amount,
            vendor_id="anthropic",
            department="ai-agents",
            cost_type="api_usage",
            notes=f"{agent}:{model}:in={usage.get('input_tokens', 0)}:out={usage.get('output_tokens', 0)}",
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("accounting: record_llm_spend failed: %s", exc)
    return amount
