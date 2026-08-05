"""
FinOps per-tenant LLM budget + soft model gate (FM-7).

The problem this closes
───────────────────────
`warden.finops.margin` could already decide whether *one* call clears a margin
floor, but nothing called it and nothing knew what a tenant had already spent
this month. Agent paths (SOVA, MasterAgent) route to Opus by default, and Opus
is 5× Sonnet and 19× Haiku on output tokens. A single Pro tenant looping the
MasterAgent can spend a multiple of the plan price in a day, and until now the
first signal would have been the Anthropic invoice.

The model
─────────
Each tier gets a **monthly LLM allowance** derived from its own list price and
the target gross margin: ``allowance = price × (1 − TARGET_GROSS_MARGIN)``. At
75% target margin a $99.99 Pro plan may spend $25.00/mo on inference and still
clear its margin. Free tiers get a small fixed allowance so an unpaid account
cannot burn Opus indefinitely. Enterprise and unpriced/custom tiers are
uncapped — their economics are negotiated, not derived.

Enforcement is **soft and additive**, in the same spirit as `margin.py`:

  * below the warn line   → the most capable model the caller offered
  * warn line → over      → progressively drops the most expensive candidates
  * fully over budget     → the cheapest candidate the caller offered

It **never** blocks a call, never returns a model the caller did not offer, and
never routes below ``candidates[0]`` — the caller's declared minimum capability.
Every failure path resolves to the most capable model: a broken budget database
must not silently degrade answer quality for a paying tenant. Each such bypass
is counted (see ``_STAGE``) so the degradation is visible, not assumed.

Nothing here is a security control. It runs after the fail-closed gates and a
thin margin never weakens a boundary.
"""
from __future__ import annotations

import contextlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.billing.pricing import TARGET_GROSS_MARGIN, monthly_price_usd
from warden.finops.rating import rate_usage
from warden.observability import Reason, record_failopen

log = logging.getLogger(__name__)

# Telemetry stage for bypasses. A bypass here means a tenant got a more
# expensive model than their budget allows — silent revenue loss, which is
# exactly what this module exists to stop, so each one is counted.
_STAGE = "finops_llm_budget"

# Monthly inference allowance for tiers with no list price (starter, trial).
# Small on purpose: enough to evaluate the agent surface, not enough to farm it.
FREE_TIER_LLM_BUDGET_USD: float = float(os.getenv("FREE_TIER_LLM_BUDGET_USD", "0.50"))

# Fraction of the allowance at which the gate starts shedding expensive models.
WARN_AT: float = 0.80

# Tiers whose spend is negotiated rather than derived — never gated.
_UNCAPPED_TIERS: frozenset[str] = frozenset({"enterprise"})

# Month-to-date spend is read per agent call; cache it briefly so a busy agent
# loop does not re-scan the cost table on every turn.
_MTD_TTL_S: float = 60.0
_mtd_cache: dict[str, tuple[float, float]] = {}   # tenant_id → (value, expires_at)


def _month_start_ts() -> int:
    now = datetime.now(UTC)
    return int(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


def tier_llm_budget_usd(tier: str) -> float | None:
    """
    Monthly LLM allowance for a tier. None = uncapped (custom-priced).

    Derived from the canonical list price so a repricing automatically moves the
    allowance with it — the two must never be separate decisions.
    """
    t = (tier or "").strip().lower()
    if t in _UNCAPPED_TIERS:
        return None
    price = monthly_price_usd(t)
    if price is None:
        return None            # unknown/custom tier — no derived allowance
    if price <= 0.0:
        return FREE_TIER_LLM_BUDGET_USD
    return round(price * (1.0 - TARGET_GROSS_MARGIN), 2)


def resolve_tier(tenant_id: str) -> str:
    """
    Best-effort plan lookup for a tenant.

    Returns "" when the plan cannot be resolved — which `tier_llm_budget_usd`
    reads as "custom/uncapped". An unknown tenant is therefore never throttled
    on a guess; the gate only acts on a plan it positively identified.
    """
    try:
        from warden.lemon_billing import get_lemon_billing
        return str(get_lemon_billing().get_plan(tenant_id) or "")
    except Exception as exc:
        record_failopen(_STAGE, Reason.BACKEND_ERROR, exc)
        return ""


def mtd_spend_usd(tenant_id: str, *, use_cache: bool = True) -> float:
    """Month-to-date LLM spend for a tenant (0.0 on any read failure)."""
    now = time.time()
    if use_cache:
        hit = _mtd_cache.get(tenant_id)
        if hit and hit[1] > now:
            return hit[0]
    try:
        from warden.staff.economics import get_tracker
        spent = get_tracker().get_cost_since(tenant_id, _month_start_ts())
    except Exception as exc:
        record_failopen(_STAGE, Reason.BACKEND_ERROR, exc)
        spent = 0.0
    _mtd_cache[tenant_id] = (spent, now + _MTD_TTL_S)
    return spent


def invalidate_cache(tenant_id: str | None = None) -> None:
    """Drop the MTD cache for one tenant, or all of it."""
    if tenant_id is None:
        _mtd_cache.clear()
    else:
        _mtd_cache.pop(tenant_id, None)


@dataclass(frozen=True)
class BudgetStatus:
    tenant_id: str
    tier: str
    budget_usd: float | None      # None = uncapped
    spent_usd: float
    remaining_usd: float | None
    pct_used: float | None        # 0.0–1.0+, None when uncapped
    state: str                    # ok | warn | over | uncapped


def budget_status(tenant_id: str, tier: str) -> BudgetStatus:
    """Where a tenant stands against its monthly LLM allowance."""
    budget = tier_llm_budget_usd(tier)
    spent = mtd_spend_usd(tenant_id)
    if budget is None:
        return BudgetStatus(tenant_id, tier, None, spent, None, None, "uncapped")
    pct = spent / budget if budget > 0 else 1.0
    state = "over" if pct >= 1.0 else ("warn" if pct >= WARN_AT else "ok")
    return BudgetStatus(
        tenant_id=tenant_id,
        tier=tier,
        budget_usd=budget,
        spent_usd=round(spent, 6),
        remaining_usd=round(max(0.0, budget - spent), 6),
        pct_used=round(pct, 4),
        state=state,
    )


@dataclass(frozen=True)
class ModelChoice:
    model: str
    downgraded: bool
    reason: str             # uncapped | within_budget | budget_warn |
                            # budget_exhausted | budget_unavailable
    status: BudgetStatus | None
    est_cost_usd: float


def choose_model(
    tenant_id: str,
    tier: str,
    candidates: list[str],
    est_input_tokens: int = 4_000,
    est_output_tokens: int = 1_000,
    cached_tokens: int = 0,
    agent: str = "agent",
) -> ModelChoice:
    """
    Pick a model from `candidates` (ordered least → most capable) given the
    tenant's month-to-date spend.

    `candidates[0]` is the floor: the least capable model the caller has
    declared acceptable for this task. This function never goes below it and
    never invents a model outside the list.
    """
    if not candidates:
        raise ValueError("choose_model requires at least one candidate model")

    most_capable = candidates[-1]
    try:
        status = budget_status(tenant_id, tier)

        if status.budget_usd is None:
            return ModelChoice(most_capable, False, "uncapped", status,
                               _est(most_capable, est_input_tokens, est_output_tokens, cached_tokens))

        if status.state == "ok":
            return ModelChoice(most_capable, False, "within_budget", status,
                               _est(most_capable, est_input_tokens, est_output_tokens, cached_tokens))

        if status.state == "over":
            chosen, reason = candidates[0], "budget_exhausted"
        else:
            # Warn band: keep the most capable candidate whose estimated cost
            # still fits inside what is left of the allowance.
            remaining = status.remaining_usd or 0.0
            chosen, reason = candidates[0], "budget_warn"
            for model in reversed(candidates):
                if _est(model, est_input_tokens, est_output_tokens, cached_tokens) <= remaining:
                    chosen = model
                    break

        downgraded = chosen != most_capable
        if downgraded:
            _count_downgrade(tier, agent, chosen)
            log.info(
                "LLM budget gate: tenant=%s tier=%s spent=$%.4f/%.2f → %s (was %s)",
                tenant_id, tier, status.spent_usd, status.budget_usd, chosen, most_capable,
            )
        return ModelChoice(chosen, downgraded, reason, status,
                           _est(chosen, est_input_tokens, est_output_tokens, cached_tokens))

    except Exception as exc:
        # Fail-open: quality is never degraded by a budget-system fault.
        record_failopen(_STAGE, Reason.BACKEND_ERROR, exc)
        return ModelChoice(most_capable, False, "budget_unavailable", None,
                           _est(most_capable, est_input_tokens, est_output_tokens, cached_tokens))


def _est(model: str, input_tokens: int, output_tokens: int, cached_tokens: int) -> float:
    return rate_usage(model, input_tokens, output_tokens, cached_tokens).total_usd


def _count_downgrade(tier: str, agent: str, chosen: str) -> None:
    with contextlib.suppress(Exception):   # metrics must never break a model choice
        from warden.metrics import LLM_BUDGET_DOWNGRADE_TOTAL
        LLM_BUDGET_DOWNGRADE_TOTAL.labels(tier=tier, agent=agent, chosen_model=chosen).inc()


def margin_report(tenant_id: str, tier: str) -> dict:
    """
    Revenue vs. cost for one tenant this month — the number the business
    actually runs on. Gross margin here is revenue minus *inference* cost only;
    infrastructure is a fixed cost shared across tenants, not a per-tenant COGS.
    """
    price = monthly_price_usd(tier)
    status = budget_status(tenant_id, tier)
    gross = None if price is None else round(price - status.spent_usd, 4)
    margin = None if not price else round(gross / price, 4)  # type: ignore[operator]
    return {
        "tenant_id":            tenant_id,
        "tier":                 tier,
        "mrr_usd":              price,
        "llm_cost_mtd_usd":     status.spent_usd,
        "llm_budget_usd":       status.budget_usd,
        "budget_pct_used":      status.pct_used,
        "budget_state":         status.state,
        "gross_profit_usd":     gross,
        "gross_margin":         margin,
        "target_gross_margin":  TARGET_GROSS_MARGIN,
    }
