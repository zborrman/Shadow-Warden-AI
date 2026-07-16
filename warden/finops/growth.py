"""
FinOps growth accounting (FM-6).

The billing machinery (FM-1..FM-5) now exceeds the *measurement* machinery: we
can rate, route, and cap spend, but nothing reads the acquisition loop back as
numbers. This module is the measurement layer — pure, deterministic growth math
so a dashboard/agent can decide where a marginal dollar goes:

  * **Funnel** — signup → first `/filter` → trial → paid → expansion. `build_funnel`
    turns ordered stage counts into per-stage and top-of-funnel conversion + the
    biggest drop-off, so the worst leak is named.
  * **Viral coefficient K** = invites_per_user × acceptance_rate × activation_rate.
    K ≥ 1 is self-sustaining, ≥ 0.5 justifies raising the referral bonus, < 0.2
    means the loop is dead weight (thresholds from docs/fintech-development-plan.md).
    `amplification = 1/(1−K)` is the total users each seed cohort ultimately yields.
  * **Unit economics** — ARPA, gross margin, logo churn, NRR, LTV = ARPA·margin/churn,
    LTV:CAC, and payback months. SMB target: LTV:CAC ≥ 3 and payback < 6 months.

Pure math (no I/O) except `resolve_referral_k`, an error-swallowing adapter that
reads the existing `billing/referral.py` redemption counters out of Redis. It
adds no storage — Track B owns the data layer; this only *reads* what referral
already writes, and accepts funnel/economics inputs the caller supplies from BI.

**Security invariant (Track C rule):** growth accounting is purely observational.
It reads metadata counts only (GDPR content-never-logged rule holds — no request
bodies here), makes no routing/billing decision, and never touches a security gate.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass

log = logging.getLogger(__name__)


# ── Funnel ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FunnelStage:
    name: str
    count: int
    conversion_from_prev: float   # count / previous stage count
    conversion_from_top: float    # count / first stage count
    dropoff_from_prev: float      # 1 − conversion_from_prev (fraction lost here)


@dataclass(frozen=True)
class Funnel:
    stages: tuple[FunnelStage, ...]
    overall_conversion: float             # last / first
    worst_leak: str | None                # stage name with the largest drop-off


def build_funnel(stage_counts: list[tuple[str, int]]) -> Funnel:
    """
    Turn an ordered [(stage_name, count), ...] list into a funnel with per-stage
    and top-of-funnel conversion. Counts are clamped to ≥ 0. A zero upstream
    stage yields 0.0 conversion downstream (no division blow-up). The worst leak
    is the transition (after the first stage) with the largest drop-off.
    """
    if not stage_counts:
        return Funnel(stages=(), overall_conversion=0.0, worst_leak=None)

    counts = [(str(name), max(0, int(c))) for name, c in stage_counts]
    top = counts[0][1]
    stages: list[FunnelStage] = []
    worst_leak: str | None = None
    worst_dropoff = -1.0

    prev = None
    for i, (name, count) in enumerate(counts):
        if prev is None:
            conv_prev = 1.0
        elif prev > 0:
            conv_prev = count / prev
        else:
            conv_prev = 0.0
        conv_top = (count / top) if top > 0 else 0.0
        dropoff = max(0.0, 1.0 - conv_prev)
        stages.append(FunnelStage(name, count, conv_prev, conv_top, dropoff))
        # track worst leak only on transitions (skip the first stage)
        if i > 0 and dropoff > worst_dropoff:
            worst_dropoff = dropoff
            worst_leak = name
        prev = count

    overall = (counts[-1][1] / top) if top > 0 else 0.0
    return Funnel(stages=tuple(stages), overall_conversion=overall, worst_leak=worst_leak)


# ── Viral coefficient ─────────────────────────────────────────────────────────

_K_SELF_SUSTAINING = 1.0
_K_HEALTHY = 0.5
_K_WEAK = 0.2


@dataclass(frozen=True)
class ViralCoefficient:
    cohort_size: int
    invites_sent: int
    accepted: int
    activated: int
    invites_per_user: float
    acceptance_rate: float
    activation_rate: float
    k: float
    verdict: str          # self_sustaining | healthy | weak | dead
    amplification: float  # 1/(1−K) for K<1, else +inf (explosive)


def _k_verdict(k: float) -> str:
    if k >= _K_SELF_SUSTAINING:
        return "self_sustaining"
    if k >= _K_HEALTHY:
        return "healthy"
    if k >= _K_WEAK:
        return "weak"
    return "dead"


def _amplification(k: float) -> float:
    """Total users a seed cohort ultimately yields = geometric sum 1/(1−K)."""
    if k >= 1.0:
        return math.inf
    if k <= 0.0:
        return 1.0
    return 1.0 / (1.0 - k)


def viral_coefficient(
    cohort_size: int, invites_sent: int, accepted: int, activated: int
) -> ViralCoefficient:
    """
    K = invites_per_user × acceptance_rate × activation_rate, factored so a weak
    loop can be diagnosed (few invites vs. low acceptance vs. low activation).

      invites_per_user = invites_sent / cohort_size
      acceptance_rate  = accepted / invites_sent
      activation_rate  = activated / accepted

    All ratios degrade to 0.0 on a zero denominator rather than raising. Counts
    are clamped ≥ 0.
    """
    n = max(0, int(cohort_size))
    inv = max(0, int(invites_sent))
    acc = max(0, int(accepted))
    act = max(0, int(activated))

    invites_per_user = (inv / n) if n > 0 else 0.0
    acceptance_rate = (acc / inv) if inv > 0 else 0.0
    activation_rate = (act / acc) if acc > 0 else 0.0
    k = invites_per_user * acceptance_rate * activation_rate

    return ViralCoefficient(
        cohort_size=n,
        invites_sent=inv,
        accepted=acc,
        activated=act,
        invites_per_user=invites_per_user,
        acceptance_rate=acceptance_rate,
        activation_rate=activation_rate,
        k=k,
        verdict=_k_verdict(k),
        amplification=_amplification(k),
    )


# ── Unit economics ────────────────────────────────────────────────────────────

def arpa(mrr_total: float, active_accounts: int) -> float:
    """Average revenue per account = total MRR / active accounts."""
    n = max(0, int(active_accounts))
    if n == 0:
        return 0.0
    return max(0.0, float(mrr_total)) / n


def logo_churn(churned_accounts: int, starting_accounts: int) -> float:
    """Fraction of accounts lost over the period. 0.0 on an empty starting base."""
    start = max(0, int(starting_accounts))
    if start == 0:
        return 0.0
    return max(0, int(churned_accounts)) / start


def net_revenue_retention(
    starting_mrr: float,
    expansion_mrr: float,
    contraction_mrr: float,
    churned_mrr: float,
) -> float:
    """
    NRR = (starting + expansion − contraction − churn) / starting.

    Measures dollar retention of the existing cohort (excludes new logos). > 1.0
    means expansion outran churn. 0.0 when there is no starting revenue.
    """
    start = max(0.0, float(starting_mrr))
    if start <= 0.0:
        return 0.0
    net = start + max(0.0, float(expansion_mrr)) - max(0.0, float(contraction_mrr)) - max(0.0, float(churned_mrr))
    return net / start


def ltv(arpa_usd: float, gross_margin: float, monthly_churn: float) -> float:
    """
    Lifetime value = ARPA × gross_margin × expected lifetime, lifetime = 1/churn.

    Zero churn → infinite lifetime (returns +inf). A non-positive margin yields
    0.0 (an unprofitable account has no positive lifetime value).
    """
    margin = max(0.0, float(gross_margin))
    a = max(0.0, float(arpa_usd))
    if margin <= 0.0 or a <= 0.0:
        return 0.0
    churn = max(0.0, float(monthly_churn))
    if churn <= 0.0:
        return math.inf
    return a * margin / churn


def ltv_cac_ratio(ltv_usd: float, cac_usd: float) -> float | None:
    """LTV:CAC. None when CAC is unknown/zero (no acquisition spend recorded yet)."""
    cac = float(cac_usd)
    if cac <= 0.0:
        return None
    if ltv_usd == math.inf:
        return math.inf
    return max(0.0, float(ltv_usd)) / cac


def payback_months(cac_usd: float, arpa_usd: float, gross_margin: float) -> float | None:
    """
    Months to recover CAC from monthly gross profit (ARPA × margin). None when
    CAC is unknown; +inf when the account earns no gross profit (never pays back).
    """
    cac = float(cac_usd)
    if cac <= 0.0:
        return None
    monthly_gross = max(0.0, float(arpa_usd)) * max(0.0, float(gross_margin))
    if monthly_gross <= 0.0:
        return math.inf
    return cac / monthly_gross


@dataclass(frozen=True)
class UnitEconomics:
    arpa: float
    gross_margin: float
    monthly_logo_churn: float
    nrr: float
    ltv: float
    cac: float | None
    ltv_cac: float | None
    payback_months: float | None
    healthy: bool  # SMB target: LTV:CAC ≥ 3 AND payback ≤ 6 months


def unit_economics(
    mrr_total: float,
    active_accounts: int,
    gross_margin: float,
    starting_accounts: int,
    churned_accounts: int,
    starting_mrr: float,
    expansion_mrr: float,
    contraction_mrr: float,
    churned_mrr: float,
    cac_usd: float | None = None,
) -> UnitEconomics:
    """
    Bundle the SaaS unit-economics figures for one period. `cac_usd=None` (no
    acquisition spend recorded) leaves LTV:CAC / payback unknown rather than
    fabricating a ratio. `healthy` is the SMB benchmark from the plan:
    LTV:CAC ≥ 3 and payback ≤ 6 months (both required, both must be known).
    """
    a = arpa(mrr_total, active_accounts)
    margin = max(0.0, float(gross_margin))
    churn = logo_churn(churned_accounts, starting_accounts)
    nrr = net_revenue_retention(starting_mrr, expansion_mrr, contraction_mrr, churned_mrr)
    lv = ltv(a, margin, churn)

    cac = None if cac_usd is None else max(0.0, float(cac_usd))
    ratio = ltv_cac_ratio(lv, cac) if cac is not None else None
    payback = payback_months(cac, a, margin) if cac is not None else None

    healthy = (
        ratio is not None
        and ratio >= 3.0
        and payback is not None
        and payback <= 6.0
    )
    return UnitEconomics(
        arpa=a,
        gross_margin=margin,
        monthly_logo_churn=churn,
        nrr=nrr,
        ltv=lv,
        cac=cac,
        ltv_cac=ratio,
        payback_months=payback,
        healthy=healthy,
    )


# ── Resilient adapter (reads referral redemption counters) ────────────────────

def resolve_referral_k(referrer_tenant_ids: list[str], cohort_size: int) -> ViralCoefficient:
    """
    Compute K from the existing referral loop for a set of referrer tenants.

    `billing/referral.py` records only *successful redemptions*
    (`warden:ref:count:{tenant}` — a redemption is a new signup, i.e. an activated
    referral); invites-sent / acceptance aren't tracked separately. So this reads
    the terminal signal and reports the reduced form K = activated / cohort_size,
    with acceptance/activation folded to 1.0 (each counted event is a completed
    activation). Wire richer funnel counters later for the fully factored K.

    Error-swallowing: any read failure resolves to an all-zero coefficient (K=0,
    "dead") rather than raising — a missing metric must never break a caller.
    """
    activated = 0
    try:
        from warden.billing.referral import get_referral_stats

        for tid in referrer_tenant_ids:
            try:
                activated += int(get_referral_stats(tid).get("total_referrals", 0))
            except Exception as exc:  # one bad tenant must not sink the whole read
                log.debug("resolve_referral_k: stats read failed tenant=%s: %s", tid, exc)
    except Exception as exc:
        log.debug("resolve_referral_k resolved to empty (K=0): %s", exc)
        activated = 0

    # reduced form: each redemption is a completed activation of one invite
    return viral_coefficient(cohort_size, invites_sent=activated, accepted=activated, activated=activated)
