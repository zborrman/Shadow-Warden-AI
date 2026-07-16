"""
warden/reliability/budget.py  (FM-5)
────────────────────────────────────
Pure error-budget + burn-rate math for the uptime SLOs (docs/sla.md §2).

Nothing here does I/O. The monitor API supplies uptime percentages measured
over one or more windows (from the `probe_hourly` continuous aggregate) and
these functions turn them into:

  • an **error budget** — how much of the allowed monthly downtime is spent, and
    how many minutes remain, given a tier's SLA target; and
  • a **multiwindow burn-rate alert** — the Google SRE Workbook (table 5-4)
    model that pages only when a fast window AND a slow window both burn the
    budget faster than a threshold, so a single blip doesn't page but a real
    outage does.

Why this matters (FM-5): the 2026-07-15 tunnel outage burned most of a month's
Pro error budget and was invisible because nothing turned raw uptime into an
SLA signal. This module is that signal — additive, read-only, no security path.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# SLA monthly uptime targets by tier (fraction of the month). Source: docs/sla.md §2.
#   Pro        99.9%  → 43.8 min/month max downtime
#   Enterprise 99.95% → 21.9 min/month max downtime
SLA_TARGETS: dict[str, float] = {
    "pro": 0.999,
    "enterprise": 0.9995,
}
DEFAULT_SLA = 0.999

_MINUTES_PER_DAY = 1440.0


def sla_for_tier(tier: str) -> float:
    """SLA uptime target for a tier name (case-insensitive). Unknown → DEFAULT_SLA.

    Starter/Individual/Community have no uptime guarantee; callers that want a
    'no SLA' answer should not call this — it always returns a usable target so
    the budget math never divides by zero.
    """
    return SLA_TARGETS.get((tier or "").strip().lower(), DEFAULT_SLA)


def _clamp_pct(uptime_pct: float) -> float:
    """Clamp an uptime percentage to [0, 100]."""
    if math.isnan(uptime_pct):
        return 0.0
    return max(0.0, min(100.0, uptime_pct))


@dataclass(frozen=True)
class ErrorBudget:
    """Budget state for one SLA window."""

    sla_target: float
    window_minutes: float
    allowed_downtime_min: float
    observed_downtime_min: float
    consumed_fraction: float   # 0.0 = none spent, 1.0 = fully spent, >1 = breached
    remaining_minutes: float   # negative once the budget is blown
    exhausted: bool


def error_budget(
    uptime_pct: float,
    sla_target: float = DEFAULT_SLA,
    window_days: float = 30.0,
) -> ErrorBudget:
    """Compute the error budget for an observed uptime over a window.

    ``uptime_pct`` is 0–100 (clamped). ``sla_target`` is a fraction (0.999).
    A perfect month spends nothing; a month at exactly the SLA spends 100%.
    """
    uptime_frac = _clamp_pct(uptime_pct) / 100.0
    window_minutes = max(0.0, window_days) * _MINUTES_PER_DAY

    # A 100% (or higher) target leaves no budget: any downtime is a breach.
    allowed_downtime = max(0.0, (1.0 - sla_target)) * window_minutes
    observed_downtime = (1.0 - uptime_frac) * window_minutes

    if allowed_downtime > 0:
        consumed = observed_downtime / allowed_downtime
        # Relative tolerance: "exactly on SLA" spends the whole budget, but the
        # two (1 - x) subtractions differ by ~1e-8 in float, so a bare >= would
        # read the boundary as not-exhausted. 1e-6 is far tighter than any real
        # observation yet absorbs the float noise.
        exhausted = observed_downtime >= allowed_downtime * (1.0 - 1e-6)
    else:
        # A 100% (or higher) target leaves no budget at all — treat as exhausted.
        consumed = math.inf if observed_downtime > 0 else 0.0
        exhausted = True

    remaining = allowed_downtime - observed_downtime
    return ErrorBudget(
        sla_target=sla_target,
        window_minutes=window_minutes,
        allowed_downtime_min=round(allowed_downtime, 3),
        observed_downtime_min=round(observed_downtime, 3),
        consumed_fraction=round(consumed, 6) if math.isfinite(consumed) else consumed,
        remaining_minutes=round(remaining, 3),
        exhausted=exhausted,
    )


def burn_rate(uptime_pct: float, sla_target: float = DEFAULT_SLA) -> float:
    """How fast the budget is being consumed vs the sustainable rate.

    ``burn_rate = observed_error_rate / budgeted_error_rate``:
      • 1.0  → spending exactly at the sustainable rate (budget lasts the month);
      • 14.4 → 2% of a 30-day budget in 1h (the classic fast-burn page trigger);
      • 0.0  → perfect uptime.

    Returns ``inf`` when the SLA leaves no budget (target ≥ 100%) and there is
    any error at all.
    """
    error_rate = 1.0 - (_clamp_pct(uptime_pct) / 100.0)
    budget_rate = 1.0 - sla_target
    if budget_rate <= 0:
        return math.inf if error_rate > 0 else 0.0
    return error_rate / budget_rate


# Multiwindow, multi-burn-rate alert table (Google SRE Workbook, table 5-4).
# Each row: (severity, long_window, short_window, burn_threshold, budget_label).
# An alert fires only when BOTH windows burn at or above the threshold — the
# long window proves it's sustained, the short window proves it's still ongoing.
BURN_MULTIWINDOW: tuple[tuple[str, str, str, float, str], ...] = (
    ("page",   "1h", "5m",  14.4, "2% of budget in 1h"),
    ("page",   "6h", "30m",  6.0, "5% of budget in 6h"),
    ("ticket", "1d", "2h",   3.0, "10% of budget in 1d"),
    ("ticket", "3d", "6h",   1.0, "10% of budget in 3d"),
)


@dataclass(frozen=True)
class BurnAlert:
    """The most severe multiwindow burn-rate tier that is currently firing."""

    severity: str          # "page" | "ticket"
    burn_threshold: float
    long_window: str
    short_window: str
    long_burn: float
    short_burn: float
    label: str


def evaluate_burn_alert(
    windows: dict[str, float],
    sla_target: float = DEFAULT_SLA,
) -> BurnAlert | None:
    """Evaluate the multiwindow burn-rate table against measured uptimes.

    ``windows`` maps a window label ("5m", "1h", "6h", "1d", …) to the uptime
    percentage measured over that window. The most severe table row whose BOTH
    windows are present and burning ≥ threshold is returned; rows missing either
    window are skipped (the caller simply hasn't measured that window yet).
    Returns ``None`` when nothing is burning fast enough to alert.
    """
    for severity, long_w, short_w, threshold, label in BURN_MULTIWINDOW:
        if long_w not in windows or short_w not in windows:
            continue
        long_burn = burn_rate(windows[long_w], sla_target)
        short_burn = burn_rate(windows[short_w], sla_target)
        if long_burn >= threshold and short_burn >= threshold:
            return BurnAlert(
                severity=severity,
                burn_threshold=threshold,
                long_window=long_w,
                short_window=short_w,
                long_burn=round(long_burn, 3) if math.isfinite(long_burn) else long_burn,
                short_burn=round(short_burn, 3) if math.isfinite(short_burn) else short_burn,
                label=label,
            )
    return None
