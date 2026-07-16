"""
FinOps unified wallet availability (FM-1).

Before this module, "how much can this tenant spend right now?" had more than one
answer: the SAC preflight wallet computed `net = balance − hold` and ignored any
promotional or trial credit, while other surfaces counted credits differently.
FM-1 fixes the composition in ONE place:

    available = max(0, prepaid + trial + bonus − hold)

- **prepaid** — real money the tenant deposited (SAC wallet balance).
- **trial**   — time-limited trial credit granted at signup.
- **bonus**   — promotional / referral / goodwill credit.
- **hold**    — funds reserved by in-flight two-phase preflight holds.

`available_usd()` is the pure, authoritative formula. `resolve_wallet()` is a
resilient adapter that assembles the four components from their existing stores
(prepaid+hold from `sac.preflight`, trial/bonus from optional grant keys that
default to 0) so a gate anywhere gets the same number — and so promo/trial
credit, once granted, is spendable everywhere without touching each call site.

Amounts are USD rounded to micro precision (6 dp), matching the preflight ledger.
Spend order (`spend_breakdown`) draws free money first — bonus, then trial, then
prepaid — so a tenant's paid balance is preserved for last.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger(__name__)

_MICRO = 6  # decimal places (micro-USD precision, matches sac.preflight)


def _round(usd: float) -> float:
    return round(float(usd), _MICRO)


def available_usd(prepaid: float, trial: float, bonus: float, hold: float) -> float:
    """
    The one authoritative availability formula: spendable = funding − holds,
    never negative. Each funding component is floored at 0 so a malformed
    negative grant can't silently eat real balance.
    """
    funding = max(0.0, prepaid) + max(0.0, trial) + max(0.0, bonus)
    return _round(max(0.0, funding - max(0.0, hold)))


@dataclass(frozen=True)
class WalletComponents:
    prepaid_usd: float
    trial_usd: float
    bonus_usd: float
    hold_usd: float

    @property
    def funding_usd(self) -> float:
        return _round(max(0.0, self.prepaid_usd) + max(0.0, self.trial_usd) + max(0.0, self.bonus_usd))

    @property
    def available_usd(self) -> float:
        return available_usd(self.prepaid_usd, self.trial_usd, self.bonus_usd, self.hold_usd)

    @property
    def is_funded(self) -> bool:
        return self.available_usd > 0.0

    def as_dict(self) -> dict:
        return {
            "prepaid_usd": _round(self.prepaid_usd),
            "trial_usd": _round(self.trial_usd),
            "bonus_usd": _round(self.bonus_usd),
            "hold_usd": _round(self.hold_usd),
            "funding_usd": self.funding_usd,
            "available_usd": self.available_usd,
            "is_funded": self.is_funded,
        }


def spend_breakdown(components: WalletComponents, charge_usd: float) -> dict:
    """
    How a `charge_usd` would be drawn across buckets, free money first
    (bonus → trial → prepaid). Pure — computes the split without mutating any
    store. `uncovered_usd > 0` means the charge exceeds availability.
    """
    remaining = max(0.0, float(charge_usd))
    draw: dict[str, float] = {}
    for name, amount in (
        ("bonus", components.bonus_usd),
        ("trial", components.trial_usd),
        ("prepaid", components.prepaid_usd),
    ):
        take = min(remaining, max(0.0, amount))
        draw[name] = _round(take)
        remaining = _round(remaining - take)
    return {
        "charge_usd": _round(max(0.0, float(charge_usd))),
        "from_bonus_usd": draw["bonus"],
        "from_trial_usd": draw["trial"],
        "from_prepaid_usd": draw["prepaid"],
        "uncovered_usd": _round(remaining),
        "fully_covered": remaining <= 0.0,
    }


# ── resilient adapters (compose from existing stores) ─────────────────────────

def _grant_usd(tenant_id: str, kind: str) -> float:
    """
    Read a promotional/trial dollar grant from its Redis key
    (`finops:grant:{kind}:{tenant_id}`). Returns 0.0 when unset or on any error —
    a missing grant store must never block or inflate a wallet.
    """
    try:
        import redis as _redis

        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return 0.0
        client = _redis.from_url(url, decode_responses=True, socket_connect_timeout=5, socket_timeout=3)
        val = client.get(f"finops:grant:{kind}:{tenant_id}")
        return max(0.0, float(str(val))) if val is not None else 0.0
    except Exception as exc:
        log.debug("grant lookup (%s) resolved to 0: %s", kind, exc)
        return 0.0


def resolve_wallet(tenant_id: str) -> WalletComponents:
    """
    Assemble the unified wallet for a tenant from its live sources. Resilient:
    any unavailable source contributes 0 rather than raising, so availability
    degrades to whatever funding *can* be read (never to a false "funded").
    """
    prepaid = 0.0
    hold = 0.0
    try:
        from warden.sac.preflight import get_wallet

        w = get_wallet(tenant_id)
        prepaid = float(w.get("balance_usd", 0.0))
        hold = float(w.get("hold_usd", 0.0))
    except Exception as exc:
        log.debug("preflight wallet read resolved to 0 for %s: %s", tenant_id, exc)

    return WalletComponents(
        prepaid_usd=prepaid,
        trial_usd=_grant_usd(tenant_id, "trial"),
        bonus_usd=_grant_usd(tenant_id, "bonus"),
        hold_usd=hold,
    )


def resolve_available_usd(tenant_id: str) -> float:
    """Convenience: the single spendable number for a tenant, all sources composed."""
    return resolve_wallet(tenant_id).available_usd
