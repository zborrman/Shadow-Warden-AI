"""
warden/billing/referral.py
──────────────────────────
Referral flywheel for Shadow Warden AI.

Mechanics
─────────
  • Any tenant on Starter / Individual / Pro can generate a referral code.
  • Enterprise tenants are excluded (referral_program=False in TIER_LIMITS).
  • When a new tenant redeems a valid code during signup, both parties receive
    bonus requests credited to their monthly quota for the current month.

Bonus amounts (from TIER_LIMITS["referral_bonus_requests"])
────────────────────────────────────────────────────────────
  Starter:    +  500 req / referral (for the referred tenant)
  Individual: +  500 req / referral
  Pro:        +2 000 req / referral
  Enterprise: referral_program=False — no code generation allowed

Redis key layout
────────────────
  warden:ref:code:{CODE}         → JSON  (90-day TTL, deleted on redemption)
  warden:ref:count:{tenant_id}   → INT   (lifetime referrals made, no TTL)
  warden:ref:bonus:{tenant_id}:{YYYY-MM} → INT  (bonus requests this month, 35d TTL)

Thread-safe: all Redis ops are atomic (SETEX / INCR / GETDEL).
Fail-open: Redis errors degrade gracefully — codes stored in-memory fallback.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime

log = logging.getLogger("warden.billing.referral")

# In-memory fallback for dev/test environments without Redis.
_CODE_STORE: dict[str, str] = {}

_CODE_TTL = 90 * 86400   # 90 days
_BONUS_TTL = 35 * 86400  # ~1 month + 3 days


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    """Return a sync Redis client (None if unavailable)."""
    try:
        import redis as _r
        from warden.config import settings
        return _r.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=1,
        )
    except Exception:
        return None


def _month_key_suffix() -> str:
    return datetime.now(UTC).strftime("%Y-%m")


# ── Code generation ───────────────────────────────────────────────────────────

def generate_referral_code(tenant_id: str, plan: str) -> str:
    """
    Generate a unique referral code for *tenant_id*.

    Returns
    -------
    str  — REF-XXXXXXXX  (8 uppercase hex chars)

    Raises
    ------
    PermissionError  — if the tenant's plan has referral_program=False (Enterprise)
    """
    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    tier    = _normalize_tier(plan)
    limits  = TIER_LIMITS.get(tier, TIER_LIMITS["starter"])
    if not limits.get("referral_program", True):
        raise PermissionError(
            f"Referral program is not available on the {tier.upper()} plan."
        )

    code    = f"REF-{uuid.uuid4().hex[:8].upper()}"
    payload = json.dumps({
        "tenant_id":  tenant_id,
        "plan":       tier,
        "created_at": datetime.now(UTC).isoformat(),
    })

    r = _redis()
    if r is not None:
        try:
            r.setex(f"warden:ref:code:{code}", _CODE_TTL, payload)
        except Exception as exc:
            log.debug("referral: Redis SETEX error: %s", exc)
            _CODE_STORE[code] = payload
    else:
        _CODE_STORE[code] = payload

    log.info("referral: generated code=%s tenant=%s plan=%s", code, tenant_id, tier)
    return code


# ── Code redemption ───────────────────────────────────────────────────────────

def redeem_referral_code(code: str, new_tenant_id: str) -> dict:
    """
    Redeem a referral code for a new tenant.

    Credits bonus requests to both the referrer (based on their plan) and the
    new tenant (fixed +500 req welcome bonus regardless of tier).

    Returns
    -------
    {
      "referrer_tenant_id": str,
      "referrer_plan":      str,
      "referrer_bonus_req": int,
      "new_tenant_bonus_req": int,
      "code":               str,
    }

    Raises
    ------
    ValueError  — code is invalid, expired, or already used
    ValueError  — self-referral attempt
    """
    r       = _redis()
    raw_key = f"warden:ref:code:{code}"
    raw     = None

    if r is not None:
        try:
            raw = r.getdel(raw_key)
        except Exception as exc:
            log.debug("referral: Redis GETDEL error: %s", exc)
    else:
        raw = _CODE_STORE.pop(code, None)

    if not raw:
        raise ValueError(
            f"Referral code {code!r} is invalid, expired, or already used."
        )

    data        = json.loads(raw)
    referrer_id = data["tenant_id"]
    referrer_plan = data.get("plan", "starter")

    if referrer_id == new_tenant_id:
        # Put code back so it's not consumed
        if r is not None:
            try:
                r.setex(raw_key, _CODE_TTL, raw)
            except Exception:
                pass
        else:
            _CODE_STORE[code] = raw
        raise ValueError("Self-referral is not allowed.")

    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    tier   = _normalize_tier(referrer_plan)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["starter"])
    referrer_bonus = limits.get("referral_bonus_requests", 500)
    new_tenant_bonus = 500  # welcome bonus for the new signup

    month = _month_key_suffix()
    _credit_bonus(referrer_id, referrer_bonus, r, month)
    _credit_bonus(new_tenant_id, new_tenant_bonus, r, month)
    _increment_referral_count(referrer_id, r)

    log.info(
        "referral: redeemed code=%s referrer=%s (bonus=%d) new=%s (bonus=%d)",
        code, referrer_id, referrer_bonus, new_tenant_id, new_tenant_bonus,
    )
    return {
        "referrer_tenant_id":   referrer_id,
        "referrer_plan":        tier,
        "referrer_bonus_req":   referrer_bonus,
        "new_tenant_bonus_req": new_tenant_bonus,
        "code":                 code,
    }


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_referral_stats(tenant_id: str) -> dict:
    """
    Return referral statistics for *tenant_id*.

    {
      "tenant_id":         str,
      "total_referrals":   int,
      "bonus_req_this_month": int,
    }
    """
    r     = _redis()
    month = _month_key_suffix()
    total = 0
    bonus = 0

    if r is not None:
        try:
            raw_total = r.get(f"warden:ref:count:{tenant_id}")
            raw_bonus = r.get(f"warden:ref:bonus:{tenant_id}:{month}")
            total = int(raw_total) if raw_total else 0
            bonus = int(raw_bonus) if raw_bonus else 0
        except Exception as exc:
            log.debug("referral: Redis stats error: %s", exc)

    return {
        "tenant_id":            tenant_id,
        "total_referrals":      total,
        "bonus_req_this_month": bonus,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _credit_bonus(tenant_id: str, bonus_req: int, r, month: str) -> None:
    """Atomically credit bonus requests for this month."""
    if r is None or bonus_req <= 0:
        return
    key = f"warden:ref:bonus:{tenant_id}:{month}"
    try:
        new_total = r.incrby(key, bonus_req)
        if new_total == bonus_req:
            r.expire(key, _BONUS_TTL)
    except Exception as exc:
        log.debug("referral: bonus credit error tenant=%s: %s", tenant_id, exc)


def _increment_referral_count(tenant_id: str, r) -> None:
    """Increment the lifetime referral counter for the referrer."""
    if r is None:
        return
    try:
        r.incr(f"warden:ref:count:{tenant_id}")
    except Exception as exc:
        log.debug("referral: count INCR error tenant=%s: %s", tenant_id, exc)


def get_bonus_requests(tenant_id: str) -> int:
    """
    Return total bonus requests credited to *tenant_id* for the current month.
    Used by quota_middleware to extend the effective limit.
    """
    r     = _redis()
    month = _month_key_suffix()
    if r is None:
        return 0
    try:
        raw = r.get(f"warden:ref:bonus:{tenant_id}:{month}")
        return int(raw) if raw else 0
    except Exception:
        return 0
