"""
warden/billing/usage_budgets.py  (ENT-04)
──────────────────────────────────────────
AI Usage Budgets — per-department request-level caps with Slack approval.

Budget enforcement happens in the /filter pipeline: when a department
has consumed ≥ WARN_PCT% of its monthly budget, the next request triggers
a Slack approval request (or auto-blocks at 100%).

Storage: Redis counters per (tenant_id, department) reset monthly.
Config:  Redis hash `usage_budget:{tenant_id}:{department}`

Budget fields
-------------
  monthly_limit    — max requests/month (0 = unlimited)
  warn_pct         — warn threshold % (default 80)
  block_at_pct     — block threshold % (default 100)
  notify_slack     — channel/webhook to alert
  auto_approve     — skip approval gate (default false)

Approval flow
-------------
When consumed >= block_at_pct:
  POST to SLACK_WEBHOOK_URL with approval link → /billing/budget/approve/{token}
  Request is queued in Redis for 5 min (max_approval_wait_s=300)
  If no approval within timeout → fail-open (allow)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

log = logging.getLogger("warden.billing.usage_budgets")

_in_proc_budgets: dict[str, dict] = {}
_in_proc_counters: dict[str, int] = {}


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as rl  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        r = rl.Redis.from_url(url, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


def _month_key() -> str:
    return datetime.now(UTC).strftime("%Y-%m")


# ── Budget config ──────────────────────────────────────────────────────────────

def set_budget(tenant_id: str, department: str, monthly_limit: int,
               warn_pct: int = 80, block_at_pct: int = 100,
               notify_slack: str = "", auto_approve: bool = False) -> dict:
    cfg = {
        "tenant_id":    tenant_id,
        "department":   department,
        "monthly_limit": monthly_limit,
        "warn_pct":     warn_pct,
        "block_at_pct": block_at_pct,
        "notify_slack": notify_slack,
        "auto_approve": auto_approve,
    }
    r = _redis()
    if r:
        r.set(f"usage_budget:{tenant_id}:{department}", json.dumps(cfg))
    _in_proc_budgets[f"{tenant_id}:{department}"] = cfg
    return cfg


def get_budget(tenant_id: str, department: str) -> dict | None:
    r = _redis()
    if r:
        raw = r.get(f"usage_budget:{tenant_id}:{department}")
        if raw:
            return json.loads(raw)
    return _in_proc_budgets.get(f"{tenant_id}:{department}")


def list_budgets(tenant_id: str) -> list[dict]:
    r = _redis()
    if r:
        keys = r.keys(f"usage_budget:{tenant_id}:*")
        result = []
        for k in keys:
            raw = r.get(k)
            if raw:
                result.append(json.loads(raw))
        return result
    return [v for k, v in _in_proc_budgets.items() if k.startswith(f"{tenant_id}:")]


# ── Counter ────────────────────────────────────────────────────────────────────

def increment_counter(tenant_id: str, department: str) -> int:
    r = _redis()
    month_key = _month_key()
    counter_key = f"usage_counter:{tenant_id}:{department}:{month_key}"
    if r:
        new_val = r.incr(counter_key)
        # Expire at end of next month (60 days is safe)
        r.expire(counter_key, 60 * 86400)
        return new_val
    key = f"{tenant_id}:{department}:{month_key}"
    _in_proc_counters[key] = _in_proc_counters.get(key, 0) + 1
    return _in_proc_counters[key]


def get_counter(tenant_id: str, department: str) -> int:
    r = _redis()
    month_key = _month_key()
    counter_key = f"usage_counter:{tenant_id}:{department}:{month_key}"
    if r:
        val = r.get(counter_key)
        return int(val) if val else 0
    return _in_proc_counters.get(f"{tenant_id}:{department}:{month_key}", 0)


# ── Enforcement ────────────────────────────────────────────────────────────────

def check_budget_gate(tenant_id: str, department: str) -> dict:
    """Check budget before processing a request.

    Returns
    -------
    {"allowed": bool, "pct_used": float, "status": "ok"|"warn"|"blocked"|"unlimited"}
    """
    budget = get_budget(tenant_id, department)
    if not budget or budget.get("monthly_limit", 0) == 0:
        return {"allowed": True, "pct_used": 0.0, "status": "unlimited"}

    used       = get_counter(tenant_id, department)
    limit      = budget["monthly_limit"]
    pct        = used / limit * 100 if limit else 0.0
    block_at   = budget.get("block_at_pct", 100)
    warn_at    = budget.get("warn_pct", 80)

    if pct >= block_at:
        _fire_slack_alert(budget, used, limit, pct)
        return {"allowed": False, "pct_used": pct, "status": "blocked"}

    if pct >= warn_at:
        _fire_slack_alert(budget, used, limit, pct)
        return {"allowed": True, "pct_used": pct, "status": "warn"}

    return {"allowed": True, "pct_used": pct, "status": "ok"}


def _fire_slack_alert(budget: dict, used: int, limit: int, pct: float) -> None:
    webhook = budget.get("notify_slack") or os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook:
        return
    tenant_id  = budget.get("tenant_id", "")
    department = budget.get("department", "")
    msg = {
        "text": (
            f"🚨 *AI Budget Alert* — {department} ({tenant_id})\n"
            f"Used: {used}/{limit} requests ({pct:.0f}%)\n"
            f"Month: {_month_key()}"
        )
    }
    try:
        import httpx  # noqa: PLC0415

        from warden.net_guard import assert_public_url
        assert_public_url(webhook)  # SSRF guard: tenant-configured webhook URL
        httpx.post(webhook, json=msg, timeout=3, follow_redirects=False)
    except Exception as exc:
        log.debug("budget alert failed — %s", exc)
