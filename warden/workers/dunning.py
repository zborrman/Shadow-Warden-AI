"""
warden/workers/dunning.py
──────────────────────────
ARQ worker: subscription dunning processor.

Runs every 12 hours (06:00 and 18:00 UTC). Finds tenants in 'past_due'
status whose updated_at is older than DUNNING_GRACE_DAYS (default 7).
Downgrades them to 'starter' and alerts Slack.

Grace period flow
─────────────────
  Day 0  — payment fails → lemon_billing marks status='past_due'
  Day 1–7 — Lemon Squeezy retries charge (its own dunning emails)
  Day 7+  — this worker downgrades to starter and notifies Slack
  Day 8+  — if customer renews, next subscription_created webhook re-activates

Environment variables
─────────────────────
  DUNNING_GRACE_DAYS  — grace days before forced downgrade (default 7)
  SLACK_WEBHOOK_URL   — optional alert destination
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

log = logging.getLogger("warden.workers.dunning")

_GRACE_DAYS = int(os.getenv("DUNNING_GRACE_DAYS", "7"))


async def _slack(msg: str) -> None:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            await c.post(webhook, json={"text": msg})
    except Exception as exc:
        log.warning("dunning: slack alert failed: %s", exc)


async def process_dunning(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    ARQ job: downgrade past_due subscriptions past the grace period.
    """
    ts     = datetime.now(UTC).isoformat()
    cutoff = (datetime.now(UTC) - timedelta(days=_GRACE_DAYS)).isoformat()

    try:
        from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
        billing    = get_lemon_billing()
        downgraded = billing.expire_past_due(cutoff)
    except Exception as exc:
        log.warning("dunning: lemon_billing unavailable: %s", exc)
        return {"ts": ts, "error": str(exc), "downgraded": 0}

    if downgraded:
        names = ", ".join(f"`{d['tenant_id']}`" for d in downgraded[:5])
        extra = f" (+{len(downgraded) - 5} more)" if len(downgraded) > 5 else ""
        await _slack(
            f":money_with_wings: *Dunning* — {len(downgraded)} subscription(s) "
            f"downgraded to *starter* after {_GRACE_DAYS}-day grace period.\n"
            f"Tenants: {names}{extra}\n"
            f"_Customer re-activation: /billing/upgrade_"
        )
        log.info("dunning: downgraded %d subscriptions (cutoff=%s).", len(downgraded), cutoff[:10])
    else:
        log.info("dunning: no delinquent subscriptions found.")

    return {
        "ts":         ts,
        "grace_days": _GRACE_DAYS,
        "downgraded": len(downgraded),
        "tenants":    [d["tenant_id"] for d in downgraded],
    }
