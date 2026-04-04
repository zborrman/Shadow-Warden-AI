"""
warden/api/tenant_impact.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
GET /tenant/impact — Dollar Impact Calculator scoped to the authenticated tenant.

Identical math to /financial/impact but filtered to the calling tenant's
traffic only, so a customer sees their own ROI — not the platform aggregate.

Auth
────
  Bearer <oidc_id_token>  — Warden Identity (Google / Microsoft)
  X-API-Key               — classic API key (tenant_id from AuthResult)

Response shape (pruned for client-side dashboard widget)
────────────────────────────────────────────────────────
  {
    "tenant_id":           "acme",
    "period_days":         30,
    "generated_at":        "2026-04-04T12:00:00+00:00",

    // ── Live counters ──────────────────────────────────
    "requests_total":      4821,
    "requests_blocked":    312,
    "requests_allowed":    4509,
    "pii_masked":          87,
    "block_rate_pct":      6.47,

    // ── Dollar Impact ──────────────────────────────────
    "dollar_saved":        31200,   // blocks × COST_PER_INCIDENT_USD
    "inference_saved_usd": 0.624,   // shadow-ban inference cost avoided
    "annual_projection":   374400,  // dollar_saved × (365/period_days)

    // ── Threat breakdown ───────────────────────────────
    "top_threats": [
      {"label": "Prompt Injection", "count": 143, "pct": 45.8},
      ...
    ],

    // ── Timeline (sparkline data — one bucket per day) ─
    "timeline": [
      {"date": "2026-03-05", "requests": 160, "blocked": 11, "pii": 3},
      ...
    ],

    // ── Subscription context ───────────────────────────
    "plan":                "startup",
    "quota":               50000,
    "rate_limit_per_min":  60,
    "quota_used_pct":      9.64,
  }
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query

from warden.auth_guard import AuthResult, require_ext_auth

log = logging.getLogger("warden.api.tenant_impact")

router = APIRouter(prefix="/tenant", tags=["Tenant Impact"])

# IBM Cost of a Data Breach Report 2024: $4.88 M average / ~265 incidents
# = ~$18 400 per incident.  We use a conservative $100 per blocked request
# as the "prevented cost" to avoid overselling.  Configurable via env var.
COST_PER_INCIDENT_USD: float = float(
    os.getenv("IMPACT_COST_PER_BLOCK_USD", "100.0")
)

# Flag → human-readable threat label
_FLAG_LABELS: dict[str, str] = {
    "prompt_injection":        "Prompt Injection",
    "jailbreak":               "Jailbreak Attempt",
    "pii_detected":            "PII Detected",
    "secret_detected":         "Secret / Credential Leak",
    "data_exfiltration":       "Data Exfiltration",
    "policy_violation":        "Policy Violation",
    "toxicity":                "Toxic Content",
    "shadow_banned":           "Shadow-Banned Entity",
    "ip_blocked":              "IP Blocklist Hit",
    "session_anomaly":         "Session Anomaly",
    "worm_attempt":            "Zero-Click Worm Attempt",
    "adversarial_suffix":      "Adversarial Suffix",
    "encoded_payload":         "Encoded Payload",
    "indirect_injection":      "Indirect Injection",
    "rag_poisoning":           "RAG Poisoning Attempt",
}


def _label(flag: str) -> str:
    return _FLAG_LABELS.get(flag, flag.replace("_", " ").title())


def _build_impact(
    tenant_id: str,
    period_days: int,
) -> dict:
    """
    Read logs.json, filter to tenant_id + period, compute impact metrics.
    Fail-open: returns zeroed dict on any I/O error.
    """
    from warden.analytics import logger as event_logger  # noqa: PLC0415

    try:
        entries = event_logger.load_entries(days=period_days)
    except Exception as exc:
        log.warning("tenant_impact: load_entries failed: %s", exc)
        entries = []

    # ── Filter to this tenant ─────────────────────────────────────────────────
    entries = [
        e for e in entries
        if e.get("tenant_id", "default") == tenant_id
    ]

    total    = len(entries)
    blocked  = sum(1 for e in entries if not e.get("allowed", True))
    allowed  = total - blocked
    pii      = sum(1 for e in entries if e.get("masked", False))
    block_pct = round(blocked / total * 100, 2) if total else 0.0

    # ── Dollar impact ─────────────────────────────────────────────────────────
    dollar_saved      = blocked * COST_PER_INCIDENT_USD
    inference_saved   = sum(e.get("attack_cost_usd", 0.0) for e in entries
                            if e.get("shadow_banned"))
    annual_projection = round(dollar_saved * (365 / max(period_days, 1)), 2)

    # ── Threat breakdown ──────────────────────────────────────────────────────
    flag_counts: dict[str, int] = defaultdict(int)
    for e in entries:
        if not e.get("allowed", True):
            for flag in e.get("flags", []):
                flag_counts[flag] += 1

    total_flags = sum(flag_counts.values()) or 1
    top_threats = sorted(
        [
            {
                "flag":  flag,
                "label": _label(flag),
                "count": count,
                "pct":   round(count / total_flags * 100, 1),
            }
            for flag, count in flag_counts.items()
        ],
        key=lambda x: -x["count"],
    )[:8]

    # ── Timeline (daily buckets) ──────────────────────────────────────────────
    now    = datetime.now(UTC)
    cutoff = now - timedelta(days=period_days)

    day_buckets: dict[str, dict] = {}
    for d in range(period_days):
        day = (cutoff + timedelta(days=d + 1)).strftime("%Y-%m-%d")
        day_buckets[day] = {"date": day, "requests": 0, "blocked": 0, "pii": 0}

    for e in entries:
        try:
            ts  = datetime.fromisoformat(e.get("ts", ""))
            day = ts.strftime("%Y-%m-%d")
        except ValueError:
            continue
        if day in day_buckets:
            day_buckets[day]["requests"] += 1
            if not e.get("allowed", True):
                day_buckets[day]["blocked"] += 1
            if e.get("masked"):
                day_buckets[day]["pii"] += 1

    timeline = list(day_buckets.values())

    # ── Subscription context ──────────────────────────────────────────────────
    plan             = "free"
    quota: int | None = 1_000
    rate_limit       = 10
    quota_used_pct   = 0.0

    try:
        from warden.stripe_billing import get_stripe_billing  # noqa: PLC0415
        billing      = get_stripe_billing()
        plan         = billing.get_plan(tenant_id)
        quota        = billing.get_quota(tenant_id)
        rate_limit   = billing.get_rate_limit_per_minute(tenant_id)
        if quota:
            quota_used_pct = round(total / quota * 100, 2)
    except Exception as exc:
        log.debug("tenant_impact: billing lookup failed (non-fatal): %s", exc)

    return {
        "tenant_id":          tenant_id,
        "period_days":        period_days,
        "generated_at":       now.isoformat(),
        # counters
        "requests_total":     total,
        "requests_blocked":   blocked,
        "requests_allowed":   allowed,
        "pii_masked":         pii,
        "block_rate_pct":     block_pct,
        # dollar impact
        "dollar_saved":       round(dollar_saved, 2),
        "inference_saved_usd": round(inference_saved, 4),
        "annual_projection":  annual_projection,
        # breakdown
        "top_threats":        top_threats,
        "timeline":           timeline,
        # subscription
        "plan":               plan,
        "quota":              quota,
        "rate_limit_per_min": rate_limit,
        "quota_used_pct":     quota_used_pct,
    }


@router.get("/impact")
async def tenant_impact(
    period: int       = Query(30, ge=1, le=90, description="Lookback window in days (1–90)"),
    auth:   AuthResult = Depends(require_ext_auth),
) -> dict:
    """
    Dollar Impact Calculator — filtered to the authenticated tenant.

    Returns live ROI metrics: blocks, PII intercepts, dollar value saved,
    threat breakdown, daily sparkline, and subscription quota status.

    Designed to be polled by the browser extension popup (every 5 minutes)
    and embedded in customer-facing portals without a separate BI tool.
    """
    return _build_impact(tenant_id=auth.tenant_id, period_days=period)
