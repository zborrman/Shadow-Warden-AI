"""
warden/billing/overage.py
──────────────────────────
Overage billing — automatic charge triggers when quotas are exceeded.

Strategy per tier
─────────────────
  Individual ($5/mo)
    Hard stop — no overage. HTTP 402 with upgrade link.
    Upsell: "Upgrade to Business for 10× storage and file sharing."

  Business ($49/mo)
    Soft limit — overage enabled. No service interruption.
    Charges: +$5.00 per 50 GB storage OR bandwidth pack (auto-charged).
    Stripe invoice line item: "Storage Overage — {N} GB" / "Bandwidth Overage".

  MCP ($199/mo)
    Soft limit — overage enabled at lower unit price ($0.04/GB).
    Expansion pack: +$40.00 per 1 TB storage block (purchasable in advance).
    Stripe invoice line item metered billing via usage records.

Referral Growth Mechanics
──────────────────────────
  Individual referral: +2 GB storage for referrer + referee (Dropbox model).
  Referral code stored in Redis + SQLite with referrer's community_id.
  apply_referral() validates code, calls quota.apply_referral_bonus() for both.

Compliance upsell copy (EU/US market)
──────────────────────────────────────
  GDPR Art. 32 requires "appropriate technical measures" for personal data.
  CCPA fines: up to $7,500 per intentional violation.
  WhatsApp Business API: data goes to Meta servers — non-compliant for PII.
  Pitch: "E2EE Business tunnel for $49/mo vs. €20M GDPR fine."

Integration points
──────────────────
  Stripe:  create_overage_invoice_item(tenant_id, metric, gb, stripe_customer_id)
  Paddle:  create_paddle_charge(tenant_id, amount_cents, description)
  Webhook: fire_overage_webhook(community_id, metric, used, limit) — for portals
           that handle billing outside Warden (e.g. resellers).
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime

log = logging.getLogger("warden.billing.overage")

# Overage webhook URL (optional — for external billing systems)
OVERAGE_WEBHOOK_URL: str = os.getenv("OVERAGE_WEBHOOK_URL", "")

# Stripe secret key (reuses existing STRIPE_SECRET_KEY env var)
STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")

# Paddle API key (reuses existing PADDLE_API_KEY env var)
PADDLE_API_KEY: str = os.getenv("PADDLE_API_KEY", "")


# ── Overage event record ──────────────────────────────────────────────────────

def _log_overage_event(
    community_id: str,
    tenant_id:    str,
    tier:         str,
    metric:       str,
    used_bytes:   int,
    limit_bytes:  int,
    action:       str,
) -> None:
    """Write overage event to warden audit log."""
    log.warning(
        "OVERAGE tier=%s community=%s metric=%s used=%d limit=%d action=%s",
        tier, community_id[:8], metric, used_bytes, limit_bytes, action,
    )


# ── Overage resolution ────────────────────────────────────────────────────────

def resolve_overage(
    community_id: str,
    tenant_id:    str,
    tier:         str,
    metric:       str,
    used_bytes:   int,
    limit_bytes:  int,
    stripe_customer_id: str | None = None,
    paddle_subscription_id: str | None = None,
) -> dict:
    """
    Handle a quota overage event.

    Flow:
      1. Log the event.
      2. Fire webhook if configured (external billing systems).
      3. Create Stripe invoice item if customer ID provided.
      4. Create Paddle charge if subscription ID provided.
      5. Return resolution dict with billing_ref for the caller.

    Returns
    ──────
    {
      "action":      "overage_charged" | "webhook_fired" | "logged_only",
      "metric":      "storage" | "bandwidth",
      "overage_gb":  float,
      "amount_cents": int,
      "billing_ref": str | None,
    }
    """
    from warden.billing.feature_gate import OVERAGE_PRICES, _normalize_tier
    prices    = OVERAGE_PRICES.get(_normalize_tier(tier), {})
    overage_b = max(0, used_bytes - limit_bytes)
    overage_gb = overage_b / (1024 ** 3)

    price_key   = f"{metric}_cents_per_gb"
    cents_per_gb = prices.get(price_key, 10)
    amount_cents = max(1, int(overage_gb * cents_per_gb))

    description = (
        f"Warden {tier.upper()} Overage — {metric} {overage_gb:.2f} GB "
        f"@ ${cents_per_gb/100:.2f}/GB"
    )

    _log_overage_event(community_id, tenant_id, tier, metric, used_bytes, limit_bytes, "charge")

    billing_ref: str | None = None

    # ── Stripe ────────────────────────────────────────────────────────────────
    if stripe_customer_id and STRIPE_SECRET_KEY:
        billing_ref = _create_stripe_invoice_item(
            stripe_customer_id, amount_cents, description
        )
        if billing_ref:
            _fire_overage_webhook(community_id, metric, overage_gb, amount_cents, "stripe")
            return {
                "action":       "overage_charged",
                "metric":       metric,
                "overage_gb":   round(overage_gb, 3),
                "amount_cents": amount_cents,
                "billing_ref":  billing_ref,
            }

    # ── Paddle ────────────────────────────────────────────────────────────────
    if paddle_subscription_id and PADDLE_API_KEY:
        billing_ref = _create_paddle_charge(
            paddle_subscription_id, amount_cents, description
        )
        if billing_ref:
            _fire_overage_webhook(community_id, metric, overage_gb, amount_cents, "paddle")
            return {
                "action":       "overage_charged",
                "metric":       metric,
                "overage_gb":   round(overage_gb, 3),
                "amount_cents": amount_cents,
                "billing_ref":  billing_ref,
            }

    # ── Webhook only ──────────────────────────────────────────────────────────
    if OVERAGE_WEBHOOK_URL:
        _fire_overage_webhook(community_id, metric, overage_gb, amount_cents, "webhook")
        return {
            "action":       "webhook_fired",
            "metric":       metric,
            "overage_gb":   round(overage_gb, 3),
            "amount_cents": amount_cents,
            "billing_ref":  None,
        }

    # ── Log only (dev/test) ───────────────────────────────────────────────────
    return {
        "action":       "logged_only",
        "metric":       metric,
        "overage_gb":   round(overage_gb, 3),
        "amount_cents": amount_cents,
        "billing_ref":  None,
    }


def get_upgrade_url(tier: str, metric: str) -> str:
    """
    Return upgrade CTA URL for hard-quota 402 responses.

    In production this would link to the Stripe/Paddle checkout for the
    next tier. Returns a portal-relative URL by default.
    """
    next_tier = "business" if tier == "individual" else "mcp"
    base_url  = os.getenv("PORTAL_BASE_URL", "https://app.shadowwarden.ai")
    return f"{base_url}/billing/upgrade?from={tier}&to={next_tier}&reason={metric}"


def get_overage_pack_url(tier: str, metric: str) -> str:
    """
    Return URL to purchase an overage expansion pack.

    Business: $5 for 50 GB.  MCP: $40 for 1 TB.
    """
    base_url = os.getenv("PORTAL_BASE_URL", "https://app.shadowwarden.ai")
    return f"{base_url}/billing/overage-pack?tier={tier}&metric={metric}"


# ── Referral system ───────────────────────────────────────────────────────────

def generate_referral_code(community_id: str, referrer_member_id: str) -> str:
    """
    Generate a unique referral code for a community member.

    Code format: REF-{8 hex chars} — short enough for sharing.
    Stored in Redis with 90-day TTL (fail-open in dev without Redis).
    """
    code = f"REF-{uuid.uuid4().hex[:8].upper()}"
    payload = json.dumps({
        "community_id":      community_id,
        "referrer_member_id": referrer_member_id,
        "created_at":        datetime.now(UTC).isoformat(),
    })
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            r.setex(f"warden:referral:{code}", 90 * 86400, payload)
    except Exception as exc:
        log.debug("overage: referral code Redis error: %s", exc)

    log.info("overage: referral code generated code=%s community=%s", code, community_id[:8])
    return code


def apply_referral(
    referral_code:  str,
    new_community_id: str,
) -> dict:
    """
    Redeem a referral code when a new user signs up.

    Awards referral_bonus_bytes to both the referrer's community and the
    new community.  Code is deleted from Redis after use (one-time use).

    Returns {"referrer_community_id": ..., "bonus_bytes": ..., "code": ...}
    or raises ValueError if code invalid/expired/already used.
    """
    payload_raw = None
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            payload_raw = r.getdel(f"warden:referral:{referral_code}")
    except Exception as exc:
        log.debug("overage: referral Redis error: %s", exc)

    if not payload_raw:
        raise ValueError(f"Referral code {referral_code!r} is invalid, expired, or already used.")

    data = json.loads(payload_raw)
    referrer_cid = data["community_id"]

    from warden.communities.quota import apply_referral_bonus
    # Bonus for referrer
    apply_referral_bonus(referrer_cid, data["referrer_member_id"])
    # Bonus for new signup
    apply_referral_bonus(new_community_id, "referral-signup")

    from warden.billing.feature_gate import TIER_LIMITS
    bonus_bytes = TIER_LIMITS["individual"]["referral_bonus_bytes"]

    log.info(
        "overage: referral redeemed code=%s referrer=%s new=%s bonus=%s",
        referral_code, referrer_cid[:8], new_community_id[:8],
        f"{bonus_bytes / (1024**3):.1f} GB",
    )
    return {
        "referrer_community_id": referrer_cid,
        "new_community_id":      new_community_id,
        "bonus_bytes":           bonus_bytes,
        "code":                  referral_code,
    }


# ── Internal billing helpers ──────────────────────────────────────────────────

def _create_stripe_invoice_item(
    customer_id:  str,
    amount_cents: int,
    description:  str,
) -> str | None:
    """Create a Stripe invoice item. Returns invoice_item.id or None on error."""
    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        item = stripe.InvoiceItem.create(
            customer    = customer_id,
            amount      = amount_cents,
            currency    = "usd",
            description = description,
        )
        return item.id
    except Exception as exc:
        log.warning("overage: Stripe invoice item error: %s", exc)
        return None


def _create_paddle_charge(
    subscription_id: str,
    amount_cents:    int,
    description:     str,
) -> str | None:
    """Create a Paddle one-time charge. Returns transaction_id or None on error."""
    try:
        import httpx
        resp = httpx.post(
            "https://api.paddle.com/adjustments",
            headers={"Authorization": f"Bearer {PADDLE_API_KEY}"},
            json={
                "action":          "credit",
                "subscription_id": subscription_id,
                "reason":          description,
                "items": [{
                    "type":          "custom",
                    "amount":        str(amount_cents),
                    "description":   description,
                }],
            },
            timeout=10,
        )
        if resp.status_code == 201:
            return resp.json().get("data", {}).get("id")
    except Exception as exc:
        log.warning("overage: Paddle charge error: %s", exc)
    return None


def _fire_overage_webhook(
    community_id: str,
    metric:       str,
    overage_gb:   float,
    amount_cents: int,
    provider:     str,
) -> None:
    """POST overage event to external webhook (for resellers / custom portals)."""
    if not OVERAGE_WEBHOOK_URL:
        return
    try:
        import httpx
        httpx.post(
            OVERAGE_WEBHOOK_URL,
            json={
                "event":        "overage",
                "community_id": community_id,
                "metric":       metric,
                "overage_gb":   overage_gb,
                "amount_cents": amount_cents,
                "provider":     provider,
                "ts":           datetime.now(UTC).isoformat(),
            },
            timeout=5,
        )
    except Exception as exc:
        log.debug("overage: webhook error: %s", exc)
