"""
warden/api/webhook.py
─────────────────────
POST /billing/webhook  — Lemon Squeezy signed webhook receiver.

Security
────────
  X-Signature header carries HMAC-SHA256(raw_body, LEMONSQUEEZY_WEBHOOK_SECRET).
  Signature verification is delegated to LemonBilling.handle_webhook().
  Missing secret → signature check skipped (dev mode only — set the secret in prod).

Idempotency
───────────
  event_id (from meta.event_id or meta.uuid) is stored in webhook_events table.
  Duplicate deliveries return 200 {"ok": true, "duplicate": true} immediately.

Evidence
────────
  Every processed event is shipped to MinIO at:
    warden-evidence/billing/<YYYYMMDD>/<event_id>.json
  Fail-open: MinIO errors never cause webhook failures.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

from fastapi import APIRouter, Header, HTTPException, Request

log = logging.getLogger("warden.api.webhook")

router = APIRouter(prefix="/billing", tags=["billing"])


async def _ship_evidence(event_id: str, payload: bytes) -> None:
    try:
        from warden.storage.s3 import get_storage  # noqa: PLC0415
        storage = get_storage()
        if storage is None:
            return
        date_str = datetime.now(UTC).strftime("%Y%m%d")
        key      = f"evidence/billing/{date_str}/{event_id}.json"
        await storage.put_object_async("warden-evidence", key, payload)
        log.info("billing evidence written: %s", key)
    except Exception as exc:
        log.warning("billing evidence ship failed (fail-open): %s", exc)


@router.post(
    "/webhook",
    status_code=200,
    summary="Lemon Squeezy webhook receiver",
    response_model=None,
)
async def lemon_squeezy_webhook(
    request:     Request,
    x_signature: str | None = Header(default=None, alias="X-Signature"),
) -> dict:
    """
    Receives signed Lemon Squeezy webhook events.

    Events handled:
      subscription_created      — activate/upgrade plan
      subscription_updated      — sync plan + renewal date
      subscription_resumed      — re-activate paused subscription
      subscription_cancelled    — downgrade to starter immediately
      subscription_expired      — downgrade to starter
      subscription_payment_failed — mark past_due; dunning worker handles grace
      order_created             — one-time purchase (mapped to plan activation)
    """
    payload = await request.body()
    if not payload:
        raise HTTPException(status_code=400, detail="Empty webhook body.")

    try:
        from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
        billing    = get_lemon_billing()
        event_name = billing.handle_webhook(payload, x_signature or "")
    except ValueError as exc:
        log.warning("webhook: signature rejected — %s", exc)
        raise HTTPException(status_code=400, detail="Invalid webhook signature.") from exc
    except Exception as exc:
        log.error("webhook: processing error — %s", exc, exc_info=True)
        # Return 200 so Lemon Squeezy doesn't retry a permanently broken event.
        return {"ok": False, "error": str(exc)}

    # Extract event_id for evidence key (already checked for idempotency inside handle_webhook)
    event_id = "unknown"
    try:
        meta     = json.loads(payload).get("meta", {})
        event_id = str(meta.get("event_id") or meta.get("uuid") or "unknown")
    except Exception:
        pass

    await _ship_evidence(event_id, payload)
    return {"ok": True, "event": event_name}


@router.get(
    "/webhook/health",
    summary="Webhook endpoint health check",
    response_model=None,
)
async def webhook_health() -> dict:
    """Verify webhook receiver is reachable and LS secret is configured."""
    secret_set = bool(os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET"))
    return {
        "status":     "ok",
        "secret_set": secret_set,
        "endpoint":   "POST /billing/webhook",
    }
