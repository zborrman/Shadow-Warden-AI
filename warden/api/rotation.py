"""
warden/api/rotation.py  (Q1.3)
──────────────────────────────
Secrets Rotation Alerts — monitor API key age and alert before expiry.

Endpoints
─────────
  GET  /admin/rotation/status        — age of all tracked secrets
  POST /admin/rotation/rotate-alert  — manually trigger Slack rotation alert
  POST /admin/rotation/record        — record that a key was rotated (sets timestamp)

Design
──────
  • Key age tracked in Redis under  warden:key_age:{sha256_prefix}
  • Default warning threshold: KEY_ROTATION_WARNING_DAYS=75 (90-day policy)
  • Default max age:            KEY_ROTATION_MAX_DAYS=90
  • Integrates with SOVA sova_rotation_check cron (02:00 UTC daily)
  • Fail-open: if Redis unavailable, returns degraded status (no crash)
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

log = logging.getLogger("warden.api.rotation")

router = APIRouter(prefix="/admin/rotation", tags=["rotation"])

_WARNING_DAYS = int(os.getenv("KEY_ROTATION_WARNING_DAYS", "75"))
_MAX_DAYS     = int(os.getenv("KEY_ROTATION_MAX_DAYS",     "90"))
_ADMIN_KEY    = os.getenv("ADMIN_KEY", "")

# ── Secrets to monitor ────────────────────────────────────────────────────────
# We never log the actual key value — only a 12-char SHA-256 prefix for lookup.

def _tracked_secrets() -> list[dict]:
    """Return list of configured secrets with their env-var labels."""
    candidates = [
        ("WARDEN_API_KEY",         os.getenv("WARDEN_API_KEY",         "")),
        ("ANTHROPIC_API_KEY",      os.getenv("ANTHROPIC_API_KEY",      "")),
        ("NVIDIA_API_KEY",         os.getenv("NVIDIA_API_KEY",         "")),
        ("VAULT_MASTER_KEY",       os.getenv("VAULT_MASTER_KEY",       "")),
        ("COMMUNITY_VAULT_KEY",    os.getenv("COMMUNITY_VAULT_KEY",    "")),
        ("SOVEREIGN_ATTEST_KEY",   os.getenv("SOVEREIGN_ATTEST_KEY",   "")),
        ("SLACK_WEBHOOK_URL",      os.getenv("SLACK_WEBHOOK_URL",      "")),
        ("PAGERDUTY_ROUTING_KEY",  os.getenv("PAGERDUTY_ROUTING_KEY",  "")),
    ]
    result = []
    for label, value in candidates:
        if value:
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            result.append({"label": label, "digest": digest})
    return result


def _redis_key(digest: str) -> str:
    return f"warden:key_age:{digest}"


def _get_redis():
    try:
        from warden.cache import _get_client
        return _get_client()
    except Exception:
        return None


def _get_age_days(digest: str) -> float | None:
    """Return key age in days from Redis, or None if not recorded."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_redis_key(digest))
        if raw is None:
            return None
        recorded_at = float(raw)
        return (time.time() - recorded_at) / 86400
    except Exception:
        return None


def _record_rotation(digest: str) -> None:
    r = _get_redis()
    if r is None:
        return
    import contextlib
    with contextlib.suppress(Exception):
        r.set(_redis_key(digest), str(time.time()), ex=365 * 86400)


def _status_for(label: str, digest: str) -> dict:
    age = _get_age_days(digest)
    if age is None:
        return {
            "label":      label,
            "digest":     digest,
            "status":     "untracked",
            "age_days":   None,
            "expires_in": None,
            "alert":      False,
        }
    days_left = _MAX_DAYS - age
    alert     = age >= _WARNING_DAYS
    if age >= _MAX_DAYS:
        status = "EXPIRED"
    elif alert:
        status = "WARNING"
    else:
        status = "OK"
    return {
        "label":      label,
        "digest":     digest,
        "status":     status,
        "age_days":   round(age, 1),
        "expires_in": round(max(days_left, 0), 1),
        "alert":      alert,
    }


def _require_admin(x_admin_key: Annotated[str, Header(alias="X-Admin-Key")] = "") -> None:
    if _ADMIN_KEY and x_admin_key != _ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin key required.")


# ── Models ────────────────────────────────────────────────────────────────────

class RotationStatusResponse(BaseModel):
    keys:            list[dict]
    alerts:          list[str]
    warning_days:    int
    max_days:        int
    generated_at:    str


class RecordRotationRequest(BaseModel):
    label: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status", response_model=RotationStatusResponse, summary="Check API key ages")
async def rotation_status(
    _: None = Depends(_require_admin),
) -> RotationStatusResponse:
    secrets = _tracked_secrets()
    keys    = [_status_for(s["label"], s["digest"]) for s in secrets]
    alerts  = [k["label"] for k in keys if k["alert"]]

    # Fire Slack alert if any keys are WARNING/EXPIRED
    if alerts:
        try:
            from warden.alerting import send_alert
            msg = (
                f"*Shadow Warden — Key Rotation Alert*\n"
                f"The following secrets are approaching or past the {_MAX_DAYS}-day rotation policy:\n"
                + "\n".join(f"• `{a}`" for a in alerts)
            )
            send_alert(msg, level="warning")
        except Exception as exc:
            log.debug("rotation: slack alert skipped: %s", exc)

    return RotationStatusResponse(
        keys         = keys,
        alerts       = alerts,
        warning_days = _WARNING_DAYS,
        max_days     = _MAX_DAYS,
        generated_at = datetime.now(UTC).isoformat(),
    )


@router.post("/record", summary="Record that a key was rotated (resets age clock)")
async def record_rotation(
    body: RecordRotationRequest,
    _: None = Depends(_require_admin),
) -> dict:
    secrets = _tracked_secrets()
    match   = next((s for s in secrets if s["label"] == body.label), None)
    if match is None:
        raise HTTPException(status_code=404, detail=f"No active secret found for label '{body.label}'.")
    _record_rotation(match["digest"])
    log.info("rotation: key recorded for label=%s digest=%s", body.label, match["digest"])
    return {"recorded": True, "label": body.label, "recorded_at": datetime.now(UTC).isoformat()}


@router.post("/rotate-alert", summary="Manually trigger rotation reminder to Slack")
async def rotate_alert(
    _: None = Depends(_require_admin),
) -> dict:
    try:
        from warden.alerting import send_alert
        send_alert(
            "*Shadow Warden — Manual Rotation Reminder*\n"
            "This is a manually triggered reminder to rotate all API secrets.",
            level="warning",
        )
        return {"sent": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
