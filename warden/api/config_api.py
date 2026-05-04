"""
Settings & Configuration REST API — /api/settings/*

Extends the existing inline /api/config with:
  GET  /api/settings              — full config snapshot (all knobs)
  POST /api/settings              — apply changes; Tier-1 keys trigger approval flow
  GET  /api/settings/pending      — list pending Tier-1 approvals
  POST /api/settings/approve/{token} — resolve approval (approve|reject)
  GET  /api/settings/drift        — current config vs last-saved baseline
  POST /api/settings/snapshot     — save current config as the drift baseline

Tier-1 keys (require Slack approval before applying):
  ANTHROPIC_API_KEY, WARDEN_API_KEY, VAULT_MASTER_KEY, NVIDIA_API_KEY,
  ADMIN_KEY, SUPER_ADMIN_KEY

Hot-reload keys (applied immediately, no restart):
  semantic_threshold, strict_mode, rate_limit_per_minute,
  uncertainty_lower_threshold, healer_bypass_threshold

All other keys → stored in pending approval queue.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from warden.site.approval import (
    TIER1_KEYS,
    PendingChange,
    get_pending,
    issue_token,
    list_pending,
    resolve_token,
)

log = logging.getLogger("warden.api.config_api")

router = APIRouter(prefix="/api/settings", tags=["settings"])

_SNAPSHOT_PATH = Path(os.getenv("CONFIG_SNAPSHOT_PATH", "data/config_snapshot.json"))

# Keys that can be hot-reloaded without restart
_HOT_RELOAD_KEYS: frozenset[str] = frozenset({
    "semantic_threshold",
    "strict_mode",
    "rate_limit_per_minute",
    "uncertainty_lower_threshold",
    "healer_bypass_threshold",
    "intel_ops_enabled",
    "intel_bridge_interval_hrs",
})


# ── Pydantic ──────────────────────────────────────────────────────────────────

class SettingsUpdate(BaseModel):
    changes: dict[str, Any] = Field(description="Key-value pairs to update")
    tenant_id: str = "default"
    requested_by: str = "api"


class ApprovalAction(BaseModel):
    action: str = Field(pattern="^(approve|reject)$")


# ── Config snapshot ───────────────────────────────────────────────────────────

def _full_config() -> dict[str, Any]:
    """Return the complete live configuration dict."""
    return {
        # Core pipeline
        "semantic_threshold":           float(os.getenv("SEMANTIC_THRESHOLD", "0.72")),
        "strict_mode":                  os.getenv("STRICT_MODE", "false").lower() == "true",
        "rate_limit_per_minute":        int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
        "uncertainty_lower_threshold":  float(os.getenv("UNCERTAINTY_LOWER_THRESHOLD", "0.3")),
        # Topology
        "topology_enabled":             os.getenv("TOPOLOGY_ENABLED", "true").lower() == "true",
        "betti_threshold_b0":           int(os.getenv("BETTI_THRESHOLD_B0", "8")),
        "betti_threshold_b1":           int(os.getenv("BETTI_THRESHOLD_B1", "3")),
        "ngram_window":                 int(os.getenv("NGRAM_WINDOW", "3")),
        # Obfuscation
        "obfuscation_decode_depth":     int(os.getenv("OBFUSCATION_DECODE_DEPTH", "3")),
        "decode_base64":                os.getenv("DECODE_BASE64", "true").lower() == "true",
        "decode_homoglyphs":            os.getenv("DECODE_HOMOGLYPHS", "true").lower() == "true",
        # Secrets
        "entropy_threshold":            float(os.getenv("ENTROPY_THRESHOLD", "4.5")),
        "entropy_scan_enabled":         os.getenv("ENTROPY_SCAN_ENABLED", "true").lower() == "true",
        # Evolution
        "evolution_enabled":            bool(os.getenv("ANTHROPIC_API_KEY")),
        "intel_ops_enabled":            os.getenv("INTEL_OPS_ENABLED", "false").lower() == "true",
        "intel_bridge_interval_hrs":    int(os.getenv("INTEL_OPS_INTERVAL_HRS", "6")),
        # Healer
        "healer_bypass_threshold":      float(os.getenv("HEALER_BYPASS_THRESHOLD", "0.15")),
        # Features
        "browser_enabled":              os.getenv("BROWSER_ENABLED", "false").lower() == "true",
        "mtls_enabled":                 os.getenv("MTLS_ENABLED", "false").lower() == "true",
        "otel_enabled":                 os.getenv("OTEL_ENABLED", "false").lower() == "true",
        "audit_trail_enabled":          os.getenv("AUDIT_TRAIL_ENABLED", "false").lower() == "true",
        "prompt_shield_enabled":        os.getenv("PROMPT_SHIELD_ENABLED", "false").lower() == "true",
        # Integrations — presence only (never expose actual values)
        "anthropic_api_key_set":        bool(os.getenv("ANTHROPIC_API_KEY")),
        "nvidia_api_key_set":           bool(os.getenv("NVIDIA_API_KEY")),
        "admin_key_set":                bool(os.getenv("ADMIN_KEY")),
        "vault_master_key_set":         bool(os.getenv("VAULT_MASTER_KEY")),
        "slack_webhook_set":            bool(os.getenv("SLACK_WEBHOOK_URL")),
        # Meta
        "model_cache_dir":              os.getenv("MODEL_CACHE_DIR", "/warden/models"),
        "log_retention_days":           int(os.getenv("GDPR_LOG_RETENTION_DAYS", "30")),
        "snapshot_at":                  datetime.now(UTC).isoformat(),
    }


def _apply_hot_reload(key: str, value: Any) -> bool:
    """Apply a hot-reloadable setting immediately. Returns True if applied."""
    try:
        if key == "semantic_threshold":
            val = max(0.1, min(1.0, float(value)))
            os.environ["SEMANTIC_THRESHOLD"] = str(val)
            try:
                from warden.brain.semantic import get_guard  # noqa: PLC0415
                g = get_guard()
                if g:
                    g.threshold = val
            except Exception:
                pass
            return True

        if key == "strict_mode":
            os.environ["STRICT_MODE"] = str(bool(value)).lower()
            return True

        if key == "rate_limit_per_minute":
            os.environ["RATE_LIMIT_PER_MINUTE"] = str(int(value))
            try:
                from warden.main import set_default_rate_limit  # noqa: PLC0415
                set_default_rate_limit(int(value))
            except Exception:
                pass
            return True

        if key == "uncertainty_lower_threshold":
            val = max(0.0, min(0.99, float(value)))
            os.environ["UNCERTAINTY_LOWER_THRESHOLD"] = str(val)
            return True

        if key == "healer_bypass_threshold":
            val = max(0.0, min(1.0, float(value)))
            os.environ["HEALER_BYPASS_THRESHOLD"] = str(val)
            return True

        if key == "intel_ops_enabled":
            os.environ["INTEL_OPS_ENABLED"] = str(bool(value)).lower()
            return True

        if key == "intel_bridge_interval_hrs":
            os.environ["INTEL_OPS_INTERVAL_HRS"] = str(int(value))
            return True

    except Exception as exc:
        log.warning("hot-reload failed for %s: %s", key, exc)
    return False


async def _slack_approval_request(change: PendingChange, base_url: str) -> None:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        log.info("No SLACK_WEBHOOK_URL — approval token: %s", change.token[:20])
        return
    approve_url = f"{base_url}/api/settings/approve/{change.token}?action=approve"
    reject_url  = f"{base_url}/api/settings/approve/{change.token}?action=reject"
    msg = {
        "text": (
            f":key: *Tier-1 config change requires approval*\n"
            f"Key: `{change.key}`\n"
            f"Requested by: `{change.requested_by}`\n"
            f"Token: `{change.token[:20]}…`\n\n"
            f"• Approve: `POST {approve_url}`\n"
            f"• Reject:  `POST {reject_url}`\n\n"
            f"_Token expires in 1 hour._"
        )
    }
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            await c.post(webhook, json=msg)
    except Exception as exc:
        log.warning("approval slack alert failed: %s", exc)


async def _ship_evidence(change: PendingChange) -> None:
    """Write approved Tier-1 change to MinIO evidence vault (fail-open)."""
    try:
        from warden.storage.s3 import get_storage  # noqa: PLC0415
        storage = get_storage()
        if storage is None:
            return
        record = {
            "event":        "tier1_config_approved",
            "key":          change.key,
            "requested_by": change.requested_by,
            "approved_at":  datetime.now(UTC).isoformat(),
            "token":        change.token[:20],
        }
        key = f"evidence/config/{datetime.now(UTC).strftime('%Y%m%d')}/{change.token[:16]}.json"
        await storage.put_object_async("warden-evidence", key, json.dumps(record).encode())
        log.info("config evidence written: %s", key)
    except Exception as exc:
        log.warning("config evidence ship failed (fail-open): %s", exc)


def _save_snapshot(config: dict) -> None:
    _SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=_SNAPSHOT_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp, _SNAPSHOT_PATH)
    except Exception:
        os.unlink(tmp)
        raise


def _compute_drift() -> dict:
    if not _SNAPSHOT_PATH.exists():
        return {"baseline": None, "drifted_keys": [], "drift_count": 0}
    try:
        baseline = json.loads(_SNAPSHOT_PATH.read_text())
    except Exception:
        return {"baseline": None, "drifted_keys": [], "drift_count": 0}

    current = _full_config()
    skip = {"snapshot_at"}
    drifted = [
        {"key": k, "baseline": baseline.get(k), "current": current.get(k)}
        for k in set(baseline) | set(current)
        if k not in skip and baseline.get(k) != current.get(k)
    ]
    return {
        "baseline_at":  baseline.get("snapshot_at"),
        "checked_at":   current["snapshot_at"],
        "drifted_keys": drifted,
        "drift_count":  len(drifted),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def get_settings(tenant_id: str = Query(default="default")) -> dict:
    """Full live configuration snapshot. Sensitive key values replaced with boolean presence."""
    return _full_config()


@router.post("")
async def update_settings(
    req: SettingsUpdate,
    x_forwarded_for: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Apply configuration changes.

    Hot-reload keys are applied immediately and return `applied: [...]`.
    Tier-1 keys require Slack approval and return `pending: [...] + approval_token`.
    Unknown keys are ignored with a warning.
    """
    base_url = os.getenv("WARDEN_BASE_URL", "http://localhost:8001")
    applied: list[str]  = []
    pending_tokens: list[dict] = []
    ignored:  list[str]  = []

    for key, value in req.changes.items():
        key_lower = key.lower()

        if key_lower in TIER1_KEYS:
            change = issue_token(key_lower, str(value), req.requested_by)
            await _slack_approval_request(change, base_url)
            pending_tokens.append(change.redacted())
            log.info("Tier-1 change queued for approval: key=%s token=%s", key, change.token[:20])

        elif key_lower in _HOT_RELOAD_KEYS:
            if _apply_hot_reload(key_lower, value):
                applied.append(key_lower)
            else:
                ignored.append(key_lower)

        else:
            ignored.append(key_lower)
            log.debug("settings update: unknown key %s — ignored", key)

    status = 202 if pending_tokens else 200
    return {
        "applied":          applied,
        "pending_approval": pending_tokens,
        "ignored":          ignored,
        "status":           "partial" if pending_tokens else "ok",
    }


@router.get("/pending")
def get_pending_approvals() -> dict:
    """List all pending Tier-1 approval tokens (redacted values)."""
    return {"pending": list_pending()}


@router.post("/approve/{token}")
async def approve_setting(
    token: str,
    action: str = Query(pattern="^(approve|reject)$"),
    x_admin_key: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Resolve a pending Tier-1 approval.
    Requires X-Admin-Key header.
    action=approve → applies the change + writes evidence.
    action=reject  → discards the pending change.
    """
    import hmac as _hmac  # noqa: PLC0415
    admin = os.getenv("ADMIN_KEY", "")
    if not admin or not x_admin_key or not _hmac.compare_digest(x_admin_key, admin):
        raise HTTPException(status_code=403, detail="Admin key required")

    change = resolve_token(token, action)
    if change is None:
        raise HTTPException(status_code=404, detail="Token not found, expired, or already resolved")

    if action == "approve":
        # Apply the Tier-1 change via env var (restart required for most)
        os.environ[change.key.upper()] = change.new_value
        await _ship_evidence(change)
        log.info("Tier-1 change APPROVED: key=%s", change.key)
        return {
            "resolved": True,
            "action":   "approved",
            "key":      change.key,
            "note":     "Change applied to env. Container restart may be required.",
        }
    else:
        log.info("Tier-1 change REJECTED: key=%s", change.key)
        return {"resolved": True, "action": "rejected", "key": change.key}


@router.get("/drift")
def get_drift() -> dict:
    """Compare current config against the last saved snapshot."""
    return _compute_drift()


@router.post("/snapshot")
def save_snapshot(
    x_admin_key: Annotated[str | None, Header()] = None,
) -> dict:
    """Save current config as the drift baseline (admin only)."""
    import hmac as _hmac  # noqa: PLC0415
    admin = os.getenv("ADMIN_KEY", "")
    if not admin or not x_admin_key or not _hmac.compare_digest(x_admin_key, admin):
        raise HTTPException(status_code=403, detail="Admin key required")
    config = _full_config()
    _save_snapshot(config)
    return {"saved": True, "keys": len(config), "snapshot_at": config["snapshot_at"]}
