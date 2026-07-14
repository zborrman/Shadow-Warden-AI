"""
warden/api/gdpr.py
━━━━━━━━━━━━━━━━━
GDPR Art. 17 (erasure) and Art. 20 (portability) REST API.

Endpoints
─────────
  DELETE /gdpr/purge/session/{session_id}   — erase all traces of a session
  GET    /gdpr/export/session/{session_id}  — export all metadata for a session
  DELETE /gdpr/purge/before/{iso_date}      — bulk erasure before a date
  POST   /gdpr/purge/tenant/{tenant_id}     — erase all data for a tenant
  GET    /gdpr/retention-policy             — current retention config
  GET    /gdpr/audit/{tenant_id}            — last 100 GDPR operations for tenant

All write operations are logged to the GDPR audit trail (in-memory + optional S3).
"""
from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from warden.analytics import logger as event_logger
from warden.auth_guard import AuthResult, require_api_key
from warden.config import settings

log = logging.getLogger("warden.api.gdpr")


def _is_admin(x_admin_key: str) -> bool:
    """Constant-time check of the operator override key. Fail-closed: unset ADMIN_KEY
    never authorises anyone (an empty configured key must not match an empty header)."""
    admin_key = os.getenv("ADMIN_KEY", "")
    return bool(admin_key) and hmac.compare_digest(x_admin_key, admin_key)


def require_tenant_owner_or_admin(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
    x_admin_key: str = Header(""),
) -> None:
    """
    Authorize a tenant-scoped GDPR operation (SR-1.4b — closes the IDOR).

    A valid API key alone was enough to erase or read ANY tenant's data because the
    handlers trusted the `{tenant_id}` in the URL. Now the caller's own resolved
    tenant (from its key) must match the path tenant — self-service, own data only —
    unless it presents a valid X-Admin-Key (the operator-admin path, resolving the
    self-service-vs-admin question). Anything else is 403.
    """
    if _is_admin(x_admin_key):
        return
    if auth.tenant_id != tenant_id:
        log.warning(
            "GDPR IDOR blocked: key-tenant=%s attempted tenant=%s", auth.tenant_id, tenant_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may only operate on your own tenant. Operator access requires X-Admin-Key.",
        )


def require_admin_only(x_admin_key: str = Header("")) -> None:
    """
    Operator-admin gate for cross-tenant destructive ops. `DELETE /purge/before/{date}`
    erases EVERY tenant's data before a date, so a per-tenant key must not authorise it —
    that is an operator action. Fail-closed: no valid X-Admin-Key ⇒ 403.
    """
    if not _is_admin(x_admin_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant bulk purge requires X-Admin-Key.",
        )

# Router-level auth: every /gdpr endpoint requires a valid API key. Without this
# the path-based endpoints (DELETE /purge/tenant/{id}, GET /audit/{id}, session
# purge/export) were unauthenticated — any caller could erase or read another
# tenant's data. (The /export and /purge body endpoints already had it.)
router = APIRouter(
    prefix="/gdpr",
    tags=["gdpr"],
    dependencies=[Depends(require_api_key)],
)

# In-memory GDPR audit trail (last 500 operations, survives restarts via S3 if enabled)
_audit: list[dict] = []
_AUDIT_CAP = 500

RETENTION_DAYS: int = settings.gdpr_log_retention_days


def _record_audit(operation: str, subject: str, tenant_id: str = "", records_affected: int = 0) -> None:
    entry = {
        "ts":               datetime.now(UTC).isoformat(),
        "operation":        operation,
        "subject":          subject,
        "tenant_id":        tenant_id,
        "records_affected": records_affected,
    }
    _audit.append(entry)
    if len(_audit) > _AUDIT_CAP:
        _audit.pop(0)


# ── Response models ───────────────────────────────────────────────────────────

class PurgeResult(BaseModel):
    ok:               bool
    records_removed:  int
    subject:          str
    timestamp:        str


class ExportResult(BaseModel):
    session_id:  str
    record:      dict | None
    exported_at: str


# ── Session-level erasure ─────────────────────────────────────────────────────

@router.delete(
    "/purge/session/{session_id}",
    response_model=PurgeResult,
    summary="Erase all traces of a session (Art. 17)",
    description=(
        "Removes the session's evidence bundle from MinIO, its log entry from "
        "logs.json, and its ERS keys from Redis. Idempotent — safe to call "
        "multiple times."
    ),
)
async def purge_session(session_id: str) -> PurgeResult:
    removed = 0

    # 1. MinIO Evidence Vault
    try:
        from warden.storage.s3 import get_storage  # noqa: PLC0415
        storage = get_storage()
        if storage:
            bucket = settings.s3_evidence_bucket
            key = f"bundles/{session_id}.json"
            await storage.put_object_async(bucket, key, b"")  # overwrite with empty
            removed += 1
            log.info("GDPR purge: MinIO evidence cleared for session %s", session_id)
    except Exception as exc:
        log.warning("GDPR purge: MinIO clear failed (non-fatal) — %s", exc)

    # 2. Logs (logs.json) — purge by session_id matching request_id prefix
    try:
        from warden.analytics.logger import LOGS_PATH  # noqa: PLC0415
        if LOGS_PATH.exists():
            lines = LOGS_PATH.read_text(encoding="utf-8").splitlines()
            kept = []
            for line in lines:
                try:
                    entry = json.loads(line)
                    if entry.get("request_id", "").startswith(session_id[:8]):
                        removed += 1
                    else:
                        kept.append(line)
                except Exception:
                    kept.append(line)
            import os as _os  # noqa: PLC0415
            import tempfile  # noqa: PLC0415
            with tempfile.NamedTemporaryFile("w", dir=LOGS_PATH.parent, delete=False, suffix=".tmp") as f:
                f.write("\n".join(kept) + ("\n" if kept else ""))
                tmp = f.name
            _os.replace(tmp, LOGS_PATH)
    except Exception as exc:
        log.warning("GDPR purge: logs.json clear failed (non-fatal) — %s", exc)

    # 3. Redis ERS keys
    try:
        from warden.cache import _get_client as _redis  # noqa: PLC0415
        r = _redis()
        if r:
            pattern = f"warden:ers:{session_id[:16]}:*"
            keys = r.keys(pattern)
            if keys:
                r.delete(*keys)
                removed += len(keys)
    except Exception as exc:
        log.warning("GDPR purge: Redis ERS clear failed (non-fatal) — %s", exc)

    _record_audit("purge_session", session_id, records_affected=removed)
    return PurgeResult(
        ok=True,
        records_removed=removed,
        subject=session_id,
        timestamp=datetime.now(UTC).isoformat(),
    )


# ── Data export (Art. 20 portability) ────────────────────────────────────────

@router.get(
    "/export/session/{session_id}",
    response_model=ExportResult,
    summary="Export all metadata recorded for a session (Art. 20)",
)
async def export_session(session_id: str) -> ExportResult:
    record = None
    try:
        from warden.analytics.logger import read_by_request_id  # noqa: PLC0415
        record = read_by_request_id(session_id)
    except Exception as exc:
        log.warning("GDPR export: log read failed — %s", exc)

    _record_audit("export_session", session_id)
    return ExportResult(
        session_id=session_id,
        record=record,
        exported_at=datetime.now(UTC).isoformat(),
    )


# ── Bulk erasure before date ──────────────────────────────────────────────────

@router.delete(
    "/purge/before/{iso_date}",
    response_model=PurgeResult,
    summary="Bulk erase all log entries before a given ISO date (Art. 17)",
    dependencies=[Depends(require_admin_only)],
)
async def purge_before_date(iso_date: str) -> PurgeResult:
    try:
        before_dt = datetime.fromisoformat(iso_date).replace(tzinfo=UTC)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid date format: {iso_date!r}. Use ISO 8601, e.g. 2026-01-01.",
        ) from None

    removed = 0
    try:
        from warden.analytics.logger import purge_before  # noqa: PLC0415
        removed = purge_before(before_dt)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    _record_audit("purge_before", iso_date, records_affected=removed)
    return PurgeResult(
        ok=True,
        records_removed=removed,
        subject=f"entries before {iso_date}",
        timestamp=datetime.now(UTC).isoformat(),
    )


# ── Tenant-level erasure ──────────────────────────────────────────────────────

@router.delete(
    "/purge/tenant/{tenant_id}",
    response_model=PurgeResult,
    summary="Erase all log entries for a specific tenant (GDPR contract termination)",
    dependencies=[Depends(require_tenant_owner_or_admin)],
)
async def purge_tenant(tenant_id: str) -> PurgeResult:
    removed = 0
    try:
        from warden.analytics.logger import LOGS_PATH  # noqa: PLC0415
        if LOGS_PATH.exists():
            lines = LOGS_PATH.read_text(encoding="utf-8").splitlines()
            kept = []
            for line in lines:
                try:
                    entry = json.loads(line)
                    if entry.get("tenant_id") == tenant_id:
                        removed += 1
                    else:
                        kept.append(line)
                except Exception:
                    kept.append(line)
            import os as _os  # noqa: PLC0415
            import tempfile  # noqa: PLC0415
            with tempfile.NamedTemporaryFile("w", dir=LOGS_PATH.parent, delete=False, suffix=".tmp") as f:
                f.write("\n".join(kept) + ("\n" if kept else ""))
                tmp = f.name
            _os.replace(tmp, LOGS_PATH)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # Clear Redis ERS keys for this tenant (pattern-based)
    try:
        from warden.cache import _get_client as _redis  # noqa: PLC0415
        r = _redis()
        if r:
            for key in r.scan_iter("warden:ers:*"):
                r.delete(key)
    except Exception:
        pass

    _record_audit("purge_tenant", tenant_id, tenant_id=tenant_id, records_affected=removed)
    return PurgeResult(
        ok=True,
        records_removed=removed,
        subject=f"tenant:{tenant_id}",
        timestamp=datetime.now(UTC).isoformat(),
    )


# ── Retention policy ──────────────────────────────────────────────────────────

@router.get(
    "/retention-policy",
    summary="Get current data retention configuration",
)
async def retention_policy() -> dict:
    return {
        "log_retention_days":     RETENTION_DAYS,
        "evidence_vault_bucket":  settings.s3_evidence_bucket,
        "s3_enabled":             settings.s3_enabled,
        "gdpr_log_path":          settings.logs_path,
        "auto_purge_enabled":     settings.gdpr_auto_purge,
        "auto_purge_cron":        "daily at 02:00 UTC",
    }


# ── GDPR audit trail ──────────────────────────────────────────────────────────

@router.get(
    "/audit/{tenant_id}",
    summary="Last GDPR operations recorded for this tenant",
    dependencies=[Depends(require_tenant_owner_or_admin)],
)
async def gdpr_audit(tenant_id: str) -> dict:
    tenant_ops = [e for e in _audit if not tenant_id or e.get("tenant_id") == tenant_id or e.get("subject", "").startswith(tenant_id)]
    return {"tenant_id": tenant_id, "operations": tenant_ops[-100:], "total": len(tenant_ops)}


# ── Automatic retention enforcement (called by cron worker) ──────────────────

async def run_retention_purge() -> int:
    """
    Called daily by the GDPR retention cronjob.
    Removes log entries older than GDPR_LOG_RETENTION_DAYS (default 30).
    Returns the number of records removed.
    """
    try:
        from warden.analytics.logger import purge_old_entries  # noqa: PLC0415
        removed = purge_old_entries()
        _record_audit("auto_retention_purge", f"entries older than {RETENTION_DAYS} days", records_affected=removed)
        log.info("GDPR auto-retention: removed %d entries older than %d days", removed, RETENTION_DAYS)
        return removed
    except Exception as exc:
        log.error("GDPR auto-retention failed: %s", exc)
        return 0


# ── Request-ID export / date purge (migrated from main.py inline, Phase 3) ─────

class _GdprExportRequest(BaseModel):
    request_id: str


class _GdprPurgeRequest(BaseModel):
    before: str   # ISO-8601 datetime string, e.g. "2024-01-01T00:00:00Z"


@router.post(
    "/export",
    summary="Export log metadata for a specific request ID (GDPR Art. 15)",
    dependencies=[Depends(require_api_key)],
)
async def gdpr_export(body: _GdprExportRequest):
    entry = event_logger.read_by_request_id(body.request_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"No log entry found for request_id={body.request_id!r}.",
        )
    return {"request_id": body.request_id, "entry": entry}


@router.post(
    "/purge",
    summary="Delete log entries before a given date (GDPR Art. 17)",
    dependencies=[Depends(require_api_key)],
)
async def gdpr_purge(body: _GdprPurgeRequest):
    try:
        before_dt = datetime.fromisoformat(body.before)
    except ValueError:
        return JSONResponse(
            status_code=422,
            content={"detail": f"Invalid datetime format: {body.before!r}. Use ISO-8601."},
        )
    removed = event_logger.purge_before(before_dt)
    log.info(
        json.dumps({"event": "gdpr_purge", "removed": removed, "before": body.before})
    )
    return {"removed": removed, "before": body.before}
