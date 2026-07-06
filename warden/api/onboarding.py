"""
warden/api/onboarding.py
━━━━━━━━━━━━━━━━━━━━━━━━━
SMB tenant onboarding + MSP cross-tenant dashboard REST API.

Endpoints
─────────
  POST   /onboard                              — provision a new tenant
  GET    /onboard/{tenant_id}                  — tenant status
  GET    /tenants                              — list all tenants (MSP)
  POST   /onboard/{tenant_id}/rotate-key       — rotate API key
  PUT    /onboard/{tenant_id}/status           — activate / deactivate
  PUT    /onboard/{tenant_id}/telegram         — set Telegram chat_id
  POST   /onboard/{tenant_id}/verify-telegram  — send test Telegram message
  GET    /msp/overview                         — cross-tenant fleet stats
  GET    /msp/report/{tenant_id}               — monthly compliance report

Extracted from ``warden/main.py`` (Phase 3). The OnboardingEngine, BillingStore,
and DataPolicyEngine singletons are published to ``warden.runtime`` in the app
lifespan and resolved here; the report engine is a module-level singleton.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from warden.analytics import logger as event_logger
from warden.analytics.report import get_engine as _get_report_engine
from warden.auth_guard import AuthResult, require_api_key
from warden.runtime import runtime as _runtime

log = logging.getLogger("warden.api.onboarding")

# Unprefixed router — paths span /onboard, /tenants and /msp, so full paths are
# declared on each route (matches the historical inline layout exactly).
router = APIRouter()


# ── Request models ────────────────────────────────────────────────────────────

class _OnboardRequest(BaseModel):
    company_name:     str   = Field(..., min_length=2, max_length=120)
    contact_email:    str   = Field(..., min_length=5)
    plan:             str   = Field("pro", pattern="^(free|pro|msp)$")
    telegram_chat_id: str | None = None
    custom_quota_usd: float | None = None


class _TelegramSetRequest(BaseModel):
    chat_id: str | None = None


class _TelegramTestRequest(BaseModel):
    chat_id: str


def _require_onboarding():
    onboarding = _runtime.get("onboarding")
    if onboarding is None:
        raise HTTPException(503, detail="OnboardingEngine not initialized.")
    return onboarding


# ── Onboarding API ────────────────────────────────────────────────────────────

@router.post(
    "/onboard",
    tags=["onboarding"],
    summary="Create a new SMB tenant (MSP admin only)",
    status_code=201,
)
async def create_tenant(
    body: _OnboardRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Provision a new SMB client tenant.

    Returns a one-time setup kit including the raw API key (not stored in plaintext),
    OPENAI_BASE_URL for the client, and a .env template.
    """
    onboarding = _require_onboarding()
    try:
        kit = onboarding.create_tenant(
            company_name     = body.company_name,
            contact_email    = body.contact_email,
            plan             = body.plan,
            telegram_chat_id = body.telegram_chat_id,
            custom_quota_usd = body.custom_quota_usd,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Apply billing quota if billing is configured
    billing = _runtime.get("billing")
    if billing is not None and kit.quota_usd > 0:
        billing.set_quota(kit.tenant_id, kit.quota_usd)

    log.info(
        json.dumps({
            "event":     "tenant_created",
            "tenant_id": kit.tenant_id,
            "plan":      kit.plan,
            "by":        auth.tenant_id,
        })
    )
    return kit.as_dict()


@router.get(
    "/onboard/{tenant_id}",
    tags=["onboarding"],
    summary="Get tenant status",
)
async def get_tenant_status(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Return tenant metadata (no key hash exposed)."""
    onboarding = _require_onboarding()
    tenant = onboarding.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    return tenant


@router.get(
    "/tenants",
    tags=["onboarding"],
    summary="List all tenants (MSP dashboard)",
)
async def list_tenants(
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Return all provisioned tenants with metadata (no key hashes)."""
    onboarding = _require_onboarding()
    tenants = onboarding.list_tenants()
    return {"count": len(tenants), "tenants": tenants}


@router.post(
    "/onboard/{tenant_id}/rotate-key",
    tags=["onboarding"],
    summary="Issue a new API key for a tenant (invalidates old key immediately)",
)
async def rotate_tenant_key(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Rotate the API key for a tenant. Old key is immediately revoked."""
    onboarding = _require_onboarding()
    new_key = onboarding.rotate_key(tenant_id)
    if new_key is None:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    log.info(
        json.dumps({"event": "key_rotated", "tenant_id": tenant_id, "by": auth.tenant_id})
    )
    return {
        "tenant_id": tenant_id,
        "api_key":   new_key,
        "message":   "New API key issued. Update your client's OPENAI_API_KEY immediately.",
    }


@router.put(
    "/onboard/{tenant_id}/status",
    tags=["onboarding"],
    summary="Activate or deactivate a tenant",
)
async def set_tenant_status(
    tenant_id: str,
    active: bool,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Enable or suspend a tenant's API key."""
    onboarding = _require_onboarding()
    if active:
        found = onboarding.reactivate_tenant(tenant_id)
    else:
        found = onboarding.deactivate_tenant(tenant_id)
    if not found:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    return {"tenant_id": tenant_id, "active": active}


@router.put(
    "/onboard/{tenant_id}/telegram",
    tags=["onboarding"],
    summary="Set or clear a tenant's Telegram chat_id",
)
async def set_tenant_telegram(
    tenant_id: str,
    body: _TelegramSetRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Store a Telegram chat_id for per-tenant block event notifications."""
    onboarding = _require_onboarding()
    found = onboarding.update_telegram(tenant_id, body.chat_id)
    if not found:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    return {"tenant_id": tenant_id, "telegram_chat_id": body.chat_id}


@router.post(
    "/onboard/{tenant_id}/verify-telegram",
    tags=["onboarding"],
    summary="Send a test Telegram message to verify bot and chat_id",
)
async def verify_tenant_telegram(
    tenant_id: str,
    body: _TelegramTestRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Send a test Telegram message. Returns ok=true if message was delivered."""
    from warden.telegram_alert import send_test_message  # noqa: PLC0415
    ok = await send_test_message(body.chat_id)
    return {"ok": ok, "chat_id": body.chat_id}


# ── MSP cross-tenant dashboard ────────────────────────────────────────────────

@router.get(
    "/msp/overview",
    tags=["msp"],
    summary="Cross-tenant MSP overview — aggregate stats for all tenants",
)
async def msp_overview(
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Returns per-tenant stats (requests, blocks, cost, block rate, quota usage)
    for the current calendar month, plus fleet-wide totals.

    Designed for the MSP sales dashboard — shows all client activity in one view.
    Requires a valid API key (any key; MSP keys have plan=msp in the key file).
    """
    onboarding = _require_onboarding()
    billing = _runtime.get("billing")
    tenants = onboarding.list_tenants()
    year_month = datetime.now(UTC).strftime("%Y-%m")

    tenant_rows: list[dict] = []
    fleet_requests = 0
    fleet_blocked  = 0
    fleet_cost     = 0.0

    # ── Aggregate masking stats from the log (last 31 days covers current month)
    _log_entries    = event_logger.load_entries(days=31)
    _masked_by_tid: dict[str, int] = {}
    _entity_by_tid: dict[str, dict[str, int]] = {}
    fleet_masked    = 0
    fleet_entities: dict[str, int] = {}
    for _le in _log_entries:
        _tid = _le.get("tenant_id", "default")
        _ec  = _le.get("entity_count", 0)
        if _ec:
            _masked_by_tid[_tid] = _masked_by_tid.get(_tid, 0) + _ec
            fleet_masked        += _ec
            for _et in _le.get("entities_detected", []):
                fleet_entities[_et] = fleet_entities.get(_et, 0) + 1
                if _tid not in _entity_by_tid:
                    _entity_by_tid[_tid] = {}
                _entity_by_tid[_tid][_et] = _entity_by_tid[_tid].get(_et, 0) + 1

    for t in tenants:
        tid = t["tenant_id"]
        if billing is not None:
            usage = billing.get_usage(tid, from_date=f"{year_month}-01")
        else:
            usage = {"requests": 0, "blocked": 0, "cost_usd": 0.0, "quota_usd": None, "quota_remaining": None}

        reqs    = usage.get("requests", 0)
        blocked = usage.get("blocked",  0)
        cost    = usage.get("cost_usd", 0.0)
        quota   = usage.get("quota_usd")
        masked  = _masked_by_tid.get(tid, 0)

        fleet_requests += reqs
        fleet_blocked  += blocked
        fleet_cost     += cost

        tenant_rows.append({
            "tenant_id":       tid,
            "label":           t.get("label", tid),
            "plan":            t.get("plan", "unknown"),
            "active":          t.get("active", True),
            "requests":        reqs,
            "blocked":         blocked,
            "masked_entities": masked,
            "block_rate":      round(blocked / reqs, 4) if reqs else 0.0,
            "cost_usd":        round(cost, 6),
            "quota_usd":       quota,
            "quota_pct":       round(cost / quota * 100, 1) if quota else None,
            "created_at":      t.get("created_at", ""),
        })

    # Sort by most blocked first for the demo table
    tenant_rows.sort(key=lambda r: r["blocked"], reverse=True)

    return {
        "month":          year_month,
        "fleet": {
            "tenants":          len(tenant_rows),
            "requests":         fleet_requests,
            "blocked":          fleet_blocked,
            "masked_entities":  fleet_masked,
            "top_entities":     fleet_entities,
            "block_rate":       round(fleet_blocked / fleet_requests, 4) if fleet_requests else 0.0,
            "cost_usd":         round(fleet_cost, 6),
        },
        "tenants": tenant_rows,
    }


@router.get(
    "/msp/report/{tenant_id}",
    tags=["msp"],
    summary="Monthly compliance report for a single tenant",
)
async def msp_report(
    tenant_id:  str,
    month:      str       = "",   # YYYY-MM; defaults to current calendar month
    fmt:        str       = "html",  # html | json | pdf
    brand_name: str       = "Shadow Warden AI",
    logo_url:   str | None = None,
    auth: AuthResult = Depends(require_api_key),
):
    """
    Generate a monthly compliance report for *tenant_id*.

    - **month** — ``YYYY-MM`` format (e.g. ``2026-02``). Defaults to the
      current calendar month.
    - **fmt** — ``html`` (default) returns a self-contained, print-ready HTML
      document. ``pdf`` renders via Playwright headless Chromium and returns a
      ``application/pdf`` attachment. ``json`` returns structured data for
      programmatic access.
    - **brand_name** — Override the "Shadow Warden AI" title for white-label
      deployments (default: ``"Shadow Warden AI"``).
    - **logo_url** — Optional URL to a tenant logo image displayed on the cover
      page (must be publicly accessible when rendering PDF).

    The report covers: executive summary, threat intelligence, PII intercepts,
    risk-level breakdown, daily activity, and auto-generated recommendations.
    """
    if not month:
        month = datetime.now(UTC).strftime("%Y-%m")

    # Basic format validation
    try:
        year_i, mon_i = map(int, month.split("-"))
        if not (1 <= mon_i <= 12):
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid month format {month!r} — expected YYYY-MM.",
        ) from exc

    engine = _get_report_engine()

    if fmt == "json":
        return engine.render_json(tenant_id, month)

    if fmt == "pdf":
        try:
            pdf_bytes = engine.render_pdf(
                tenant_id, month, brand_name=brand_name, logo_url=logo_url
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        filename = f"warden-report-{tenant_id}-{month}.pdf"
        return Response(
            content    = pdf_bytes,
            media_type = "application/pdf",
            headers    = {"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Default: HTML — return as a downloadable attachment
    html_bytes = engine.render_html(
        tenant_id, month, brand_name=brand_name, logo_url=logo_url
    ).encode("utf-8")
    filename   = f"warden-report-{tenant_id}-{month}.html"
    return Response(
        content     = html_bytes,
        media_type  = "text/html; charset=utf-8",
        headers     = {"Content-Disposition": f'attachment; filename="{filename}"'},
    )
