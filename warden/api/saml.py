"""
warden/api/saml.py
───────────────────
SAML 2.0 SSO endpoints (ENT-01) — extracted from main.py (architecture Phase 3).

Self-contained: the SAML provider lives on ``app.state.saml`` (set during
lifespan), resolved here via ``request.app.state`` — so this router never
imports ``warden.main``. Route paths and behaviour are identical to the previous
inline handlers; the route-inventory guard verifies the move changed nothing.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from warden.auth.saml_provider import SAMLProvider, SamlSession

log = logging.getLogger("warden.api.saml")

router = APIRouter(tags=["SSO"])


def _saml_request_data(request: Request, form_data: dict | None = None) -> dict:
    """Build the python3-saml request_data dict from a FastAPI Request."""
    https = request.headers.get("x-forwarded-proto", "http") == "https"
    return {
        "https":       "on" if https else "off",
        "http_host":   request.headers.get("host", "localhost"),
        "script_name": request.url.path,
        "server_port": str(request.url.port or (443 if https else 80)),
        "get_data":    dict(request.query_params),
        "post_data":   form_data or {},
    }


def _provider(request: Request) -> SAMLProvider:
    provider: SAMLProvider | None = getattr(request.app.state, "saml", None)
    if provider is None:
        raise HTTPException(503, "SAML SSO is not configured on this instance.")
    return provider


@router.get(
    "/auth/saml/metadata",
    summary="SAML 2.0 SP Metadata XML",
    response_class=JSONResponse,
    include_in_schema=True,
)
async def saml_metadata(request: Request):
    """Return the Service Provider metadata XML for IdP configuration."""
    provider = _provider(request)
    xml, errors = provider.get_metadata_xml()
    if errors:
        raise HTTPException(500, f"SAML metadata errors: {errors}")
    return Response(content=xml, media_type="application/xml")


@router.get(
    "/auth/saml/login",
    summary="Initiate SAML 2.0 login (redirect to IdP)",
    include_in_schema=True,
)
async def saml_login(request: Request, relay_state: str = ""):
    """Start the SAML login flow — redirect the browser to the IdP."""
    provider = _provider(request)
    rd = _saml_request_data(request)
    try:
        login_url = provider.build_login_url(rd, relay_state=relay_state)
    except Exception as exc:
        log.error("SAML login URL build failed: %s", exc)
        raise HTTPException(500, "Failed to build SAML login request.") from exc
    return RedirectResponse(url=login_url, status_code=302)


@router.post(
    "/auth/saml/acs",
    summary="SAML 2.0 Assertion Consumer Service (ACS)",
    include_in_schema=True,
)
async def saml_acs(request: Request):
    """Assertion Consumer Service — the IdP POSTs the signed SAMLResponse here."""
    provider = _provider(request)

    form = await request.form()
    form_data = dict(form.items())
    rd = _saml_request_data(request, form_data=form_data)

    try:
        session: SamlSession = provider.process_response(rd)
    except ValueError as exc:
        log.warning("SAML ACS rejected: %s", exc)
        raise HTTPException(401, str(exc)) from exc
    except Exception as exc:
        log.error("SAML ACS error: %s", exc)
        raise HTTPException(500, "SAML processing error.") from exc

    try:
        otp = provider.store_otp(session)
    except Exception as exc:
        log.error("SAML OTP store failed: %s", exc)
        raise HTTPException(500, "Failed to create login session.") from exc

    dashboard_url = os.getenv("DASHBOARD_URL", "http://localhost:8501")
    redirect_url  = f"{dashboard_url}?token={otp}"
    log.info("SAML ACS: login accepted for %s → redirecting to dashboard", session.email)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get(
    "/auth/saml/session",
    summary="Exchange SAML one-time token for a session JWT",
)
async def saml_session(request: Request, token: str):
    """Exchange the one-time token for a signed session JWT."""
    provider = _provider(request)

    session = provider.redeem_otp(token)
    if session is None:
        raise HTTPException(401, "Invalid or expired login token. Please log in again.")

    try:
        jwt_token = provider.issue_jwt(session)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc)) from exc

    return {
        "access_token": jwt_token,
        "token_type":   "bearer",
        "expires_in":   int(os.getenv("SAML_SESSION_TTL", "28800")),
        "email":        session.email,
        "name":         session.name,
        "tenant_id":    session.tenant_id,
    }


@router.get(
    "/auth/saml/verify",
    summary="Verify a session JWT (for dashboard middleware use)",
)
async def saml_verify(request: Request):
    """Verify the Bearer JWT in the Authorization header; return decoded payload."""
    provider = _provider(request)

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header.")

    token   = auth_header[len("Bearer "):]
    payload = provider.verify_jwt(token)
    if payload is None:
        raise HTTPException(401, "Invalid or expired JWT.")

    return payload
