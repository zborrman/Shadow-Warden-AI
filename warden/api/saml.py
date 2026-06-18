"""
warden/api/saml.py  (ENT-01)
──────────────────────────────
FastAPI router — /auth/saml/*

GET  /auth/saml/login      → redirect to IdP
POST /auth/saml/acs        → SAML Response → set session cookie
GET  /auth/saml/metadata   → SP metadata XML
POST /auth/saml/logout     → clear session
"""
from __future__ import annotations

from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response

router = APIRouter(prefix="/auth/saml", tags=["SSO / SAML"])


@router.get("/login")
async def saml_login():
    """Redirect to SAML IdP for authentication."""
    try:
        from warden.auth.saml import build_authn_request  # noqa: PLC0415
        sso_url, relay_state = await build_authn_request()
        resp = RedirectResponse(sso_url, status_code=302)
        resp.set_cookie("saml_relay", relay_state, httponly=True, samesite="lax", max_age=600)
        return resp
    except Exception as exc:
        return HTMLResponse(f"<h1>SSO Error</h1><p>{exc}</p>", status_code=500)


@router.post("/acs")
async def saml_acs(SAMLResponse: str = Form(...), RelayState: str = Form(default="")):  # noqa: N803
    """Assertion Consumer Service — process SAML Response and start session."""
    try:
        from warden.auth.saml import process_acs  # noqa: PLC0415
        user = await process_acs(SAMLResponse)
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(
            "warden_sso_session",
            f"{user.tenant_id}:{user.email}",
            httponly=True, samesite="strict", max_age=86400,
        )
        return resp
    except Exception as exc:
        return HTMLResponse(
            f"<h1>SSO Authentication Failed</h1><p>{exc}</p>",
            status_code=401,
        )


@router.get("/metadata")
async def saml_metadata():
    """Return SP metadata XML for IdP registration."""
    from warden.auth.saml import sp_metadata_xml  # noqa: PLC0415
    xml = sp_metadata_xml()
    return Response(content=xml, media_type="application/samlmetadata+xml")


@router.post("/logout")
async def saml_logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("warden_sso_session")
    return resp
