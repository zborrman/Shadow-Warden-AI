"""
warden/auth/router.py
─────────────────────
The marketing site's own account endpoints — retired 2026-11-26.

Endpoints
─────────
  POST /auth/login   — 410, points at the portal sign-in
  POST /auth/signup  — 410, points at the portal sign-up
  POST /auth/logout  — clears any leftover site cookies
  GET  /auth/me      — reads a leftover sw_session cookie (1 h TTL), else 401

Why retired
───────────
In production `user_store` read and wrote `warden_core.portal_users`, the
portal's own account table. So the site login was a second password check on
portal accounts — no second factor, no per-account lockout (only a per-IP
limit, which an attacker rotating addresses does not meet) — and the site
sign-up created portal accounts outside the portal's enrolment. The cookie it
issued granted nothing but nav state. The portal (`/portal/auth/*`) is the one
place an account is created or used: strong password, TOTP, per-account
lockout, reset by emailed token.

Nothing here issues a credential any more. Do not bring the old handlers back:
add what is missing to the portal instead.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from warden.config import settings

_COOKIE = "sw_session"
_ALG = "HS256"
_DOMAIN = settings.auth_cookie_domain

PORTAL_LOGIN_URL = "https://portal.shadow-warden-ai.com/login"
PORTAL_REGISTER_URL = "https://portal.shadow-warden-ai.com/register"

try:
    from jose import JWTError as _JWTError
    from jose import jwt as _jwt
    _JOSE_OK = True
except ImportError:  # pragma: no cover
    _JOSE_OK = False
    _JWTError = Exception  # type: ignore[assignment,misc]


def _secret() -> str:
    s = os.getenv("AUTH_JWT_SECRET", "")
    if s:
        return s
    seed = os.getenv("VAULT_MASTER_KEY", "") or os.getenv("SAML_JWT_SECRET", "")
    if seed:
        return hashlib.sha256(f"auth:{seed}".encode()).hexdigest()
    raise RuntimeError("AUTH_JWT_SECRET is not configured")


def _decode(token: str) -> dict[str, Any] | None:
    if not _JOSE_OK:
        return None
    try:
        return _jwt.decode(token, _secret(), algorithms=[_ALG])
    except (_JWTError, RuntimeError):
        return None


router = APIRouter(prefix="/auth", tags=["auth"])


def _retired(where: str) -> JSONResponse:
    return JSONResponse(
        {"detail": "Site accounts are retired. Use the Shadow Warden portal.", "location": where},
        status_code=410,
        headers={"Link": f'<{where}>; rel="alternate"'},
    )


@router.post("/login", summary="Retired: sign in at the portal (410)")
async def login() -> JSONResponse:
    return _retired(PORTAL_LOGIN_URL)


@router.post("/signup", summary="Retired: create the account at the portal (410)")
async def signup() -> JSONResponse:
    return _retired(PORTAL_REGISTER_URL)


@router.post("/logout", summary="Clear session cookie")
async def logout() -> JSONResponse:
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(key=_COOKIE, domain=_DOMAIN, path="/")
    resp.delete_cookie(key="sw_logged_in", domain=_DOMAIN, path="/")
    return resp


@router.get("/me", summary="Return current session user (credential-aware CORS)")
async def me(request: Request) -> JSONResponse:
    token = request.cookies.get(_COOKIE)
    if not token:
        return JSONResponse({"authenticated": False}, status_code=401)
    payload = _decode(token)
    if not payload:
        return JSONResponse({"authenticated": False}, status_code=401)
    return JSONResponse(
        {"authenticated": True, "email": payload.get("sub"), "exp": payload.get("exp")}
    )
