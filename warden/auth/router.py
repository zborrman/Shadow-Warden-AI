"""
warden/auth/router.py
─────────────────────
HttpOnly-cookie session auth for the Shadow Warden site.

Endpoints
─────────
  POST /auth/login   — validate credentials, set HttpOnly sw_session cookie
  POST /auth/logout  — delete the cookie
  GET  /auth/me      — return current user from cookie (CORS-safe, credentials:include)

Cookie strategy
───────────────
  • key=sw_session, httponly=True, secure=True, samesite=lax
  • domain=.shadow-warden-ai.com  (covers api.* and www.*)
  • max_age=3600  (env AUTH_SESSION_TTL to override)

User store
──────────
  AUTH_USERS_JSON  — JSON array: [{"email":"...", "password_hash":"<bcrypt>"}]
  AUTH_ADMIN_EMAIL + AUTH_ADMIN_PASSWORD_HASH  — single-user shortcut

Generate a bcrypt hash for password "changeme":
  python3 -c "import bcrypt; print(bcrypt.hashpw(b'changeme', bcrypt.gensalt()).decode())"
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any

import bcrypt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("warden.auth")

_COOKIE = "sw_session"
_ALG = "HS256"
_TTL = int(os.getenv("AUTH_SESSION_TTL", "3600"))
_DOMAIN = os.getenv("AUTH_COOKIE_DOMAIN", ".shadow-warden-ai.com")

try:
    from jose import JWTError as _JWTError
    from jose import jwt as _jwt  # type: ignore[import]
    _JOSE_OK = True
except ImportError:  # pragma: no cover
    _JOSE_OK = False
    _JWTError = Exception  # type: ignore[assignment,misc]


def _secret() -> str:
    s = os.getenv("AUTH_JWT_SECRET", "")
    if s:
        return s
    # Derive a deterministic secret from the existing vault key (dev/CI only).
    seed = os.getenv("VAULT_MASTER_KEY", "") or os.getenv("SAML_JWT_SECRET", "")
    if seed:
        return hashlib.sha256(f"auth:{seed}".encode()).hexdigest()
    raise RuntimeError("AUTH_JWT_SECRET is not configured")


def _load_users() -> dict[str, str]:
    """Return {email_lower: bcrypt_hash} from env config."""
    raw = os.getenv("AUTH_USERS_JSON", "")
    if raw:
        try:
            return {u["email"].lower(): u["password_hash"] for u in json.loads(raw)}
        except Exception as exc:
            log.warning("AUTH_USERS_JSON parse error: %s", exc)
    email = os.getenv("AUTH_ADMIN_EMAIL", "")
    pw_hash = os.getenv("AUTH_ADMIN_PASSWORD_HASH", "")
    if email and pw_hash:
        return {email.lower(): pw_hash}
    return {}


def _issue(email: str) -> str:
    if not _JOSE_OK:
        raise RuntimeError("python-jose not installed")
    now = int(time.time())
    return _jwt.encode(  # type: ignore[no-untyped-call]
        {"sub": email, "iat": now, "exp": now + _TTL},
        _secret(),
        algorithm=_ALG,
    )


def _decode(token: str) -> dict[str, Any] | None:
    if not _JOSE_OK:
        return None
    try:
        return _jwt.decode(token, _secret(), algorithms=[_ALG])  # type: ignore[no-untyped-call]
    except _JWTError:
        return None


# ── Router ─────────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", summary="Issue session cookie (HttpOnly, Secure)")
async def login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        email: str = (body.get("email") or "").strip().lower()
        password: str = body.get("password") or ""
    except Exception:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    users = _load_users()
    if not users:
        return JSONResponse(
            {"detail": "Auth not configured — set AUTH_USERS_JSON or AUTH_ADMIN_EMAIL/HASH"},
            status_code=503,
        )

    stored_hash = users.get(email)
    if not stored_hash:
        # Constant-time dummy check to prevent email enumeration via timing.
        bcrypt.checkpw(b"x", bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=4)))
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

    try:
        valid = bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception:
        valid = False

    if not valid:
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

    try:
        token = _issue(email)
    except RuntimeError as exc:
        log.error("auth token issue failed: %s", exc)
        return JSONResponse({"detail": str(exc)}, status_code=500)

    resp = JSONResponse({"ok": True, "email": email})
    resp.set_cookie(
        key=_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        domain=_DOMAIN,
        max_age=_TTL,
        path="/",
    )
    return resp


@router.post("/logout", summary="Clear session cookie")
async def logout() -> JSONResponse:
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(key=_COOKIE, domain=_DOMAIN, path="/")
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
