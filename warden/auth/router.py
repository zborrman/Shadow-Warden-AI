"""
warden/auth/router.py
─────────────────────
HttpOnly-cookie session auth for the Shadow Warden site.

Endpoints
─────────
  POST /auth/login   — validate credentials, set HttpOnly sw_session cookie
  POST /auth/signup  — register new user, auto-login (same cookie)
  POST /auth/logout  — delete the cookie
  GET  /auth/me      — return current user from cookie (CORS-safe, credentials:include)

Cookie strategy
───────────────
  • key=sw_session, httponly=True, secure=True, samesite=lax
  • domain=.shadow-warden-ai.com  (covers api.* and www.*)
  • max_age=3600  (env AUTH_SESSION_TTL to override)

User store (priority order)
───────────────────────────
  1. SQLite DB at AUTH_DB_PATH (default /tmp/warden_auth.db) — writable, persists registrations
  2. AUTH_USERS_JSON — JSON array: [{"email":"...", "password_hash":"<bcrypt>"}]
  3. AUTH_ADMIN_EMAIL + AUTH_ADMIN_PASSWORD_HASH — single-user shortcut

Generate a bcrypt hash:
  python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpass', bcrypt.gensalt()).decode())"
"""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import bcrypt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from warden.config import settings
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.auth")

_COOKIE = "sw_session"
_ALG = "HS256"
_TTL = settings.auth_session_ttl
_DOMAIN = settings.auth_cookie_domain
_DB_PATH = settings.auth_db_path

# Signup rate limit: max 5 registrations per IP per hour
_SIGNUP_RATE_LIMIT = settings.auth_signup_rate_limit
_SIGNUP_RATE_WINDOW = 3600
_rate_lock = threading.Lock()
_rate_store: dict[str, list[float]] = collections.defaultdict(list)

try:
    from jose import JWTError as _JWTError
    from jose import jwt as _jwt
    _JOSE_OK = True
except ImportError:  # pragma: no cover
    _JOSE_OK = False
    _JWTError = Exception  # type: ignore[assignment,misc]

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── SQLite user store ──────────────────────────────────────────────────────────

_AUTH_DDL = """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT    NOT NULL,
        created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );
"""
register("auth", "warden.auth.router", _AUTH_DDL)


@contextmanager
def _db() -> Generator[sqlite3.Connection, None, None]:
    with open_db("auth", _DB_PATH, module_default_path=_DB_PATH) as con:
        yield con


def _db_get_user(email: str) -> str | None:
    """Return bcrypt hash for email from SQLite, or None."""
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()
        return row[0] if row else None
    except Exception as exc:
        log.warning("auth db read error: %s", exc)
        return None


def _db_create_user(email: str, pw_hash: str) -> bool:
    """Insert user. Returns False if email already exists."""
    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash)
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as exc:
        log.error("auth db write error: %s", exc)
        return False


def _load_env_users() -> dict[str, str]:
    """Return {email_lower: bcrypt_hash} from env-var config (read-only, pre-seeded accounts)."""
    raw = settings.auth_users_json
    if raw:
        try:
            return {u["email"].lower(): u["password_hash"] for u in json.loads(raw)}
        except Exception as exc:
            log.warning("AUTH_USERS_JSON parse error: %s", exc)
    email = settings.auth_admin_email
    pw_hash = settings.auth_admin_password_hash
    if email and pw_hash:
        return {email.lower(): pw_hash}
    return {}


def _email_exists(email: str) -> bool:
    """Check both SQLite DB and env-var users."""
    if _db_get_user(email) is not None:
        return True
    return email.lower() in _load_env_users()


def _lookup_password_hash(email: str) -> str | None:
    """Return stored hash from SQLite first, then env users."""
    h = _db_get_user(email)
    if h:
        return h
    return _load_env_users().get(email.lower())


# ── JWT helpers ────────────────────────────────────────────────────────────────

def _secret() -> str:
    s = os.getenv("AUTH_JWT_SECRET", "")
    if s:
        return s
    seed = os.getenv("VAULT_MASTER_KEY", "") or os.getenv("SAML_JWT_SECRET", "")
    if seed:
        return hashlib.sha256(f"auth:{seed}".encode()).hexdigest()
    raise RuntimeError("AUTH_JWT_SECRET is not configured")


def _issue(email: str) -> str:
    if not _JOSE_OK:
        raise RuntimeError("python-jose not installed")
    now = int(time.time())
    return _jwt.encode(
        {"sub": email, "iat": now, "exp": now + _TTL},
        _secret(),
        algorithm=_ALG,
    )


def _decode(token: str) -> dict[str, Any] | None:
    if not _JOSE_OK:
        return None
    try:
        return _jwt.decode(token, _secret(), algorithms=[_ALG])
    except _JWTError:
        return None


def _set_session_cookie(resp: JSONResponse) -> None:
    """Attach the sw_session HttpOnly cookie to a response."""
    # value already embedded in resp; cookie is set by caller after _issue()
    pass


def _rate_check(ip: str) -> bool:
    """Return True if IP is within rate limit, False if exceeded."""
    now = time.time()
    cutoff = now - _SIGNUP_RATE_WINDOW
    with _rate_lock:
        timestamps = _rate_store[ip]
        # evict old entries
        _rate_store[ip] = [t for t in timestamps if t > cutoff]
        if len(_rate_store[ip]) >= _SIGNUP_RATE_LIMIT:
            return False
        _rate_store[ip].append(now)
    return True


# ── Router ─────────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/auth", tags=["auth"])


def _cookie_response(email: str, *, status: int = 200, body: dict | None = None) -> JSONResponse:
    """Build a JSONResponse with the session cookie set."""
    token = _issue(email)
    resp = JSONResponse(body or {"ok": True, "email": email}, status_code=status)
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
    # Non-HttpOnly indicator cookie — lets client JS detect auth state without an API call.
    # Does NOT carry the JWT; only signals "a session exists" (safe to read via JS).
    resp.set_cookie(
        key="sw_logged_in",
        value="1",
        httponly=False,
        secure=True,
        samesite="lax",
        domain=_DOMAIN,
        max_age=_TTL,
        path="/",
    )
    return resp


@router.post("/login", summary="Issue session cookie (HttpOnly, Secure)")
async def login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        email: str = (body.get("email") or "").strip().lower()
        password: str = body.get("password") or ""
    except Exception:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    stored_hash = _lookup_password_hash(email)
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
        return _cookie_response(email)
    except RuntimeError as exc:
        log.error("auth token issue failed: %s", exc)
        return JSONResponse({"detail": str(exc)}, status_code=500)


@router.post("/signup", summary="Register new account and auto-login (HttpOnly cookie)")
async def signup(request: Request) -> JSONResponse:
    # Rate limit by client IP
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown").split(",")[0].strip()
    if not _rate_check(client_ip):
        return JSONResponse(
            {"detail": "Too many registration attempts. Please try again later."},
            status_code=429,
        )

    try:
        body = await request.json()
        email: str = (body.get("email") or "").strip().lower()
        password: str = body.get("password") or ""
    except Exception:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    # Validate email format
    if not email or not _EMAIL_RE.match(email):
        return JSONResponse({"detail": "Invalid email address."}, status_code=422)

    # Validate password length
    if len(password) < 8:
        return JSONResponse({"detail": "Password must be at least 8 characters."}, status_code=422)

    # Reject if already registered
    if _email_exists(email):
        return JSONResponse({"detail": "An account with this email already exists."}, status_code=409)

    # Hash password and store
    try:
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as exc:
        log.error("bcrypt hash failed: %s", exc)
        return JSONResponse({"detail": "Registration failed. Please try again."}, status_code=500)

    if not _db_create_user(email, pw_hash):
        return JSONResponse({"detail": "An account with this email already exists."}, status_code=409)

    log.info("new user registered: %s", email)

    try:
        return _cookie_response(email, body={"ok": True, "email": email, "created": True})
    except RuntimeError as exc:
        log.error("auth token issue failed: %s", exc)
        return JSONResponse({"detail": str(exc)}, status_code=500)


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
