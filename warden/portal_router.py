"""
warden/portal_router.py
━━━━━━━━━━━━━━━━━━━━━━━
Customer portal REST API.

Mounted at /portal in main.py.  All routes except /portal/auth/* require
a valid JWT Bearer token issued by POST /portal/auth/login.

Auth flow
─────────
  Register → POST /portal/auth/register  → {user_id, tenant_id}
  Login    → POST /portal/auth/login     → {access_token, token_type, expires_in}
             (refresh token in HttpOnly cookie)
  Refresh  → POST /portal/auth/refresh   → {access_token, ...}
  Logout   → POST /portal/auth/logout    → 204

JWT payload
───────────
  {sub: user_id, tid: tenant_id, role: "owner"|"member", exp, iat}

Environment variables
─────────────────────
  PORTAL_JWT_SECRET        — min 32 chars; generate with: openssl rand -hex 32
  PORTAL_ACCESS_TOKEN_TTL  — minutes (default 60)
  PORTAL_REFRESH_TOKEN_TTL — days (default 7)
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from warden.db.connection import get_db

log = logging.getLogger("warden.portal")

# ── Config ────────────────────────────────────────────────────────────────────

_JWT_SECRET      = os.getenv("PORTAL_JWT_SECRET", "change-me-" + secrets.token_hex(16))
_JWT_ALGORITHM   = "HS256"
_ACCESS_TTL_MIN  = int(os.getenv("PORTAL_ACCESS_TOKEN_TTL",  "60"))
_REFRESH_TTL_DAY = int(os.getenv("PORTAL_REFRESH_TOKEN_TTL", "7"))
_COOKIE_NAME     = "warden_refresh"

router = APIRouter(tags=["portal"])
_bearer = HTTPBearer(auto_error=False)


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _issue_access_token(user_id: str, tenant_id: str, role: str) -> str:
    exp = datetime.now(UTC) + timedelta(minutes=_ACCESS_TTL_MIN)
    payload = {"sub": user_id, "tid": tenant_id, "role": role, "exp": exp}
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def _issue_refresh_token(user_id: str) -> str:
    exp = datetime.now(UTC) + timedelta(days=_REFRESH_TTL_DAY)
    payload = {"sub": user_id, "type": "refresh", "exp": exp, "jti": secrets.token_hex(16)}
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def _issue_totp_session(user_id: str) -> str:
    """Short-lived (15 min) JWT issued after password OK but TOTP not yet verified."""
    exp = datetime.now(UTC) + timedelta(minutes=15)
    payload = {"sub": user_id, "type": "totp_pending", "exp": exp}
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}") from exc


# ── Auth dependency ───────────────────────────────────────────────────────────

class _PortalUser(BaseModel):
    user_id:   str
    tenant_id: str
    role:      str


async def require_portal_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> _PortalUser:
    if not creds:
        raise HTTPException(status_code=401, detail="Authorization header required.")
    claims = _decode_token(creds.credentials)
    if claims.get("type") == "refresh":
        raise HTTPException(status_code=401, detail="Use access token, not refresh token.")
    return _PortalUser(
        user_id=claims["sub"],
        tenant_id=claims["tid"],
        role=claims.get("role", "owner"),
    )


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class _RegisterIn(BaseModel):
    email:        EmailStr
    password:     str = Field(..., min_length=8)
    display_name: str = Field("", max_length=80)


class _LoginIn(BaseModel):
    email:    EmailStr
    password: str


class _TokenOut(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int  # seconds


class _CreateKeyIn(BaseModel):
    label:      str = Field("Default", max_length=60)
    rate_limit: int = Field(60, ge=1, le=10000)


class _PatchKeyIn(BaseModel):
    label:      str | None = Field(None, max_length=60)
    rate_limit: int | None = Field(None, ge=1, le=10000)


class _PatchMeIn(BaseModel):
    display_name: str | None = Field(None, max_length=80)
    notify_high:  bool | None = None
    notify_block: bool | None = None


class _ChangePasswordIn(BaseModel):
    current_password: str
    new_password:     str = Field(..., min_length=8)


class _ForgotPasswordIn(BaseModel):
    email: EmailStr


class _ResetPasswordIn(BaseModel):
    token:        str
    new_password: str = Field(..., min_length=8)


class _TotpCompleteIn(BaseModel):
    totp_session: str
    code:         str = Field(..., min_length=6, max_length=6)


class _TotpConfirmIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class _TotpDisableIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


# ── DB helpers ────────────────────────────────────────────────────────────────

async def _get_user_by_email(db: AsyncSession, email: str) -> dict | None:
    row = await db.execute(
        text("SELECT * FROM warden_core.portal_users WHERE email = :e"),
        {"e": email.lower()},
    )
    r = row.mappings().first()
    return dict(r) if r else None


async def _get_user_by_id(db: AsyncSession, user_id: str) -> dict | None:
    row = await db.execute(
        text("SELECT * FROM warden_core.portal_users WHERE id = :id"),
        {"id": user_id},
    )
    r = row.mappings().first()
    return dict(r) if r else None


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _reload_keys_file(tenant_id: str, key_hash: str, rate_limit: int, revoke: bool = False) -> None:
    """
    Append or revoke an entry in the WARDEN_API_KEYS_PATH JSON file so that
    auth_guard.py picks it up on next reload.  Fail-open — errors are logged.
    """
    import json

    keys_path = os.getenv("WARDEN_API_KEYS_PATH", "")
    if not keys_path:
        return
    try:
        try:
            with open(keys_path) as f:
                data: dict[str, Any] = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        if revoke:
            data.pop(key_hash, None)
        else:
            data[key_hash] = {"tenant_id": tenant_id, "rate_limit": rate_limit}

        tmp = keys_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, keys_path)
        log.info("portal: keys file updated (tenant=%s revoke=%s)", tenant_id, revoke)
    except Exception as exc:
        log.warning("portal: failed to update keys file — %s", exc)


# ── Auth endpoints ────────────────────────────────────────────────────────────

@router.post("/auth/register", status_code=201)
async def register(body: _RegisterIn, db: AsyncSession = Depends(get_db)):
    """Create a new customer account + tenant."""
    email = body.email.lower()
    existing = await _get_user_by_email(db, email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered.")

    tenant_id = f"tenant_{uuid.uuid4().hex[:12]}"
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    user_id = str(uuid.uuid4())

    await db.execute(
        text("""
            INSERT INTO warden_core.portal_users
                (id, email, password_hash, display_name, tenant_id, role)
            VALUES (:id, :email, :pw, :name, :tid, 'owner')
        """),
        {"id": user_id, "email": email, "pw": pw_hash,
         "name": body.display_name or email.split("@")[0], "tid": tenant_id},
    )
    await db.commit()
    log.info("portal: new user registered [user_id=%s tenant=%s]", user_id, tenant_id)
    return {"user_id": user_id, "tenant_id": tenant_id}


@router.post("/auth/login")
async def login(body: _LoginIn, response: Response, db: AsyncSession = Depends(get_db)):
    user = await _get_user_by_email(db, body.email.lower())
    if not user or not bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # If TOTP is enabled, issue a short-lived totp_session instead of full JWT
    if user.get("totp_enabled"):
        totp_session = _issue_totp_session(str(user["id"]))
        return {"requires_totp": True, "totp_session": totp_session}

    access  = _issue_access_token(str(user["id"]), user["tenant_id"], user["role"])
    refresh = _issue_refresh_token(str(user["id"]))

    await db.execute(
        text("UPDATE warden_core.portal_users SET last_login_at = NOW() WHERE id = :id"),
        {"id": str(user["id"])},
    )
    await db.commit()

    response.set_cookie(
        key=_COOKIE_NAME, value=refresh,
        httponly=True, secure=True, samesite="strict",
        max_age=_REFRESH_TTL_DAY * 86400,
    )
    return _TokenOut(access_token=access, expires_in=_ACCESS_TTL_MIN * 60)


@router.post("/auth/totp/complete")
async def totp_complete(body: _TotpCompleteIn, response: Response, db: AsyncSession = Depends(get_db)):
    """Step 2 of login when TOTP is enabled: verify 6-digit code and issue full JWT."""
    import pyotp  # noqa: PLC0415

    try:
        claims = _decode_token(body.totp_session)
    except HTTPException:
        raise HTTPException(status_code=401, detail="TOTP session expired or invalid.")

    if claims.get("type") != "totp_pending":
        raise HTTPException(status_code=401, detail="Invalid session token type.")

    user = await _get_user_by_id(db, claims["sub"])
    if not user or not user.get("totp_enabled") or not user.get("totp_secret"):
        raise HTTPException(status_code=401, detail="TOTP not configured for this account.")

    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid authenticator code.")

    access  = _issue_access_token(str(user["id"]), user["tenant_id"], user["role"])
    refresh = _issue_refresh_token(str(user["id"]))

    await db.execute(
        text("UPDATE warden_core.portal_users SET last_login_at = NOW() WHERE id = :id"),
        {"id": str(user["id"])},
    )
    await db.commit()

    response.set_cookie(
        key=_COOKIE_NAME, value=refresh,
        httponly=True, secure=True, samesite="strict",
        max_age=_REFRESH_TTL_DAY * 86400,
    )
    return _TokenOut(access_token=access, expires_in=_ACCESS_TTL_MIN * 60)


@router.post("/auth/totp/setup")
async def totp_setup(user: _PortalUser = Depends(require_portal_user), db: AsyncSession = Depends(get_db)):
    """Generate a new TOTP secret and return otpauth:// URI for QR code rendering."""
    import pyotp  # noqa: PLC0415

    row = await _get_user_by_id(db, user.user_id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    if row.get("totp_enabled"):
        raise HTTPException(status_code=409, detail="TOTP is already enabled. Disable it first.")

    secret = pyotp.random_base32()
    totp   = pyotp.TOTP(secret)
    email  = row["email"]
    uri    = totp.provisioning_uri(name=email, issuer_name="Shadow Warden AI")

    # Store secret (not yet enabled — confirmed by /auth/totp/confirm)
    await db.execute(
        text("UPDATE warden_core.portal_users SET totp_secret=:s, totp_enabled=FALSE WHERE id=:id"),
        {"s": secret, "id": user.user_id},
    )
    await db.commit()
    return {"secret": secret, "otpauth_uri": uri}


@router.post("/auth/totp/confirm", status_code=200)
async def totp_confirm(
    body: _TotpConfirmIn,
    user: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm the first TOTP code to activate 2FA on the account."""
    import pyotp  # noqa: PLC0415

    row = await _get_user_by_id(db, user.user_id)
    if not row or not row.get("totp_secret"):
        raise HTTPException(status_code=400, detail="Call /auth/totp/setup first.")
    if row.get("totp_enabled"):
        raise HTTPException(status_code=409, detail="TOTP already enabled.")

    totp = pyotp.TOTP(row["totp_secret"])
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code — try again.")

    await db.execute(
        text("UPDATE warden_core.portal_users SET totp_enabled=TRUE WHERE id=:id"),
        {"id": user.user_id},
    )
    await db.commit()
    log.info("portal: TOTP enabled for user %s", user.user_id)
    return {"totp_enabled": True}


@router.post("/auth/totp/disable", status_code=200)
async def totp_disable(
    body: _TotpDisableIn,
    user: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable TOTP — requires current authenticator code."""
    import pyotp  # noqa: PLC0415

    row = await _get_user_by_id(db, user.user_id)
    if not row or not row.get("totp_enabled") or not row.get("totp_secret"):
        raise HTTPException(status_code=400, detail="TOTP is not enabled.")

    totp = pyotp.TOTP(row["totp_secret"])
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid authenticator code.")

    await db.execute(
        text("UPDATE warden_core.portal_users SET totp_secret=NULL, totp_enabled=FALSE WHERE id=:id"),
        {"id": user.user_id},
    )
    await db.commit()
    log.info("portal: TOTP disabled for user %s", user.user_id)
    return {"totp_enabled": False}


@router.get("/auth/totp/status")
async def totp_status(
    user: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    """Return whether TOTP is enabled for the current user."""
    row = await _get_user_by_id(db, user.user_id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"totp_enabled": bool(row.get("totp_enabled"))}


@router.post("/auth/refresh", response_model=_TokenOut)
async def refresh_token(
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh: str | None = Cookie(None, alias=_COOKIE_NAME),
):
    if not refresh:
        raise HTTPException(status_code=401, detail="No refresh token.")
    claims = _decode_token(refresh)
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token.")

    user = await _get_user_by_id(db, claims["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    access      = _issue_access_token(str(user["id"]), user["tenant_id"], user["role"])
    new_refresh = _issue_refresh_token(str(user["id"]))
    response.set_cookie(
        key=_COOKIE_NAME, value=new_refresh,
        httponly=True, secure=True, samesite="strict",
        max_age=_REFRESH_TTL_DAY * 86400,
    )
    return _TokenOut(access_token=access, expires_in=_ACCESS_TTL_MIN * 60)


@router.post("/auth/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(_COOKIE_NAME)


@router.post("/auth/forgot-password", status_code=202)
async def forgot_password(body: _ForgotPasswordIn, db: AsyncSession = Depends(get_db)):
    """Generate a reset token (email delivery is out-of-scope for v1 — token returned in response)."""
    user = await _get_user_by_email(db, body.email.lower())
    if not user:
        return {"detail": "If the email exists, a reset link has been sent."}
    token = secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(hours=1)
    await db.execute(
        text("UPDATE warden_core.portal_users SET reset_token=:t, reset_expires=:e WHERE id=:id"),
        {"t": token, "e": expires, "id": str(user["id"])},
    )
    await db.commit()
    # TODO: send email. For now return token directly (dev mode).
    log.warning("portal: password reset token for %s (deliver via email in prod)", body.email)
    return {"detail": "Reset token issued.", "reset_token": token}


@router.post("/auth/reset-password", status_code=200)
async def reset_password(body: _ResetPasswordIn, db: AsyncSession = Depends(get_db)):
    row = await db.execute(
        text("SELECT * FROM warden_core.portal_users WHERE reset_token = :t"),
        {"t": body.token},
    )
    user = row.mappings().first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
    expires = user["reset_expires"]
    if expires and expires < datetime.now(UTC):
        raise HTTPException(status_code=400, detail="Reset token expired.")
    pw_hash = bcrypt.hashpw(body.new_password.encode(), bcrypt.gensalt()).decode()
    await db.execute(
        text("""
            UPDATE warden_core.portal_users
            SET password_hash=:pw, reset_token=NULL, reset_expires=NULL
            WHERE id=:id
        """),
        {"pw": pw_hash, "id": str(user["id"])},
    )
    await db.commit()
    return {"detail": "Password reset successfully."}


# ── /me ───────────────────────────────────────────────────────────────────────

@router.get("/me")
async def get_me(
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user_by_id(db, me.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "user_id":      str(user["id"]),
        "email":        user["email"],
        "display_name": user["display_name"],
        "tenant_id":    user["tenant_id"],
        "role":         user["role"],
        "notify_high":  user["notify_high"],
        "notify_block": user["notify_block"],
        "created_at":   user["created_at"].isoformat() if user["created_at"] else None,
        "last_login_at": user["last_login_at"].isoformat() if user["last_login_at"] else None,
    }


@router.patch("/me")
async def patch_me(
    body: _PatchMeIn,
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    updates: dict[str, Any] = {}
    if body.display_name is not None:
        updates["display_name"] = body.display_name
    if body.notify_high is not None:
        updates["notify_high"] = body.notify_high
    if body.notify_block is not None:
        updates["notify_block"] = body.notify_block
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update.")

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    updates["id"] = me.user_id
    await db.execute(
        text(f"UPDATE warden_core.portal_users SET {set_clause} WHERE id = :id"),
        updates,
    )
    await db.commit()
    return {"detail": "Updated."}


@router.post("/me/change-password")
async def change_password(
    body: _ChangePasswordIn,
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user_by_id(db, me.user_id)
    if not user or not bcrypt.checkpw(body.current_password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Current password incorrect.")
    pw_hash = bcrypt.hashpw(body.new_password.encode(), bcrypt.gensalt()).decode()
    await db.execute(
        text("UPDATE warden_core.portal_users SET password_hash=:pw WHERE id=:id"),
        {"pw": pw_hash, "id": me.user_id},
    )
    await db.commit()
    return {"detail": "Password changed."}


# ── /keys ─────────────────────────────────────────────────────────────────────

@router.get("/keys")
async def list_keys(
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    rows = await db.execute(
        text("""
            SELECT id, label, key_prefix, rate_limit, active, created_at, revoked_at
            FROM warden_core.portal_api_keys
            WHERE tenant_id = :tid
            ORDER BY created_at DESC
        """),
        {"tid": me.tenant_id},
    )
    return [
        {
            "id":          str(r["id"]),
            "label":       r["label"],
            "key_prefix":  r["key_prefix"],
            "rate_limit":  r["rate_limit"],
            "active":      r["active"],
            "created_at":  r["created_at"].isoformat() if r["created_at"] else None,
            "revoked_at":  r["revoked_at"].isoformat() if r["revoked_at"] else None,
        }
        for r in rows.mappings().all()
    ]


@router.post("/keys", status_code=201)
async def create_key(
    body: _CreateKeyIn,
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    raw_key    = "sw_live_" + secrets.token_urlsafe(32)
    key_hash   = _hash_key(raw_key)
    key_prefix = raw_key[:16] + "..."
    key_id     = str(uuid.uuid4())

    await db.execute(
        text("""
            INSERT INTO warden_core.portal_api_keys
                (id, tenant_id, label, key_hash, key_prefix, rate_limit, created_by)
            VALUES (:id, :tid, :label, :hash, :prefix, :rl, :by)
        """),
        {
            "id":     key_id,
            "tid":    me.tenant_id,
            "label":  body.label,
            "hash":   key_hash,
            "prefix": key_prefix,
            "rl":     body.rate_limit,
            "by":     me.user_id,
        },
    )
    await db.commit()
    _reload_keys_file(me.tenant_id, key_hash, body.rate_limit)
    log.info("portal: API key created [tenant=%s label=%s]", me.tenant_id, body.label)
    return {
        "id":          key_id,
        "key":         raw_key,   # shown exactly once
        "key_prefix":  key_prefix,
        "label":       body.label,
        "rate_limit":  body.rate_limit,
    }


@router.patch("/keys/{key_id}")
async def patch_key(
    key_id: str,
    body: _PatchKeyIn,
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    updates: dict[str, Any] = {}
    if body.label is not None:
        updates["label"] = body.label
    if body.rate_limit is not None:
        updates["rate_limit"] = body.rate_limit
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update.")
    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    updates.update({"id": key_id, "tid": me.tenant_id})
    await db.execute(
        text(f"UPDATE warden_core.portal_api_keys SET {set_clause} WHERE id=:id AND tenant_id=:tid"),
        updates,
    )
    await db.commit()
    return {"detail": "Updated."}


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_key(
    key_id: str,
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    row = await db.execute(
        text("SELECT key_hash FROM warden_core.portal_api_keys WHERE id=:id AND tenant_id=:tid"),
        {"id": key_id, "tid": me.tenant_id},
    )
    key = row.mappings().first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found.")
    await db.execute(
        text("""
            UPDATE warden_core.portal_api_keys
            SET active=false, revoked_at=NOW()
            WHERE id=:id AND tenant_id=:tid
        """),
        {"id": key_id, "tid": me.tenant_id},
    )
    await db.commit()
    _reload_keys_file(me.tenant_id, key["key_hash"], 0, revoke=True)
    log.info("portal: API key revoked [tenant=%s key_id=%s]", me.tenant_id, key_id)


# ── /stats ────────────────────────────────────────────────────────────────────

def _load_tenant_logs(tenant_id: str, days: int = 30) -> list[dict]:
    """Read NDJSON log filtered by tenant_id. Returns last `days` days of entries."""
    from warden.analytics.logger import load_entries
    entries = load_entries(days=days)
    return [e for e in entries if e.get("tenant_id") == tenant_id or tenant_id == "default"]


@router.get("/stats/summary")
async def stats_summary(me: _PortalUser = Depends(require_portal_user)):
    entries = _load_tenant_logs(me.tenant_id, days=30)
    total   = len(entries)
    blocked = sum(1 for e in entries if not e.get("allowed", True))
    allowed = total - blocked
    risk_dist: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "block": 0}
    for e in entries:
        lvl = e.get("risk_level", "low")
        if lvl in risk_dist:
            risk_dist[lvl] += 1
    return {
        "total":         total,
        "blocked":       blocked,
        "allowed":       allowed,
        "risk_dist":     risk_dist,
        "period_days":   30,
    }


@router.get("/stats/daily")
async def stats_daily(
    days: int = 30,
    me: _PortalUser = Depends(require_portal_user),
):
    entries = _load_tenant_logs(me.tenant_id, days=days)
    # Group by date
    from collections import defaultdict
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})
    for e in entries:
        ts = e.get("timestamp", "")[:10]  # YYYY-MM-DD
        if not ts:
            continue
        buckets[ts]["total"] += 1
        if not e.get("allowed", True):
            buckets[ts]["blocked"] += 1
        else:
            buckets[ts]["allowed"] += 1
    return [
        {"date": d, **v}
        for d, v in sorted(buckets.items())
    ]


@router.get("/stats/flags")
async def stats_flags(me: _PortalUser = Depends(require_portal_user)):
    entries = _load_tenant_logs(me.tenant_id, days=30)
    from collections import Counter
    counter: Counter[str] = Counter()
    for e in entries:
        for flag in e.get("flags", []):
            counter[flag] += 1
    return [{"flag": f, "count": c} for f, c in counter.most_common(10)]


# ── /billing placeholder ──────────────────────────────────────────────────────

@router.get("/billing")
async def billing(
    me: _PortalUser = Depends(require_portal_user),
    db: AsyncSession = Depends(get_db),
):
    period = datetime.now(UTC).strftime("%Y-%m")
    row = await db.execute(
        text("""
            SELECT requests, cost_usd
            FROM warden_core.billing_usage
            WHERE tenant_id=:tid AND period=:p
        """),
        {"tid": me.tenant_id, "p": period},
    )
    usage = row.mappings().first()
    return {
        "plan":              "Starter",
        "period":            period,
        "requests_used":     usage["requests"] if usage else 0,
        "requests_quota":    10000,
        "cost_usd":          float(usage["cost_usd"]) if usage else 0.0,
        "stripe_portal_url": None,  # wire in when Stripe is added
    }
