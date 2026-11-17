"""
warden/auth_guard.py
━━━━━━━━━━━━━━━━━━━
Per-tenant API-key authentication for the Warden gateway.

Key store
─────────
  • Single-key mode (env var): set WARDEN_API_KEY to a shared secret.
    All requests using that key are mapped to tenant_id="default".
  • Multi-key mode (JSON file): set WARDEN_API_KEYS_PATH to a JSON file
    containing an array of key objects.  Each key is mapped to a tenant_id
    and can be individually rotated (active/revoked).

Dev mode: both env var and file path unset → all requests pass through
with tenant_id="default".

JSON key file format::

    {
      "keys": [
        {
          "key_hash": "<sha256 hex digest of the API key>",
          "tenant_id": "acme-corp",
          "label": "production key",
          "active": true,
          "rate_limit": 120,
          "created_at": "2025-01-01T00:00:00Z",
          "rotated_at": null
        }
      ]
    }

``rate_limit`` (optional) — requests per minute for this key.  Omit to use the
``TENANT_RATE_LIMIT`` env var (default 60).

Generate a key hash::

    python -c "import hashlib; print(hashlib.sha256(b'your-api-key').hexdigest())"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, Form, Header, HTTPException, Query, Security, status
from fastapi import Path as PathParam
from fastapi.security import APIKeyHeader

from warden.config import settings

log = logging.getLogger("warden.auth")

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Single shared key (backwards compatible) ─────────────────────────────────
_VALID_KEY: str = settings.warden_api_key

# ── Multi-key file ───────────────────────────────────────────────────────────
_KEYS_PATH: str = settings.warden_api_keys_path

# Default per-key rate limit; individual keys can override via their JSON entry.
# Stored in a list so set_default_rate_limit() can mutate it without a global stmt.
_DEFAULT_KEY_RATE: int = settings.tenant_rate_limit
_rate_limit_box: list[int] = [_DEFAULT_KEY_RATE]


def set_default_rate_limit(per_minute: int) -> None:
    """Live-update the default rate limit without a container restart.

    Called by POST /api/config when rate_limit_per_minute is set.
    Per-tenant overrides in WARDEN_API_KEYS_PATH are not affected.
    """
    _rate_limit_box[0] = max(1, per_minute)
    os.environ["RATE_LIMIT_PER_MINUTE"] = str(_rate_limit_box[0])

MAX_KEYS = 1000  # safety cap


@dataclass(frozen=True)
class _KeyEntry:
    key_hash:   str
    tenant_id:  str
    label:      str
    active:     bool
    rate_limit: int = 60  # requests per minute; overridden per-key from JSON


_key_store: list[_KeyEntry] = []
_key_store_loaded = False


def _load_key_store() -> list[_KeyEntry]:
    """Load multi-tenant key store from JSON file.  Called once on first auth."""
    global _key_store_loaded
    if _key_store_loaded:
        return _key_store

    _key_store_loaded = True

    if not _KEYS_PATH:
        return _key_store

    path = Path(_KEYS_PATH)
    if not path.exists():
        log.warning("WARDEN_API_KEYS_PATH=%s does not exist — multi-key auth disabled.", _KEYS_PATH)
        return _key_store

    try:
        data = json.loads(path.read_text())
        for entry in data.get("keys", [])[:MAX_KEYS]:
            _key_store.append(_KeyEntry(
                key_hash=entry["key_hash"],
                tenant_id=entry.get("tenant_id", "default"),
                label=entry.get("label", ""),
                active=entry.get("active", True),
                rate_limit=int(entry.get("rate_limit", _DEFAULT_KEY_RATE)),
            ))
        log.info("Loaded %d API key(s) from %s", len(_key_store), _KEYS_PATH)
    except Exception:
        log.exception("Failed to load API keys from %s", _KEYS_PATH)

    return _key_store


def _lookup_multi_key(api_key: str) -> _KeyEntry | None:
    """Check api_key against the multi-key store.  Returns the matching entry or None."""
    incoming_hash = hashlib.sha256(api_key.encode()).hexdigest()
    store = _load_key_store()
    for entry in store:
        if hmac.compare_digest(incoming_hash, entry.key_hash) and entry.active:
            return entry
    return None


@dataclass(frozen=True)
class AuthResult:
    """Returned by require_api_key — carries resolved tenant_id, rate limit, and ERS score."""
    api_key:     str
    tenant_id:   str
    rate_limit:  int   = 60     # requests per minute
    ers_score:   float = 0.0    # Entity Risk Score 0.0–1.0 (populated by main.py after auth)
    shadow_ban:  bool  = False  # True when ERS >= ERS_SHADOW_BAN_THRESHOLD
    entity_key:  str   = ""     # SHA-256[:16] of tenant_id:ip (GDPR-safe)
    last_flag:   str   = ""     # ERS event type with highest weighted contribution (audit log)


def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> AuthResult:
    """
    FastAPI Security dependency.

    Resolution order:
      1. Multi-key file (WARDEN_API_KEYS_PATH) — SHA-256 hash lookup
      2. Single shared key (WARDEN_API_KEY) — constant-time compare
      3. Dev mode (both unset) — all requests pass
    """
    # Dev / air-gapped mode
    if not _VALID_KEY and not _KEYS_PATH:
        return AuthResult(api_key="", tenant_id="default", rate_limit=_DEFAULT_KEY_RATE)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 1. Try multi-key store
    if _KEYS_PATH:
        entry = _lookup_multi_key(api_key)
        if entry:
            return AuthResult(api_key=api_key, tenant_id=entry.tenant_id,
                              rate_limit=entry.rate_limit)

    # 2. Single shared key
    if _VALID_KEY and hmac.compare_digest(api_key.encode(), _VALID_KEY.encode()):
        return AuthResult(api_key=api_key, tenant_id="default",
                          rate_limit=_DEFAULT_KEY_RATE)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key header.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def bind_tenant(auth: AuthResult, claimed: str | None, x_admin_key: str | None = None) -> str:
    """The tenant a request acts on, given the tenant it *claims* to act on.

    A tenant id in a query string, path or body is caller-supplied text; taken at
    its word it lets one tenant read and change another's rows by typing a name.
    The caller's own tenant (resolved from its API key) is the answer, and a
    claim that names it — or names nothing — changes nothing.

    A claim that names a different tenant is honoured for the operator only:
      * a valid ``X-Admin-Key``, or
      * the master key, which resolves to ``"default"``. It is the key the
        gateway's own tools (SOVA, the admin UI, the portal's server proxy) call
        with on behalf of a named tenant, and it is the only identity in
        single-key and unauthenticated dev mode. Never issue a customer a key
        mapped to ``"default"``.
    Anyone else gets 403 — an explicit refusal, not a silent substitution, so a
    client that asked for tenant A is never handed tenant B's data labelled A.
    """
    claim = (claimed or "").strip()
    if not claim or claim == auth.tenant_id:
        return auth.tenant_id
    if _is_operator(auth, x_admin_key):
        return claim
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This API key cannot act on another tenant.",
    )


def caller_tenant(
    auth: AuthResult = Depends(require_api_key),
    tenant_id: str | None = Query(default=None),
    x_admin_key: str | None = Header(default=None),
) -> str:
    """FastAPI dependency: ``tenant_id: str = Depends(caller_tenant)``.

    Replaces a bare ``tenant_id: str`` query parameter. The parameter keeps its
    name and stays optional, so existing clients that send their own tenant keep
    working; see :func:`bind_tenant` for what a foreign value gets.
    """
    return bind_tenant(auth, tenant_id, x_admin_key)


def caller_tenant_path(
    auth: AuthResult = Depends(require_api_key),
    tenant_id: str = PathParam(...),
    x_admin_key: str | None = Header(default=None),
) -> str:
    """:func:`caller_tenant` for a route whose URL carries ``{tenant_id}``.

    The path segment stays where it is, so no client URL changes; a segment that
    names another tenant is refused by :func:`bind_tenant`.
    """
    return bind_tenant(auth, tenant_id, x_admin_key)


def caller_tenant_header(
    auth: AuthResult = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None),
    x_admin_key: str | None = Header(default=None),
) -> str:
    """:func:`caller_tenant` for a route that reads the tenant from ``X-Tenant-ID``."""
    return bind_tenant(auth, x_tenant_id, x_admin_key)


def caller_tenant_form(
    auth: AuthResult = Depends(require_api_key),
    tenant_id: str | None = Form(default=None),
    x_admin_key: str | None = Header(default=None),
) -> str:
    """:func:`caller_tenant` for a multipart upload that sends ``tenant_id`` as a form field."""
    return bind_tenant(auth, tenant_id, x_admin_key)


@dataclass(frozen=True)
class CallerTenant:
    """What a handler needs to bind a tenant that arrives in the request body.

    ``tenant_id`` in a JSON body is caller-supplied text exactly like the query
    parameter :func:`caller_tenant` replaced; the parameter scanner could not
    see it, so 39 write routes protected only by a plan gate let a paying tenant
    act on any other by naming it (re-audit 2026-11-16). Use::

        caller: CallerTenant = Depends(caller_binding)
        ...
        body.tenant_id = caller.bind(body.tenant_id)

    ``auth`` is ``None`` only on a route that is anonymous by design
    (:func:`optional_caller_binding`).
    """

    auth: AuthResult | None
    x_admin_key: str | None = None

    def bind(self, claimed: str | None) -> str:
        if self.auth is not None:
            return bind_tenant(self.auth, claimed, self.x_admin_key)
        claim = (claimed or "").strip()
        # No key presented. Dev/test (auth off) keeps the claim, as the tier
        # header does; so does the operator's admin key. Anyone else owns no
        # tenant, and is recorded as exactly that.
        if claim and (tier_header_trusted() or _is_operator_key(self.x_admin_key)):
            return claim
        return "anonymous"


def caller_binding(
    auth: AuthResult = Depends(require_api_key),
    x_admin_key: str | None = Header(default=None),
) -> CallerTenant:
    """Dependency for an authenticated route whose body names a tenant."""
    return CallerTenant(auth, x_admin_key)


def optional_caller_binding(
    x_api_key: str | None = Security(_API_KEY_HEADER),
    x_admin_key: str | None = Header(default=None),
) -> CallerTenant:
    """For a route that is anonymous by design (registration, a free scanner).

    A presented key binds exactly as :func:`caller_binding` does; no key binds
    to ``"anonymous"``. It never raises for a missing key, so a public route
    stays public.
    """
    tenant = resolve_tenant_id(x_api_key)
    auth = AuthResult(api_key=x_api_key or "", tenant_id=tenant) if tenant else None
    return CallerTenant(auth, x_admin_key)


def request_tenant(request: object, default: str = "unknown") -> str:
    """The tenant a request authenticates as, for code that only has the request.

    Replaces ``request.headers.get("X-Tenant-ID")``. That header is written by
    the caller, and the code reading it decided whose add-on was checked, whose
    credits were spent and whose usage was billed. The answer is the tenant the
    presented key resolves to; the header is honoured only where auth is off
    (dev/test), as the tier header is.
    """
    state = getattr(request, "state", None)
    tenant = getattr(state, "tenant", None)
    if isinstance(tenant, dict) and (tenant.get("tenant_id") or tenant.get("id")):
        return str(tenant.get("tenant_id") or tenant.get("id"))
    raw = getattr(request, "headers", {}) or {}
    # Starlette headers are case-insensitive; a plain mapping is not.
    headers = {str(k).lower(): v for k, v in raw.items()}
    key = headers.get("x-api-key") or ""
    if not key:
        bearer = headers.get("authorization", "")
        if bearer[:7].lower() == "bearer ":
            key = bearer[7:]
    resolved = resolve_tenant_id(key)
    if resolved:
        return resolved
    if tier_header_trusted():
        return headers.get("x-tenant-id") or default
    return default


def _is_operator_key(x_admin_key: str | None) -> bool:
    admin_key = os.getenv("ADMIN_KEY", "")
    return bool(x_admin_key and admin_key and hmac.compare_digest(x_admin_key, admin_key))


def _is_operator(auth: AuthResult, x_admin_key: str | None) -> bool:
    if auth.tenant_id == "default":
        return True
    admin_key = os.getenv("ADMIN_KEY", "")
    return bool(x_admin_key and admin_key and hmac.compare_digest(x_admin_key, admin_key))


def caller_tenant_scope(
    auth: AuthResult = Depends(require_api_key),
    tenant_id: str | None = Query(default=None),
    x_admin_key: str | None = Header(default=None),
) -> str | None:
    """For a listing where ``tenant_id`` was an optional filter and ``None`` meant
    "every tenant".

    Only the operator keeps that meaning. A customer key that names no tenant is
    scoped to its own — the unfiltered view was every tenant's rows — and one
    that names another is refused, as in :func:`bind_tenant`.
    """
    claim = (tenant_id or "").strip()
    if not claim:
        return None if _is_operator(auth, x_admin_key) else auth.tenant_id
    return bind_tenant(auth, claim, x_admin_key)


def public_tenant_filter(tenant_id: str | None = Query(default=None)) -> str | None:
    """A ``tenant_id`` filter on a route that is public on purpose.

    No authentication, and none is implied: use it only where every row the
    route can return is already public (recorded with a reason in
    ``warden/tests/anonymous_read_baseline.json``), so the value narrows a public
    listing and cannot reach anything private. Anything else takes
    :func:`caller_tenant`.
    """
    return (tenant_id or "").strip() or None


def caller_label(x_api_key: str | None = Header(default=None)) -> str:
    """The caller's tenant for a log line on a route that does not require a key.

    Derived from the key when one is sent, ``"anonymous"`` otherwise — never from
    a field the caller typed.
    """
    return resolve_tenant_id(x_api_key) or "anonymous"


def tier_header_trusted() -> bool:
    """Whether a client-supplied ``X-Tenant-Tier`` header may set the plan tier.

    Honoured only when auth is not enforced (dev / air-gapped / test). In
    production — a real key configured and ``ALLOW_UNAUTHENTICATED`` off — the
    header is spoofable and must be ignored; the tier is derived from the
    authenticated tenant's billing plan instead.
    """
    if settings.allow_unauthenticated:
        return True
    return not _VALID_KEY and not _KEYS_PATH


def resolve_tenant_id(api_key: str | None) -> str | None:
    """Best-effort tenant_id for *api_key* without raising; ``None`` if unresolved.

    Mirrors :func:`require_api_key`'s lookup but never raises, so callers can
    derive the authenticated tenant's real plan tier. Returns ``None`` in dev
    mode (no auth configured) so callers fall back to their own defaults.
    """
    if not _VALID_KEY and not _KEYS_PATH:
        return None
    if not api_key:
        return None
    if _KEYS_PATH:
        entry = _lookup_multi_key(api_key)
        if entry:
            return entry.tenant_id
    if _VALID_KEY and hmac.compare_digest(api_key.encode(), _VALID_KEY.encode()):
        return "default"
    return None


def get_rate_limit(api_key: str) -> int:
    """Return the configured rate limit (req/min) for an API key.

    Used by the slowapi key_func to set per-tenant limits without performing
    full auth validation.  Falls back to _DEFAULT_KEY_RATE for unknown keys.
    """
    if not api_key:
        return _rate_limit_box[0]
    if _KEYS_PATH:
        entry = _lookup_multi_key(api_key)
        if entry:
            return entry.rate_limit
    if _VALID_KEY and hmac.compare_digest(api_key.encode(), _VALID_KEY.encode()):
        return _rate_limit_box[0]
    return _rate_limit_box[0]


def reload_keys() -> int:
    """Force-reload the key store from disk.  Returns the new key count."""
    global _key_store_loaded
    _key_store.clear()
    _key_store_loaded = False
    _load_key_store()
    return len(_key_store)


# ── Warden Identity — hybrid auth for /ext/* routes ──────────────────────────
#
# Browser-extension requests can authenticate via either:
#   • Authorization: Bearer <OIDC id_token>   (Google Workspace / Entra ID)
#   • X-API-Key: <key>                         (enterprise agents / air-gap)
#
# The OIDC path performs RS256 signature verification against cached JWKS keys
# (<1 ms per request after the first daily fetch).  The X-API-Key path falls
# through to the existing require_api_key logic unchanged.

def require_ext_auth(
    x_api_key:     str | None = Security(_API_KEY_HEADER),
    authorization: str | None = Header(None, alias="Authorization"),
) -> AuthResult:
    """
    Hybrid FastAPI dependency for /ext/* routes.

    Resolution order:
      1. Authorization: Bearer <oidc_token>  → Warden Identity (OIDC)
      2. X-API-Key: <key>                   → classic API-key auth
      3. Dev mode (no key configured)       → pass-through as tenant 'default'
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
        from warden.auth.oidc_guard import (
            verify_oidc_token,  # lazy import — avoids loading JWKS at startup
        )
        tenant_id, email = verify_oidc_token(token)
        # GDPR: never log the raw email (PII) — log a stable hash prefix instead.
        _email_h = hashlib.sha256((email or "").encode()).hexdigest()[:12]
        log.info("OIDC auth: email_hash=%s tenant=%s", _email_h, tenant_id)
        return AuthResult(
            api_key   = "",
            tenant_id = tenant_id,
            rate_limit= _DEFAULT_KEY_RATE,
            entity_key= hashlib.sha256(f"{tenant_id}:oidc:{email}".encode()).hexdigest()[:16],
        )

    return require_api_key(x_api_key)
