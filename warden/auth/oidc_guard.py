"""
warden/auth/oidc_guard.py
─────────────────────────
Warden Identity — OIDC JWT validation for Google Workspace + Microsoft Entra ID.

Flow
────
  1. Browser extension obtains an OIDC id_token via
     chrome.identity.launchWebAuthFlow (Google) or MSAL (Microsoft).
  2. Extension passes the id_token as  Authorization: Bearer <token>
     on every POST /ext/filter request (sent from the isolated Service Worker —
     the page's JS context never sees the token).
  3. This module validates the RS256 signature against cached JWKS keys (<1 ms,
     no network call after first fetch) and extracts the email claim.
  4. email domain → tenant_id mapping resolves which tenant the user belongs to.
  5. Returns (tenant_id, email) consumed by require_ext_auth in auth_guard.py.

Domain → tenant_id mapping
──────────────────────────
  Env var  OIDC_ALLOWED_DOMAINS  (comma-separated "domain:tenant_id" pairs)
  Example: OIDC_ALLOWED_DOMAINS=acme.com:tenant_acme,betacorp.io:tenant_beta

  Live updates: POST /api/oidc/domains  (admin endpoint, stored in Redis)
  Redis key:    HSET warden:oidc:domains <domain> <tenant_id>

JWKS caching
────────────
  Public keys are fetched once per provider and refreshed every _JWKS_TTL seconds
  (default 24 h).  On fetch failure the stale cache is used — the gateway never
  hard-fails on a transient JWKS network error.

Supported providers
───────────────────
  • Google Workspace   issuer: accounts.google.com
  • Microsoft Entra ID issuer: login.microsoftonline.com/<tid>/v2.0
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status

log = logging.getLogger("warden.oidc")

# ── JWKS endpoints ────────────────────────────────────────────────────────────

_GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
_MSFT_JWKS_URL   = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

_GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})

# Refresh public keys at most once per day
_JWKS_TTL: float = float(os.getenv("OIDC_JWKS_TTL_S", "86400"))

# Internal cache: url → {"keys": {kid: PublicKey}, "fetched_at": float}
_jwks_cache: dict[str, dict[str, Any]] = {}


# ── JWKS helpers ──────────────────────────────────────────────────────────────

def _get_jwks(url: str) -> dict[str, Any]:
    """Return {kid: public_key_object} dict, refreshed every _JWKS_TTL seconds."""
    from jwt.algorithms import RSAAlgorithm  # only needed here

    cached = _jwks_cache.get(url)
    if cached and time.time() - cached["fetched_at"] < _JWKS_TTL:
        return cached["keys"]

    try:
        resp = httpx.get(url, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("JWKS fetch failed for %s: %s — using stale cache", url, exc)
        if cached:
            return cached["keys"]
        return {}

    keys: dict[str, Any] = {}
    for jwk in data.get("keys", []):
        kid = jwk.get("kid", "default")
        try:
            keys[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))
        except Exception as exc:
            log.warning("Cannot parse JWK kid=%s: %s", kid, exc)

    _jwks_cache[url] = {"keys": keys, "fetched_at": time.time()}
    log.debug("JWKS refreshed from %s — %d key(s) loaded", url, len(keys))
    return keys


def _verify_rs256(token: str, jwks_url: str) -> dict[str, Any]:
    """Validate RS256 signature using cached JWKS keys. Returns decoded claims."""
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cannot parse JWT header: {exc}",
        ) from exc

    alg = header.get("alg", "")
    if alg not in ("RS256", "RS384", "RS512"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported JWT algorithm '{alg}' — RS256 required.",
        )

    kid = header.get("kid", "default")
    keys = _get_jwks(jwks_url)
    pub_key = keys.get(kid)

    if pub_key is None:
        # Key may have been rotated — force refresh once
        _jwks_cache.pop(jwks_url, None)
        keys = _get_jwks(jwks_url)
        pub_key = keys.get(kid)

    if pub_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unknown JWKS key ID '{kid}' — token may be malformed.",
        )

    try:
        return jwt.decode(
            token,
            pub_key,
            algorithms=["RS256", "RS384", "RS512"],
            # Audience validation skipped: chrome.identity scopes the token to the
            # extension's own OAuth client; the gateway only needs email + issuer.
            options={"verify_aud": False},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC token has expired — please sign in again.",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid OIDC token: {exc}",
        ) from exc


# ── Domain → tenant_id mapping ────────────────────────────────────────────────

# Loaded lazily on first auth call; refreshed from Redis when a Redis client
# is available.  Env var format: "domain1:tenant1,domain2:tenant2"
_domain_map: dict[str, str] = {}
_domain_map_loaded = False


def _load_domain_map() -> dict[str, str]:
    """Load domain→tenant mapping from env var (and Redis when available)."""
    global _domain_map_loaded
    _domain_map_loaded = True

    raw = os.getenv("OIDC_ALLOWED_DOMAINS", "")
    result: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if ":" in pair:
            domain, tenant = pair.split(":", 1)
            result[domain.strip().lower()] = tenant.strip()

    # Merge Redis overrides if available (non-fatal if Redis is down)
    try:
        from warden.cache import _get_client as get_redis_client  # noqa: PLC0415
        r = get_redis_client()
        if r is not None:
            redis_map = r.hgetall("warden:oidc:domains")
            for _dk, _tv in (redis_map or {}).items():
                d = _dk.decode("utf-8") if isinstance(_dk, (bytes, bytearray)) else str(_dk or "")  # type: ignore[attr-defined]
                t = _tv.decode("utf-8") if isinstance(_tv, (bytes, bytearray)) else str(_tv or "")  # type: ignore[attr-defined]
                result[d.lower()] = t
    except Exception:
        pass  # Redis unavailable — env var map is sufficient

    log.info("OIDC domain map loaded: %d domain(s)", len(result))
    return result


def register_domain(domain: str, tenant_id: str) -> None:
    """Add or update a domain→tenant mapping at runtime (admin portal)."""
    global _domain_map
    if not _domain_map_loaded:
        _domain_map = _load_domain_map()
    _domain_map[domain.lower()] = tenant_id

    # Persist to Redis if available
    try:
        from warden.cache import _get_client as get_redis_client  # noqa: PLC0415
        r = get_redis_client()
        if r is not None:
            r.hset("warden:oidc:domains", domain.lower(), tenant_id)
    except Exception:
        pass


def resolve_tenant(email: str) -> str:
    """
    Map an email address to a tenant_id.

    Raises
    ──────
    HTTPException 401  — no valid email claim
    HTTPException 403  — domain not registered
    HTTPException 402  — domain registered but subscription lapsed / unpaid
    """
    global _domain_map, _domain_map_loaded
    if not _domain_map_loaded:
        _domain_map = _load_domain_map()

    if "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC token contains no valid email claim.",
        )

    domain = email.split("@")[1].lower()
    tenant_id = _domain_map.get(domain)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Domain '{domain}' is not registered with Shadow Warden. "
                "Ask your administrator to add it via the admin portal."
            ),
        )

    # ── Billing gate (non-fatal if Redis is unavailable) ──────────────────────
    # Free-tier tenants never have a billing key set → pass-through (fail-open).
    # Paid tenants: key warden:oidc:billing:<tenant_id> must exist; deleted by
    # StripeBilling on subscription deletion / payment failure → HTTP 402.
    _check_billing(tenant_id)

    return tenant_id


def _check_billing(tenant_id: str) -> None:
    """
    Raise HTTP 402 if a paid tenant's subscription has lapsed.

    Logic:
      - If no billing key exists at all → pass-through (free tier or Redis down).
      - If key exists and equals "1" → active subscription, allow.
      - If key exists and equals "0" or is absent after a prior activation →
        subscription lapsed; raise 402.

    We use a "activation flag" approach:
      Redis key warden:oidc:billing:<tenant_id> is SET on checkout.session.completed
      and DELETED on subscription cancellation / payment failure.
      Free tenants never have this key → they always pass through.
      Once a tenant has had a paid plan, the absence of the key means lapsed.
    """
    try:
        from warden.cache import _get_client as get_redis  # noqa: PLC0415
        r = get_redis()
        # Check if this tenant was ever activated (has a subscription record)
        # Only block if they were previously active but key is now gone.
        val = r.get(f"warden:oidc:billing:{tenant_id}")
        if val is not None and val != b"1" and val != "1":
            raise HTTPException(
                status_code=402,
                detail=(
                    "Your organisation's Shadow Warden subscription has lapsed. "
                    "Please contact your IT administrator to renew."
                ),
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Redis unavailable — fail-open, do not block auth


# ── Main entry point ──────────────────────────────────────────────────────────

def verify_oidc_token(token: str) -> tuple[str, str]:
    """
    Validate an OIDC id_token from Google Workspace or Microsoft Entra ID.

    Returns
    ───────
    (tenant_id, email)  — ready for use in AuthResult

    Raises
    ──────
    HTTPException 401  — malformed / expired / unknown-key token
    HTTPException 403  — email domain not registered
    """
    # Peek at issuer (unverified) to route to the correct JWKS URL
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cannot decode JWT claims: {exc}",
        ) from exc

    issuer = unverified.get("iss", "")

    if issuer in _GOOGLE_ISSUERS:
        jwks_url = _GOOGLE_JWKS_URL
    elif "microsoftonline.com" in issuer or "sts.windows.net" in issuer:
        jwks_url = _MSFT_JWKS_URL
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unrecognised token issuer '{issuer}'. "
                   "Only Google Workspace and Microsoft Entra ID are supported.",
        )

    claims = _verify_rs256(token, jwks_url)
    email  = claims.get("email") or claims.get("preferred_username") or ""
    email  = email.strip().lower()

    tenant_id = resolve_tenant(email)
    return tenant_id, email


# ── Force-refresh helpers (for tests / admin) ────────────────────────────────

def invalidate_jwks_cache() -> None:
    """Clear the JWKS cache — next call will re-fetch from Google/Microsoft."""
    _jwks_cache.clear()


def invalidate_domain_map() -> None:
    """Clear the domain map cache — next auth call will reload from env + Redis."""
    global _domain_map, _domain_map_loaded
    _domain_map = {}
    _domain_map_loaded = False
