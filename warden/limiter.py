"""
warden/limiter.py
━━━━━━━━━━━━━━━━━
Shared slowapi rate limiter (architecture Phase 3b — hoisted out of main.py).

This is a dependency-free leaf module so that both ``warden.main`` and extracted
API routers (``warden/api/*``) can apply ``@limiter.limit(...)`` decorators
against the *same* Limiter instance without importing ``warden.main`` (which
would violate the layer rule). The Limiter is instantiated at import time; its
per-tenant keying reads ``WARDEN_API_KEYS_PATH`` lazily on each request via
``get_rate_limit``.
"""
from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter

from warden.auth_guard import get_rate_limit, resolve_tenant_id
from warden.client_ip import get_client_ip

# Default fallback limit (used by get_rate_limit for unrecognised / IP keys).
_RATE_LIMIT = os.getenv("RATE_LIMIT_PER_MINUTE", "60")


def tenant_key(request: Request) -> str:
    """Rate-limit bucket key: API key when present, IP address as fallback.

    Keying on the API key means each tenant gets their own independent bucket
    even when all requests arrive from the same nginx IP.

    The fallback must NOT be the proxy socket address: behind Cloudflare → Caddy
    that is one constant value for the whole internet, so every anonymous caller
    would share a single bucket. ``get_client_ip`` unwraps the forwarded headers
    when (and only when) the peer is a trusted proxy.

    The header is only a bucket when it is a key we issued. Anonymous routes
    (the storefront, catalog, image and order-request routes) share this
    limiter, and an unvalidated header is a value the caller picks: a fresh
    ``X-API-Key: <random>`` per request bought a fresh bucket every time, so
    the per-IP limit on anonymous order creation limited nothing.
    """
    api_key = request.headers.get("x-api-key")
    if api_key and resolve_tenant_id(api_key) is not None:
        return api_key
    return get_client_ip(request) or "anonymous"


def tenant_limit(key: str) -> str:
    """Per-tenant slowapi limit string derived from the key's configured rate.

    slowapi calls this with the value returned by ``tenant_key`` — the API key
    string when present, or the remote IP as fallback. ``get_rate_limit()``
    returns the per-tenant rate_limit from WARDEN_API_KEYS_PATH, falling back to
    the RATE_LIMIT_PER_MINUTE default for unrecognised / plain-IP keys.
    """
    return f"{get_rate_limit(key)}/minute"


limiter = Limiter(
    key_func=tenant_key,
    storage_uri=os.getenv("REDIS_URL", "redis://redis:6379/0"),
)
