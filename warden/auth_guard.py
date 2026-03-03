"""
warden/auth_guard.py
━━━━━━━━━━━━━━━━━━━
FastAPI dependency for X-API-Key authentication on the /filter endpoint.

Dev mode (WARDEN_API_KEY not set): all requests pass through.
Production (WARDEN_API_KEY set): requests without a matching key → 401.

Usage::

    from warden.auth_guard import require_api_key
    from fastapi import Depends

    @app.post("/filter")
    async def filter_content(..., _: str = Depends(require_api_key)):
        ...
"""
from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Single shared key loaded once at import time.
# In a multi-tenant production deployment, replace _VALID_KEY with a
# database lookup against warden_core.api_keys (PostgreSQL).
_VALID_KEY: str = os.getenv("WARDEN_API_KEY", "")


def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> str:
    """
    FastAPI Security dependency.

    - If WARDEN_API_KEY env var is blank: dev mode — all requests pass (returns "").
    - Otherwise: constant-time compare against the env var value.
      Missing or wrong key → HTTP 401.
    """
    if not _VALID_KEY:
        # Dev / air-gapped mode — authentication disabled
        return ""

    if not api_key or not hmac.compare_digest(api_key.encode(), _VALID_KEY.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
