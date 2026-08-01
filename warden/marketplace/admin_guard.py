"""
warden/marketplace/admin_guard.py  (MP-1c)
──────────────────────────────────────────
One fail-closed admin-key check for the marketplace cluster.

Why this module exists
──────────────────────
``POST /marketplace/agents/{id}/kya/revoke`` guarded itself like this::

    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and request.headers.get("X-Admin-Key") != admin_key:
        raise HTTPException(403, ...)

With ``ADMIN_KEY`` unset — the default in any deployment that never provisioned
one — ``admin_key`` is ``""`` and the whole condition short-circuits to False.
The endpoint then revokes any agent's KYA status for any caller. An empty secret
silently disabled the check rather than denying, which is the same fail-open
shape the Phase-7 signing-key rule exists to prevent (an unresolvable key must
deny, never wave the request through).

Posture
───────
* No ``ADMIN_KEY`` configured ⇒ **503, endpoint disabled**. Not 200. An operator
  who never set the key gets a loud, obviously-broken admin surface instead of a
  quietly public one.
* ``ALLOW_UNAUTHENTICATED=true`` is the one explicit escape, so local runs and
  the test suite can exercise admin endpoints without provisioning a key. It is
  opt-in and never the default.
* Comparison is constant-time — a plain ``!=`` leaks the key one byte at a time
  through response timing.

This mirrors ``warden/api/action_whitelist.py::_require_admin``, which already
had the correct shape; marketplace simply never adopted it. Kept as a plain
function rather than a FastAPI dependency so it composes with handlers that read
the header themselves, and so ``api_listings.py`` can share it without an import
cycle through ``api.py``.
"""
from __future__ import annotations

import hmac
import os

from fastapi import HTTPException

__all__ = ["require_admin_key"]


def require_admin_key(provided: str | None) -> None:
    """Raise unless *provided* matches ``ADMIN_KEY``. Fails closed when unset.

    Read fresh on every call, never snapshotted at import — a module-level
    ``_ADMIN_KEY = os.getenv(...)`` captures ``""`` when the module is imported
    before the environment is populated, and then denies (or, with the old
    fail-open shape, allows) forever regardless of what the operator sets later.
    """
    admin_key = os.getenv("ADMIN_KEY", "")

    if not admin_key:
        if os.getenv("ALLOW_UNAUTHENTICATED", "false").strip().lower() == "true":
            return
        raise HTTPException(
            status_code=503,
            detail="ADMIN_KEY not configured — marketplace admin endpoints are disabled.",
        )

    if not provided or not hmac.compare_digest(provided, admin_key):
        raise HTTPException(status_code=403, detail="Valid X-Admin-Key required.")
