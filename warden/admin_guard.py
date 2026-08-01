"""
warden/admin_guard.py  (SR-9)
─────────────────────────────
One fail-closed ``X-Admin-Key`` check for the whole gateway.

Why this is a module and not a copy-paste
─────────────────────────────────────────
``ADMIN_KEY`` was read in ~17 places with three incompatible postures:

* **fail-CLOSED** (correct) — ``billing/router.py``, ``api/action_whitelist.py``,
  ``marketplace/api_listings.py``.
* **permissive on an unset key** (a hole) — ``api/rotation.py``,
  ``streams/api.py``, ``tokenomics/api.py`` all read
  ``if _ADMIN_KEY and provided != _ADMIN_KEY:``. With ``ADMIN_KEY`` unset the
  condition short-circuits to ``False`` and the endpoint runs for anybody. An
  empty secret disabled the check instead of denying — the same shape the Phase-7 signing-key rule exists to prevent, and
  the same class as the FT-3a AP2 key hotfix and MP-1c.
* **import-snapshotted** — those three also bind ``_ADMIN_KEY`` at module import,
  so a value provided later in the process lifetime is never seen.

Posture
───────
* No ``ADMIN_KEY`` configured ⇒ **503, endpoint disabled**. Not 200. An operator
  who never provisioned a key gets a loudly broken admin surface, never a
  quietly public one.
* ``ALLOW_UNAUTHENTICATED=true`` is the single explicit escape, so local runs and
  the test suite can exercise admin endpoints without provisioning a key. It is
  opt-in and never downgrades a deployment that *does* have a key.
* Constant-time comparison — a plain ``!=`` leaks the key a byte at a time
  through response timing.
* Read fresh on every call, never snapshotted at import.

⚠️ Deployment note (the reason SR-9 exists at all)
──────────────────────────────────────────────────
``ADMIN_KEY`` must have an explicit ``- ADMIN_KEY=${ADMIN_KEY:-}`` passthrough in
``docker-compose.yml``. The gateway services carry **no ``env_file``**, so a value
present in ``/opt/shadow-warden/.env`` never reaches the container without one.
It was set in ``.env`` and absent from every container: the permissive guards
were bypassed, and the strict ones (billing add-on grant/revoke, marketplace
sponsor, KYA revoke) denied unconditionally — admin was simultaneously open and
unusable. Verify with ``docker exec <container> printenv ADMIN_KEY``, never by
reading ``.env``.
"""
from __future__ import annotations

import hmac
import os

from fastapi import HTTPException

__all__ = ["require_admin_key", "admin_key_configured"]


def admin_key_configured() -> bool:
    """True when an admin key is actually available to this process."""
    return bool(os.getenv("ADMIN_KEY", ""))


def require_admin_key(provided: str | None) -> None:
    """Raise unless *provided* matches ``ADMIN_KEY``. Fails closed when unset."""
    admin_key = os.getenv("ADMIN_KEY", "")

    if not admin_key:
        if os.getenv("ALLOW_UNAUTHENTICATED", "false").strip().lower() == "true":
            return
        raise HTTPException(
            status_code=503,
            detail="ADMIN_KEY not configured — admin endpoints are disabled.",
        )

    if not provided or not hmac.compare_digest(provided, admin_key):
        raise HTTPException(status_code=403, detail="Valid X-Admin-Key required.")
