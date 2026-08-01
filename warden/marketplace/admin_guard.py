"""
warden/marketplace/admin_guard.py  (MP-1c → SR-9)
──────────────────────────────────────────────────
Thin re-export of the gateway-wide admin guard.

MP-1c introduced this module to fix ``POST /marketplace/agents/{id}/kya/revoke``,
which skipped its admin check entirely whenever ``ADMIN_KEY`` was unset. SR-9
then found the same permissive-on-unset shape in three routers outside the
marketplace
(``api/rotation.py``, ``streams/api.py``, ``tokenomics/api.py``) and promoted the
implementation to :mod:`warden.admin_guard` so there is exactly one copy.

Kept as a module rather than deleted: marketplace code and its tests import from
here, and a second implementation is precisely what SR-9 removed.
"""
from __future__ import annotations

from warden.admin_guard import admin_key_configured, require_admin_key

__all__ = ["require_admin_key", "admin_key_configured"]
