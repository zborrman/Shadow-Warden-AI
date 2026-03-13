"""
warden/rbac.py
══════════════
Role-Based Access Control for the MSP Dashboard.

Three built-in roles
────────────────────
  admin    Full access — create/manage tenants, manage billing, view all
           dashboards, generate PDF reports, register webhooks.

  auditor  Read-only compliance access — view logs, download PDF reports,
           view incident details with XAI explanations.
           Cannot mutate any data.

  viewer   Minimal read-only — view aggregated incident charts and stats.
           Cannot see raw logs, download reports, or manage tenants.

Role resolution order
─────────────────────
  1. SAML group   "warden_role_admin" / "warden_role_auditor" / "warden_role_viewer"
  2. Env var      DASHBOARD_ROLE (default: admin — applies to password-login users)

Environment variables
─────────────────────
  DASHBOARD_ROLE   Role assigned to password-login users (default: admin)
"""
from __future__ import annotations

import logging
import os
from enum import StrEnum

log = logging.getLogger(__name__)

_DEFAULT_ROLE = os.getenv("DASHBOARD_ROLE", "admin").lower()


class DashboardRole(StrEnum):
    ADMIN   = "admin"
    AUDITOR = "auditor"
    VIEWER  = "viewer"


# Role hierarchy — higher index = more permissions
_ROLE_LEVEL: dict[str, int] = {
    DashboardRole.VIEWER:  0,
    DashboardRole.AUDITOR: 1,
    DashboardRole.ADMIN:   2,
}

# SAML group name → role
_SAML_GROUP_MAP: dict[str, DashboardRole] = {
    "warden_role_admin":   DashboardRole.ADMIN,
    "warden_role_auditor": DashboardRole.AUDITOR,
    "warden_role_viewer":  DashboardRole.VIEWER,
}

# Human labels shown in the dashboard sidebar badge
ROLE_LABEL: dict[DashboardRole, str] = {
    DashboardRole.ADMIN:   "Admin",
    DashboardRole.AUDITOR: "Auditor",
    DashboardRole.VIEWER:  "Viewer",
}

ROLE_BADGE_COLOUR: dict[DashboardRole, str] = {
    DashboardRole.ADMIN:   "#e53e3e",   # red
    DashboardRole.AUDITOR: "#d69e2e",   # amber
    DashboardRole.VIEWER:  "#3182ce",   # blue
}


def role_from_saml_groups(groups: list[str]) -> DashboardRole:
    """Return the highest-privilege role present in the SAML group list."""
    best: DashboardRole = DashboardRole.VIEWER
    for g in groups:
        mapped = _SAML_GROUP_MAP.get(g)
        if mapped and _ROLE_LEVEL[mapped] > _ROLE_LEVEL[best]:
            best = mapped
    return best


def role_from_password_login() -> DashboardRole:
    """Return the role assigned to password-authenticated users (env var)."""
    try:
        return DashboardRole(_DEFAULT_ROLE)
    except ValueError:
        log.warning("Unknown DASHBOARD_ROLE=%r — defaulting to admin", _DEFAULT_ROLE)
        return DashboardRole.ADMIN


def has_permission(role: DashboardRole | str, required: DashboardRole | str) -> bool:
    """Return True if *role* satisfies *required* (admin ≥ auditor ≥ viewer)."""
    return _ROLE_LEVEL.get(str(role), 0) >= _ROLE_LEVEL.get(str(required), 0)
