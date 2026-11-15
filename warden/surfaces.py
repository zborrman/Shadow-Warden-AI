"""
warden/surfaces.py
───────────────────
Which routers are product and which are lab (docs/surface-decision-2026-11-14.md).

A ``lab`` router keeps its code and its tests, and is **not mounted** unless
``WARDEN_LAB_SURFACES=true``. It is absent from the route inventory, from the
published ``openapi.json`` and from every anonymous probe, so it cannot be
claimed, cannot be called, and stops costing a per-route migration it would
only be withdrawn after.

Entering this set requires a measurement, not a preference: the prefix has no
reference in ``site/``, ``portal/``, ``dashboard/``, ``sdk/``, the workers or
the agent tool tables. Leaving it requires a client, a capability-matrix row
and its routes passing the tenant-isolation hook - the hook does not count a
lab module, so the debt is paid on the way out, not forgiven.

Pure data: no warden imports at module level, so the pre-commit hook can read
it without importing the app.
"""
from __future__ import annotations

# import path of the module holding the router -> why it is lab.
LAB_ROUTER_MODULES: dict[str, str] = {
    "warden.api.wallet":
        "/wallet - SAC preflight wallet; no client on any frontend, SDK or tool table",
    "warden.api.whitelabel":
        "/whitelabel - white-label config; no client, and five routes act on a "
        "path-supplied tenant",
    "warden.blockchain.api":
        "/web3 - Sepolia mandate contract; testnet only, no client",
    "warden.tokenomics.api":
        "/tokenomics - agent token; no client, no settled transaction",
    # Cohort 2 (2026-11-15).
    "warden.api.integrations":
        "/integrations - Jira, Teams, Notion and Zapier outbound writers; no client "
        "on any frontend, SDK or tool table",
    "warden.agents.packs.api":
        "/agents/packs - edge agent packs; no client, and no pack has been deployed",
}


def is_lab(import_path: str) -> bool:
    return import_path in LAB_ROUTER_MODULES


def lab_enabled() -> bool:
    """True when lab routers should mount. Off unless explicitly switched on."""
    try:
        from warden.config import settings
        return bool(settings.lab_surfaces_enabled)
    except Exception:  # noqa: BLE001 - an unreadable config must not widen the surface
        return False
