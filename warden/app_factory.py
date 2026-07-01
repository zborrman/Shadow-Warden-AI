"""
Application Factory — router registry for Shadow Warden AI.

Pattern: RouterSpec describes each optional sub-router with its import path,
include_router kwargs, and a label for logging. register_router_safe() wraps
every registration in try/except Exception — not just ImportError — so a broken
router's module-level initializer cannot crash the security pipeline.

Migration guide
───────────────
Move try/except include_router blocks from main.py into OPTIONAL_ROUTERS (or a
domain-specific list like STAFF_ROUTERS). Call register_router_group(app, specs)
once from main.py. This keeps main.py slim and isolates subsystem failures.

Currently migrated:  staff/* (STAFF-01..05)
Pending migration:   all other routers (auth, billing, billing, sep, …) — low risk
                     because they already have try/except, but moving them here
                     gives unified logging + BaseException safety.
"""
from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI

log = logging.getLogger(__name__)


@dataclass
class RouterSpec:
    """Describes one optional sub-router."""
    import_path: str                   # e.g. "warden.api.staff"
    attr: str = "router"               # attribute name on the module
    kwargs: dict[str, Any] = field(default_factory=dict)  # passed to include_router
    label: str = ""                    # log label; defaults to import_path


def register_router_safe(app: FastAPI, spec: RouterSpec) -> bool:
    """
    Import and register one router. Returns True on success.
    Catches ALL exceptions so a bad router cannot kill the app.
    """
    label = spec.label or spec.import_path
    try:
        module = importlib.import_module(spec.import_path)
        router = getattr(module, spec.attr)
        app.include_router(router, **spec.kwargs)
        log.info("router mounted: %s", label)
        return True
    except ImportError as exc:
        log.warning("router skipped (missing dep): %s — %s", label, exc)
    except Exception as exc:  # noqa: BLE001
        log.error("router FAILED (subsystem isolated): %s — %s", label, exc)
    return False


def register_router_group(app: FastAPI, specs: list[RouterSpec]) -> dict[str, bool]:
    """Register a group of routers. Returns label→success map."""
    return {(spec.label or spec.import_path): register_router_safe(app, spec) for spec in specs}


# ── Staff subsystem (STAFF-01..05) ────────────────────────────────────────────

STAFF_ROUTERS: list[RouterSpec] = [
    RouterSpec(
        import_path="warden.api.staff",
        label="Digital Staff /staff (STAFF-01)",
    ),
    RouterSpec(
        import_path="warden.api.staff_agents",
        label="Digital Staff Agents /staff/agents (STAFF-02..05)",
    ),
    RouterSpec(
        import_path="warden.api.voice",
        attr="router",
        label="Voice Commerce Agents /voice (VC-01)",
    ),
]


def register_staff_routers(app: FastAPI) -> dict[str, bool]:
    """Register all Digital Staff sub-routers in isolation."""
    return register_router_group(app, STAFF_ROUTERS)


# ── Full optional router registry (add remaining routers here over time) ───────

OPTIONAL_ROUTERS: list[RouterSpec] = [
    RouterSpec("warden.auth.router",                   label="Auth /auth"),
    RouterSpec("warden.openai_proxy",                  label="OpenAI proxy /v1"),
    RouterSpec("warden.portal_router",                 kwargs={"prefix": "/portal"}, label="Portal /portal"),
    RouterSpec("warden.agentic.router",                label="Agentic AP2 /agents"),
    RouterSpec("warden.api.financial",                 label="Financial /financial"),
    RouterSpec("warden.api.tenant_impact",             label="Tenant Impact /tenant/impact"),
    RouterSpec("warden.billing.router",                label="Billing /billing"),
    RouterSpec("warden.api.monitor",                   label="Uptime Monitor /monitors"),
    RouterSpec("warden.api.agent",                     label="SOVA Agent /agent/sova"),
    RouterSpec("warden.api.shadow_ai",                 label="Shadow AI /shadow-ai"),
    RouterSpec("warden.api.sep",                       label="SEP /sep"),
    RouterSpec("warden.api.sovereign",                 label="Sovereign /sovereign"),
    RouterSpec("warden.api.secrets",                   label="Secrets /secrets"),
    RouterSpec("warden.api.xai",                       label="XAI /xai"),
    RouterSpec("warden.api.compliance_report",         label="Compliance /compliance"),
    RouterSpec("warden.api.vendor_gov",                label="Vendor Gov /vendor-gov"),
    RouterSpec("warden.api.cost_allocation",           label="Cost Allocation /financial/allocation"),
    RouterSpec("warden.api.budget",                    label="Budget /financial/budget"),
    RouterSpec("warden.api.incident_register",         label="Incidents /incidents"),
    RouterSpec("warden.api.supplier_risk",             label="Supplier Risk /supplier-risk"),
    RouterSpec("warden.api.prompt_library",            label="Prompt Library /prompt-library"),
    RouterSpec("warden.api.training_records",          label="Training /training"),
    RouterSpec("warden.api.smb_suite",                 label="SMB Suite /smb-suite"),
    RouterSpec("warden.semantic_layer.api",            label="Semantic Layer /semantic-layer"),
    RouterSpec("warden.settings.api",                  label="Settings /settings"),
    RouterSpec("warden.business_intelligence.router",  label="BI /business-intelligence"),
    RouterSpec("warden.api.doc_converter",             label="Doc Converter /doc-converter"),
    RouterSpec("warden.document_intel.api",            label="Document Intel /document-intel"),
    RouterSpec("warden.api.obsidian",                  label="Obsidian /obsidian"),
    RouterSpec("warden.agent.master",                  attr="master_router",  label="MasterAgent /agent/master"),
    RouterSpec("warden.mcp.gateway",                   label="MCP Paid Tools /mcp"),
    # Staff subsystem — registered via register_staff_routers()
    *STAFF_ROUTERS,
]
