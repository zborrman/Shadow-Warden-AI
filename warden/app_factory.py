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


def run_turso_migrations() -> None:
    """
    Run schema migrations on all configured Turso databases.

    Called once at startup (from main.py lifespan) when TURSO_AUTO_MIGRATE=true.
    Fail-open: any individual migration error is logged and skipped.
    """
    try:
        from warden.db.turso import is_turso_enabled, run_schema_migration  # noqa: PLC0415
    except ImportError:
        return

    migrations = [
        ("billing_audit", _BILLING_AUDIT_DDL),
        ("acp",           _ACP_DDL),
        ("staff",         _STAFF_DDL),
        ("sep",           _SEP_DDL),
        ("marketplace",   _MARKETPLACE_DDL),
    ]
    for db_name, ddl in migrations:
        if is_turso_enabled(db_name):
            try:
                run_schema_migration(db_name, ddl)
                log.info("Turso migration OK: %s", db_name)
            except Exception as exc:  # noqa: BLE001
                log.warning("Turso migration FAILED (skipped): %s — %s", db_name, exc)


# ── DDL for each Turso-managed database ───────────────────────────────────────

_BILLING_AUDIT_DDL = """
    CREATE TABLE IF NOT EXISTS billing_audit_chain (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
        seq INTEGER NOT NULL, event_type TEXT NOT NULL,
        agent_id TEXT NOT NULL DEFAULT '', tool_name TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '', input_tokens INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        cost_usd TEXT NOT NULL DEFAULT '0', amount_usd TEXT NOT NULL DEFAULT '0',
        timestamp TEXT NOT NULL, prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL, evm_tx_hash TEXT NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_bac_tenant_seq
        ON billing_audit_chain(tenant_id, seq);
    CREATE TABLE IF NOT EXISTS billing_audit_evm_anchors (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
        tip_seq INTEGER NOT NULL, tip_hash TEXT NOT NULL,
        tx_hash TEXT NOT NULL DEFAULT '', anchored_at TEXT NOT NULL
    );
"""

_ACP_DDL = """
    CREATE TABLE IF NOT EXISTS acp_tokens (
        token_id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL, max_amount REAL NOT NULL,
        currency TEXT NOT NULL, use_limit INTEGER NOT NULL,
        expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE',
        issued_at TEXT NOT NULL, signature TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS acp_token_uses (
        id INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT NOT NULL,
        order_id TEXT NOT NULL, amount REAL NOT NULL, used_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS acp_refunds (
        refund_id TEXT PRIMARY KEY, order_id TEXT NOT NULL,
        merchant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL, amount REAL NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD', reason TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
        stix_chain_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL, resolved_at TEXT NOT NULL DEFAULT ''
    );
"""

_STAFF_DDL = """
    CREATE TABLE IF NOT EXISTS staff_action_costs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL, action TEXT NOT NULL, model TEXT NOT NULL,
        input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
        cost_usd REAL NOT NULL, ts INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sac_tenant ON staff_action_costs(tenant_id, ts);
    CREATE TABLE IF NOT EXISTS staff_a2a_calls (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id         TEXT    NOT NULL UNIQUE,
        caller_agent_id TEXT    NOT NULL,
        target_agent_id TEXT    NOT NULL,
        tool_name       TEXT    NOT NULL,
        status          TEXT    NOT NULL,
        latency_ms      REAL    NOT NULL,
        ts              INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_a2a_caller ON staff_a2a_calls(caller_agent_id, ts);
"""

_SEP_DDL = """
    CREATE TABLE IF NOT EXISTS sep_ueciid_index (
        ueciid        TEXT PRIMARY KEY,
        snowflake_id  INTEGER NOT NULL,
        entity_id     TEXT NOT NULL,
        community_id  TEXT NOT NULL,
        display_name  TEXT NOT NULL DEFAULT '',
        content_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
        byte_size     INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS ueciid_community_idx ON sep_ueciid_index(community_id);
    CREATE INDEX IF NOT EXISTS ueciid_snowflake_idx ON sep_ueciid_index(snowflake_id);
    CREATE INDEX IF NOT EXISTS idx_sep_ueciid ON sep_ueciid_index(ueciid, community_id);
    CREATE TABLE IF NOT EXISTS sep_pod_tags (
        entity_id     TEXT NOT NULL,
        community_id  TEXT NOT NULL,
        jurisdiction  TEXT NOT NULL DEFAULT 'EU',
        data_class    TEXT NOT NULL DEFAULT 'GENERAL',
        notes         TEXT NOT NULL DEFAULT '',
        created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        PRIMARY KEY (entity_id, community_id)
    );
    CREATE INDEX IF NOT EXISTS pod_community_idx ON sep_pod_tags(community_id);
"""

_MARKETPLACE_DDL = """
    CREATE TABLE IF NOT EXISTS kya_agent_profiles (
        did             TEXT PRIMARY KEY,
        owner_tenant_id TEXT NOT NULL DEFAULT '',
        pubkey_b64      TEXT NOT NULL DEFAULT '',
        trust_score     REAL NOT NULL DEFAULT 0.5,
        reputation_json TEXT NOT NULL DEFAULT '{}',
        kya_status      TEXT NOT NULL DEFAULT 'PENDING',
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_kya_owner  ON kya_agent_profiles(owner_tenant_id);
    CREATE INDEX IF NOT EXISTS idx_kya_status ON kya_agent_profiles(kya_status);
    CREATE TABLE IF NOT EXISTS kya_trust_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        did         TEXT NOT NULL,
        delta       REAL NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        new_score   REAL NOT NULL,
        ts          TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_kte_did ON kya_trust_events(did, ts);
"""


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
    RouterSpec("warden.api.kya",                       label="KYA DIDs /kya"),
    RouterSpec("warden.api.discovery",                 label="Agent Discovery /.well-known"),
    # Staff subsystem — registered via register_staff_routers()
    *STAFF_ROUTERS,
]
