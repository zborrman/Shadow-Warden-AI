"""
warden/agent/tools.py
──────────────────────
SOVA tool implementations — thin HTTP wrappers over the internal API.

All tools call localhost:8001 with the internal WARDEN_API_KEY so the
full pipeline (auth, rate-limit, audit) is exercised identically to
external callers.  Results are returned as dicts for the agent to reason
over.

Tool registry
─────────────
  TOOLS          — Anthropic-format tool definitions (name/description/schema)
  TOOL_HANDLERS  — {name: async callable}
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

log = logging.getLogger("warden.agent.tools")

_BASE      = "http://localhost:8001"
_API_KEY   = os.getenv("WARDEN_API_KEY", "")
_TIMEOUT   = 30.0


def _headers(tenant: str = "default") -> dict:
    return {
        "X-API-Key":   _API_KEY,
        "X-Tenant-ID": tenant,
        "Content-Type": "application/json",
    }


async def _get(path: str, tenant: str = "default", params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(f"{_BASE}{path}", headers=_headers(tenant), params=params or {})
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict, tenant: str = "default") -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{_BASE}{path}", json=body, headers=_headers(tenant))
        r.raise_for_status()
        return r.json()


async def _delete(path: str, tenant: str = "default") -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.delete(f"{_BASE}{path}", headers=_headers(tenant))
        if r.status_code == 204:
            return {"deleted": True}
        r.raise_for_status()
        return r.json()


async def _patch(path: str, body: dict, tenant: str = "default") -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.patch(f"{_BASE}{path}", json=body, headers=_headers(tenant))
        r.raise_for_status()
        return r.json()


# ── Tool handlers ─────────────────────────────────────────────────────────────

async def get_health(**_) -> dict:
    return await _get("/health")


async def get_stats(tenant_id: str = "default", **_) -> dict:
    return await _get("/api/stats", tenant=tenant_id)


async def get_config(tenant_id: str = "default", **_) -> dict:
    return await _get("/api/config", tenant=tenant_id)


async def update_config(changes: dict, tenant_id: str = "default", **_) -> dict:
    return await _post("/api/config", changes, tenant=tenant_id)


async def list_threats(type_filter: str = "", tenant_id: str = "default", **_) -> dict:
    params = {"type": type_filter} if type_filter else {}
    return await _get("/threats/intel", tenant=tenant_id, params=params)


async def refresh_threat_intel(tenant_id: str = "default", **_) -> dict:
    return await _post("/threats/intel/refresh", {}, tenant=tenant_id)


async def dismiss_threat(item_id: str, tenant_id: str = "default", **_) -> dict:
    return await _post(f"/threats/intel/{item_id}/dismiss", {}, tenant=tenant_id)


async def list_communities(tenant_id: str = "default", **_) -> dict:
    return await _get("/communities", tenant=tenant_id)


async def get_community(community_id: str, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/communities/{community_id}", tenant=tenant_id)


async def rotate_community_key(community_id: str, tenant_id: str = "default", **_) -> dict:
    return await _post(f"/communities/{community_id}/rotate", {}, tenant=tenant_id)


async def get_rotation_progress(community_id: str, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/communities/{community_id}/rotation", tenant=tenant_id)


async def list_community_members(community_id: str, tenant_id: str = "default", **_) -> list:
    return await _get(f"/communities/{community_id}/members", tenant=tenant_id)


async def list_monitors(tenant_id: str = "default", **_) -> list:
    return await _get("/monitors/", tenant=tenant_id)


async def get_monitor_status(monitor_id: str, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/monitors/{monitor_id}/status", tenant=tenant_id)


async def get_monitor_uptime(monitor_id: str, hours: int = 24, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/monitors/{monitor_id}/uptime", tenant=tenant_id, params={"hours": hours})


async def get_monitor_history(monitor_id: str, limit: int = 20, tenant_id: str = "default", **_) -> list:
    return await _get(f"/monitors/{monitor_id}/history", tenant=tenant_id, params={"limit": limit})


async def get_financial_impact(tenant_id: str = "default", **_) -> dict:
    return await _get("/financial/impact", tenant=tenant_id)


async def get_cost_saved(tenant_id: str = "default", **_) -> dict:
    return await _get("/financial/cost-saved", tenant=tenant_id)


async def get_billing_quota(tenant_id: str = "default", **_) -> dict:
    return await _get("/billing/quota", tenant=tenant_id)


async def generate_proposal(company_name: str, tenant_id: str = "default", **_) -> dict:
    return await _post("/financial/generate-proposal", {"company_name": company_name}, tenant=tenant_id)


async def list_agents(tenant_id: str = "default", **_) -> list:
    return await _get(f"/agents?tenant_id={tenant_id}", tenant=tenant_id)


async def get_agent_activity(limit: int = 50, tenant_id: str = "default", **_) -> list:
    return await _get("/agents/activity", tenant=tenant_id, params={"limit": limit})


async def revoke_agent(agent_id: str, tenant_id: str = "default", **_) -> dict:
    return await _delete(f"/agents/{agent_id}", tenant=tenant_id)


async def get_tenant_impact(tenant_id: str = "default", **_) -> dict:
    return await _get("/tenant/impact", tenant=tenant_id)


async def send_slack_alert(message: str, **_) -> dict:
    url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not url:
        return {"sent": False, "reason": "SLACK_WEBHOOK_URL not configured"}
    import json as _json
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(url, content=_json.dumps({"text": message}),
                         headers={"Content-Type": "application/json"})
        return {"sent": r.status_code == 200, "status": r.status_code}


async def filter_request(content: str, tenant_id: str = "default", **_) -> dict:
    return await _post("/filter", {"content": content, "tenant_id": tenant_id}, tenant=tenant_id)


async def get_compliance_art30(tenant_id: str = "default", **_) -> dict:
    return await _get("/compliance/art30", tenant=tenant_id)


# ── Anthropic tool schema definitions ────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "name": "get_health",
        "description": "Get Shadow Warden gateway health: Redis status, circuit breaker, bypass rate, WS clients.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_stats",
        "description": "Get aggregated security statistics: total requests, blocks, risk distribution, top flags, recent events.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string", "description": "Tenant to query (default: 'default')"},
            },
        },
    },
    {
        "name": "get_config",
        "description": "Get live configuration: thresholds, strict_mode, rate limits, ML enabled, MTLS.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "update_config",
        "description": "Update live-tunable settings (semantic_threshold, strict_mode, rate_limit, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {
                "changes": {"type": "object", "description": "Key-value pairs of settings to update"},
                "tenant_id": {"type": "string"},
            },
            "required": ["changes"],
        },
    },
    {
        "name": "list_threats",
        "description": "List detected CVEs and ArXiv LLM-attack papers from the Threat Intelligence feed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type_filter": {"type": "string", "description": "Filter by 'cve' or 'arxiv'"},
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "refresh_threat_intel",
        "description": "Trigger an on-demand OSV CVE scan + ArXiv LLM-attack paper refresh (async, returns job ID).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "dismiss_threat",
        "description": "Acknowledge/dismiss a specific threat intelligence item.",
        "input_schema": {
            "type": "object",
            "properties": {
                "item_id": {"type": "string", "description": "Threat item ID to dismiss"},
                "tenant_id": {"type": "string"},
            },
            "required": ["item_id"],
        },
    },
    {
        "name": "list_communities",
        "description": "List all Business Communities for a tenant (id, name, member count, active key version).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_community",
        "description": "Get full Community profile: members, active kid, rotation status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "rotate_community_key",
        "description": "Initiate a Root Key Rollover for a community. Generates new kid, demotes old to ROTATION_ONLY, enqueues ARQ re-wrap worker.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "get_rotation_progress",
        "description": "Check Root Key Rollover progress: done/total entity re-wraps, failed count, status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "list_community_members",
        "description": "List all active members of a community with their clearance levels.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "list_monitors",
        "description": "List all uptime monitors for a tenant (URL, check_type, interval, is_active).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_monitor_status",
        "description": "Get the latest probe result for a monitor: is_up, latency_ms, status_code, error.",
        "input_schema": {
            "type": "object",
            "properties": {
                "monitor_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["monitor_id"],
        },
    },
    {
        "name": "get_monitor_uptime",
        "description": "Get uptime % and average latency for a monitor over a time window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "monitor_id": {"type": "string"},
                "hours": {"type": "integer", "description": "Lookback window in hours (default 24)"},
                "tenant_id": {"type": "string"},
            },
            "required": ["monitor_id"],
        },
    },
    {
        "name": "get_monitor_history",
        "description": "Get recent probe results for a monitor (newest first).",
        "input_schema": {
            "type": "object",
            "properties": {
                "monitor_id": {"type": "string"},
                "limit": {"type": "integer", "description": "Max results (default 20)"},
                "tenant_id": {"type": "string"},
            },
            "required": ["monitor_id"],
        },
    },
    {
        "name": "get_financial_impact",
        "description": "Get full ROI breakdown: monthly savings, 3-year projection, tier ROI (live data from logs + Prometheus).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_cost_saved",
        "description": "Get cumulative LLM inference cost saved via shadow banning (dollar amount).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_billing_quota",
        "description": "Get current monthly request usage and quota percentage for a tenant.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "generate_proposal",
        "description": "Generate a customer-facing ROI proposal deck for a company.",
        "input_schema": {
            "type": "object",
            "properties": {
                "company_name": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["company_name"],
        },
    },
    {
        "name": "list_agents",
        "description": "List all AP2 agentic payment agents for a tenant.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_agent_activity",
        "description": "Get AP2 mandate execution audit log (agent_id, SKU, amount, timestamp, status).",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max results (default 50)"},
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "revoke_agent",
        "description": "Revoke an AP2 agentic payment agent immediately.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "get_tenant_impact",
        "description": "Get personal ROI dashboard for a tenant: blocks, PII intercepts, dollar saved, threat breakdown, daily timeline.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "send_slack_alert",
        "description": "Send a Slack notification message to the configured webhook.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Markdown-formatted Slack message"},
            },
            "required": ["message"],
        },
    },
    {
        "name": "filter_request",
        "description": "Run content through the full Shadow Warden filter pipeline (test/audit mode).",
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "get_compliance_art30",
        "description": "Get GDPR Article 30 ROPA (Record of Processing Activities) for a tenant.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
]

# ── Dispatch table ────────────────────────────────────────────────────────────

TOOL_HANDLERS: dict[str, Any] = {
    "get_health":             get_health,
    "get_stats":              get_stats,
    "get_config":             get_config,
    "update_config":          update_config,
    "list_threats":           list_threats,
    "refresh_threat_intel":   refresh_threat_intel,
    "dismiss_threat":         dismiss_threat,
    "list_communities":       list_communities,
    "get_community":          get_community,
    "rotate_community_key":   rotate_community_key,
    "get_rotation_progress":  get_rotation_progress,
    "list_community_members": list_community_members,
    "list_monitors":          list_monitors,
    "get_monitor_status":     get_monitor_status,
    "get_monitor_uptime":     get_monitor_uptime,
    "get_monitor_history":    get_monitor_history,
    "get_financial_impact":   get_financial_impact,
    "get_cost_saved":         get_cost_saved,
    "get_billing_quota":      get_billing_quota,
    "generate_proposal":      generate_proposal,
    "list_agents":            list_agents,
    "get_agent_activity":     get_agent_activity,
    "revoke_agent":           revoke_agent,
    "get_tenant_impact":      get_tenant_impact,
    "send_slack_alert":       send_slack_alert,
    "filter_request":         filter_request,
    "get_compliance_art30":   get_compliance_art30,
}
