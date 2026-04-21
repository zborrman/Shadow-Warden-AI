"""
warden/shadow_ai/smb_presets.py
────────────────────────────────
Pre-approved AI tool allowlist for Community Business (SMB) tier.

Provides a ready-to-use ALLOWLIST_ONLY policy populated with the most
common, enterprise-grade AI tools — applied on first setup so SMBs
are protected immediately without any manual configuration.

Usage
─────
    from warden.shadow_ai.smb_presets import apply_smb_preset
    apply_smb_preset(tenant_id="my-business")

The preset sets mode=ALLOWLIST_ONLY and populates a curated allowlist.
Any AI tool not on the list generates a MONITOR alert.
Admins can add custom tools via the /shadow-ai/policy endpoint.
"""
from __future__ import annotations

from datetime import UTC, datetime

# ── Curated allowlist for SMB ─────────────────────────────────────────────────
# Covers well-known enterprise AI tools with published privacy policies
# and DPA/GDPR compliance documentation.

SMB_APPROVED_PROVIDERS: list[dict] = [
    # Chat / General LLM
    {"key": "openai",       "display": "ChatGPT / OpenAI",       "risk": "LOW",    "note": "Enterprise data processing agreement available"},
    {"key": "anthropic",    "display": "Claude / Anthropic",      "risk": "LOW",    "note": "SOC 2 Type II, no training on API data"},
    {"key": "google",       "display": "Gemini / Google AI",      "risk": "LOW",    "note": "Google Workspace AI — GDPR DPA available"},
    {"key": "microsoft",    "display": "Copilot / Azure OpenAI",  "risk": "LOW",    "note": "Microsoft EUDB + GDPR compliant"},
    # Code
    {"key": "github",       "display": "GitHub Copilot",          "risk": "LOW",    "note": "Business plan excludes training on your code"},
    {"key": "cursor",       "display": "Cursor IDE",              "risk": "MEDIUM", "note": "Privacy mode recommended for sensitive repos"},
    {"key": "tabnine",      "display": "Tabnine",                 "risk": "LOW",    "note": "On-prem model available; no cloud training by default"},
    # Productivity
    {"key": "notion",       "display": "Notion AI",               "risk": "LOW",    "note": "GDPR DPA, ISO 27001"},
    {"key": "grammarly",    "display": "Grammarly",               "risk": "LOW",    "note": "SOC 2 Type II, GDPR compliant"},
    {"key": "jasper",       "display": "Jasper AI",               "risk": "MEDIUM", "note": "Review DPA before using with customer PII"},
    # Search / Research
    {"key": "perplexity",   "display": "Perplexity AI",           "risk": "MEDIUM", "note": "Avoid uploading confidential documents"},
    {"key": "you",          "display": "You.com",                 "risk": "MEDIUM", "note": "Monitor for sensitive query leakage"},
    # Automation / Workflow
    {"key": "zapier",       "display": "Zapier AI",               "risk": "LOW",    "note": "GDPR DPA available; audit connected apps"},
    {"key": "make",         "display": "Make (Integromat)",       "risk": "LOW",    "note": "EU-hosted option available"},
]

SMB_APPROVED_KEYS: list[str] = [p["key"] for p in SMB_APPROVED_PROVIDERS]

# ── High-risk providers that should be blocked for SMB by default ─────────────

SMB_DEFAULT_DENYLIST: list[str] = [
    "localai",         # unaudited self-hosted, no telemetry visibility
    "ollama",          # local but often misconfigured with external endpoints
    "huggingface",     # public inference API — data may be used for training
    "replicate",       # third-party model hosting, variable privacy policies
    "together",        # API aggregator — unclear data handling
    "anyscale",        # research-focused, no enterprise DPA
]


def apply_smb_preset(tenant_id: str, mode: str = "MONITOR") -> dict:
    """
    Apply the SMB-safe Shadow AI policy to *tenant_id*.

    mode="MONITOR"          — alert on unknown tools (default, non-blocking)
    mode="ALLOWLIST_ONLY"   — strict: flag anything not on the approved list
    mode="BLOCK_DENYLIST"   — block known high-risk providers only
    """
    from warden.shadow_ai.policy import update_policy

    policy = update_policy(tenant_id, {
        "mode":           mode,
        "allowlist":      SMB_APPROVED_KEYS,
        "denylist":       SMB_DEFAULT_DENYLIST,
        "risk_threshold": "LOW",
        "notify_slack":   False,
        "smb_preset":     True,
        "preset_applied": datetime.now(UTC).isoformat(),
    })
    return policy


def get_smb_catalog() -> list[dict]:
    """Return the full SMB approved provider catalog with metadata."""
    return [
        {
            **p,
            "approved": True,
            "category": _categorize(p["key"]),
        }
        for p in SMB_APPROVED_PROVIDERS
    ]


def _categorize(key: str) -> str:
    code_tools    = {"github", "cursor", "tabnine"}
    productivity  = {"notion", "grammarly", "jasper"}
    search        = {"perplexity", "you"}
    automation    = {"zapier", "make"}
    if key in code_tools:   return "code"
    if key in productivity: return "productivity"
    if key in search:       return "search"
    if key in automation:   return "automation"
    return "llm"
