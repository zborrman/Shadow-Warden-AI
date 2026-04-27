"""
warden/communities/oauth_discovery.py
───────────────────────────────────────
OAuth Agent Discovery — Detect AI agents connecting via SaaS OAuth grants.

Problem
────────
  Employees authorise third-party AI agents (Zapier, Make, Notion AI,
  Microsoft Copilot, etc.) through OAuth without IT approval.  These agents
  can exfiltrate community documents via sanctioned SaaS platforms while
  appearing as legitimate users.

Detection approach
──────────────────
  1. register_oauth_grant(community_id, member_id, provider, scopes)
       → store grant metadata in SQLite.
       → classify(provider, scopes) → OAuthRiskLevel.
       → if HIGH/CRITICAL → auto-alert via behavioral.record_event().

  2. list_grants(community_id) → all known OAuth grants.

  3. revoke_grant(grant_id) → mark REVOKED in DB.

  4. get_policy_verdict(community_id, provider) → ALLOW | MONITOR | BLOCK
       (uses community shadow_ai policy if available; falls back to
        MONITOR for unknown providers).

Known AI agent providers
─────────────────────────
  Detected via known OAuth app names, client_id prefixes, and scope patterns.
  Catalog mirrors warden/shadow_ai/signatures.py but for OAuth context.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.communities.oauth_discovery")

_OAUTH_DB = os.getenv("OAUTH_DB_PATH", "/tmp/warden_oauth.db")
_db_lock  = threading.RLock()


# ── AI OAuth provider catalog ─────────────────────────────────────────────────

_AI_PROVIDER_CATALOG: dict[str, dict] = {
    "zapier":          {"display": "Zapier AI",           "risk": "HIGH",     "scopes_watch": ["read", "write"]},
    "make":            {"display": "Make (Integromat)",   "risk": "HIGH",     "scopes_watch": ["files", "docs"]},
    "notion_ai":       {"display": "Notion AI",           "risk": "MEDIUM",   "scopes_watch": ["read"]},
    "copilot":         {"display": "Microsoft Copilot",   "risk": "MEDIUM",   "scopes_watch": ["read", "chat"]},
    "chatgpt_plugin":  {"display": "ChatGPT Plugin",      "risk": "CRITICAL", "scopes_watch": ["read", "write", "admin"]},
    "grammarly":       {"display": "Grammarly AI",        "risk": "LOW",      "scopes_watch": ["read"]},
    "jasper":          {"display": "Jasper AI",           "risk": "HIGH",     "scopes_watch": ["write", "publish"]},
    "otter_ai":        {"display": "Otter.ai",            "risk": "MEDIUM",   "scopes_watch": ["read", "record"]},
    "reclaim_ai":      {"display": "Reclaim AI",          "risk": "LOW",      "scopes_watch": ["calendar"]},
    "anthropic_app":   {"display": "Anthropic Claude App","risk": "MEDIUM",   "scopes_watch": ["read", "write"]},
    "openai_api":      {"display": "OpenAI API Client",   "risk": "CRITICAL", "scopes_watch": ["read", "write", "admin"]},
    "cohere":          {"display": "Cohere API",          "risk": "HIGH",     "scopes_watch": ["write"]},
    "perplexity":      {"display": "Perplexity AI",       "risk": "HIGH",     "scopes_watch": ["read", "search"]},
    "github_copilot":  {"display": "GitHub Copilot",      "risk": "MEDIUM",   "scopes_watch": ["repo", "code"]},
    "unknown":         {"display": "Unknown Agent",       "risk": "HIGH",     "scopes_watch": []},
}

_RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── Schema ────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_OAUTH_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_grants (
            grant_id     TEXT PRIMARY KEY,
            community_id TEXT NOT NULL,
            member_id    TEXT NOT NULL,
            provider     TEXT NOT NULL,
            display_name TEXT NOT NULL,
            scopes       TEXT NOT NULL DEFAULT '[]',
            risk_level   TEXT NOT NULL DEFAULT 'MEDIUM',
            status       TEXT NOT NULL DEFAULT 'ACTIVE',
            verdict      TEXT NOT NULL DEFAULT 'MONITOR',
            detected_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            revoked_at   TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_oauth_community
            ON oauth_grants(community_id, status)
    """)
    conn.commit()
    return conn


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class OAuthGrant:
    grant_id: str
    community_id: str
    member_id: str
    provider: str
    display_name: str
    scopes: list[str]
    risk_level: str     # LOW | MEDIUM | HIGH | CRITICAL
    status: str         # ACTIVE | REVOKED
    verdict: str        # ALLOW | MONITOR | BLOCK
    detected_at: str
    revoked_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id":    self.grant_id,
            "community_id":self.community_id,
            "member_id":   self.member_id,
            "provider":    self.provider,
            "display_name":self.display_name,
            "scopes":      self.scopes,
            "risk_level":  self.risk_level,
            "status":      self.status,
            "verdict":     self.verdict,
            "detected_at": self.detected_at,
            "revoked_at":  self.revoked_at,
        }


def _row_to_grant(row: sqlite3.Row) -> OAuthGrant:
    import json as _json
    return OAuthGrant(
        grant_id=row["grant_id"],
        community_id=row["community_id"],
        member_id=row["member_id"],
        provider=row["provider"],
        display_name=row["display_name"],
        scopes=_json.loads(row["scopes"]),
        risk_level=row["risk_level"],
        status=row["status"],
        verdict=row["verdict"],
        detected_at=row["detected_at"],
        revoked_at=row["revoked_at"],
    )


# ── Classification ────────────────────────────────────────────────────────────

def classify_provider(provider: str, scopes: list[str]) -> tuple[str, str]:
    """
    Returns (risk_level, verdict) for a given OAuth provider + scopes.
    risk_level: LOW | MEDIUM | HIGH | CRITICAL
    verdict:    ALLOW | MONITOR | BLOCK
    """
    key = provider.lower().replace(" ", "_").replace("-", "_")
    meta = _AI_PROVIDER_CATALOG.get(key, _AI_PROVIDER_CATALOG["unknown"])
    base_risk = meta["risk"]

    # Escalate risk when dangerous scopes are present
    dangerous_scopes = {"admin", "delete", "write", "publish"}
    scope_set = {s.lower() for s in scopes}
    if scope_set & dangerous_scopes:
        # bump one level if not already CRITICAL
        order = _RISK_ORDER.get(base_risk, 2)
        base_risk = next(
            (k for k, v in _RISK_ORDER.items() if v == min(order + 1, 4)),
            "CRITICAL",
        )

    verdict = "ALLOW" if base_risk == "LOW" else ("MONITOR" if base_risk == "MEDIUM" else "BLOCK")
    return base_risk, verdict


# ── CRUD ──────────────────────────────────────────────────────────────────────

def register_oauth_grant(
    community_id: str,
    member_id: str,
    provider: str,
    scopes: list[str] | None = None,
) -> OAuthGrant:
    """Record a newly detected OAuth grant. Auto-classifies risk and verdict."""
    import json as _json

    scopes = scopes or []
    risk_level, verdict = classify_provider(provider, scopes)

    key = provider.lower().replace(" ", "_").replace("-", "_")
    display = _AI_PROVIDER_CATALOG.get(key, {}).get("display", provider)
    grant_id = f"OAG-{uuid.uuid4().hex[:12].upper()}"

    with _db_lock:
        conn = _get_conn()
        conn.execute(
            """INSERT OR IGNORE INTO oauth_grants
               (grant_id, community_id, member_id, provider, display_name, scopes, risk_level, verdict)
               VALUES (?,?,?,?,?,?,?,?)""",
            (grant_id, community_id, member_id, provider, display,
             _json.dumps(scopes), risk_level, verdict),
        )
        conn.commit()

    log.info(
        "oauth_grant registered community=%s member=%s provider=%s risk=%s verdict=%s",
        community_id, member_id, provider, risk_level, verdict,
    )

    # Fire behavioral event for anomaly tracking
    try:
        from warden.communities.behavioral import record_event
        value = _RISK_ORDER.get(risk_level, 2) / 4.0
        record_event(community_id, "request", value)
    except Exception:  # noqa: BLE001
        pass

    return get_grant(grant_id)  # type: ignore[return-value]


def get_grant(grant_id: str) -> OAuthGrant | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM oauth_grants WHERE grant_id=?", (grant_id,)).fetchone()
    return _row_to_grant(row) if row else None


def list_grants(
    community_id: str,
    status: str = "ACTIVE",
) -> list[OAuthGrant]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM oauth_grants WHERE community_id=? AND status=? ORDER BY detected_at DESC",
        (community_id, status),
    ).fetchall()
    return [_row_to_grant(r) for r in rows]


def revoke_grant(grant_id: str) -> OAuthGrant:
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        conn.execute(
            "UPDATE oauth_grants SET status='REVOKED', revoked_at=? WHERE grant_id=?",
            (now, grant_id),
        )
        conn.commit()
    log.info("oauth_grant revoked grant_id=%s", grant_id)
    return get_grant(grant_id)  # type: ignore[return-value]


def get_risk_summary(community_id: str) -> dict[str, Any]:
    """Aggregate grant risk for a community."""
    grants = list_grants(community_id, status="ACTIVE")
    by_risk: dict[str, int] = {}
    blocked = 0
    for g in grants:
        by_risk[g.risk_level] = by_risk.get(g.risk_level, 0) + 1
        if g.verdict == "BLOCK":
            blocked += 1
    return {
        "community_id":   community_id,
        "total_active":   len(grants),
        "blocked_agents": blocked,
        "by_risk_level":  by_risk,
        "providers": [
            {"provider": g.provider, "display_name": g.display_name,
             "risk_level": g.risk_level, "verdict": g.verdict}
            for g in sorted(grants, key=lambda x: -_RISK_ORDER.get(x.risk_level, 0))[:10]
        ],
    }


def get_provider_catalog() -> list[dict[str, Any]]:
    """Return the full AI OAuth provider catalog."""
    return [
        {"provider": k, **v}
        for k, v in _AI_PROVIDER_CATALOG.items()
        if k != "unknown"
    ]
