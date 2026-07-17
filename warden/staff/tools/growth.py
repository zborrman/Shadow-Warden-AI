"""
STAFF-03: Growth Hacker Agent tools.

fetch_market_signals   — pull competitor/trend signals (public data)
generate_seo_content   — Claude Haiku content brief → draft queue (Rec-1 injected)
adjust_ad_budget       — propose budget change (human approval required for > ceiling)

Spend ceiling enforced at boundary level (see AuthorizationBoundary.spend_ceiling_usd_daily).
"""
from __future__ import annotations

import logging
import sqlite3
import time

from warden.config import data_path

log = logging.getLogger(__name__)


_DB_PATH = data_path("warden_growth.db", "GROWTH_DB_PATH")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seo_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            topic TEXT,
            content TEXT,
            injection_clean INTEGER DEFAULT 1,
            status TEXT DEFAULT 'PENDING_REVIEW',
            created_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS budget_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            channel TEXT,
            current_usd REAL,
            proposed_usd REAL,
            delta_usd REAL,
            rationale TEXT,
            status TEXT DEFAULT 'PENDING_HUMAN_APPROVAL',
            created_at INTEGER
        )
    """)
    conn.commit()
    return conn


async def fetch_market_signals(
    tenant_id: str = "default",
    keywords: list[str] | None = None,
    source: str = "trends",
) -> dict:
    """Return lightweight market signal summary. No external API in this implementation."""
    kw = keywords or []
    now = int(time.time())
    # In production: call SerpAPI / Google Trends / Crunchbase. Stub returns structured format.
    return {
        "source": source,
        "keywords": kw,
        "signals": [
            {
                "keyword": k,
                "trend": "rising",
                "volume_index": 70 + (hash(k) % 30),
                "competition": "medium",
                "sampled_at": now,
            }
            for k in kw[:10]
        ],
        "note": "Production: integrate SerpAPI / Crunchbase for live data.",
    }


async def generate_seo_content(
    tenant_id: str = "default",
    topic: str = "",
    target_keywords: list[str] | None = None,
    word_count: int = 500,
) -> dict:
    """
    Draft SEO content with Haiku then pre-screen for injection (Rec-1).
    Content is queued as PENDING_REVIEW — never published autonomously.
    """
    kw = target_keywords or []
    content_draft = (
        f"# {topic}\n\n"
        f"Keywords: {', '.join(kw)}\n\n"
        f"[Claude Haiku would generate ~{word_count} words here. "
        "Production: call claude-haiku-4-5 with SEO system prompt]\n\n"
        f"Target length: {word_count} words."
    )

    # Rec-1: pre-screen draft through filter — S6 fail-SAFE (observable + throttled bypass).
    from warden.staff.tools._prescreen import prescreen_freetext
    _pre = await prescreen_freetext(
        content_draft, tenant_id, agent_id="growth", stage_detail=f"seo:{topic[:40]}"
    )
    injection_clean = _pre.allowed

    conn = _db()
    try:
        cur = conn.execute(
            "INSERT INTO seo_drafts (tenant_id,topic,content,injection_clean,status,created_at) VALUES (?,?,?,?,?,?)",
            (tenant_id, topic, content_draft, int(injection_clean), "PENDING_REVIEW", int(time.time())),
        )
        conn.commit()
        draft_id = cur.lastrowid
    finally:
        conn.close()

    return {
        "draft_id": draft_id,
        "topic": topic,
        "injection_clean": injection_clean,
        "status": "PENDING_REVIEW",
        "note": "Content queued for human review before publication.",
    }


async def adjust_ad_budget(
    tenant_id: str = "default",
    channel: str = "",
    current_usd: float = 0.0,
    proposed_usd: float = 0.0,
    rationale: str = "",
) -> dict:
    """Propose budget adjustment. Always requires human approval — logs to queue."""
    delta = proposed_usd - current_usd
    conn = _db()
    try:
        cur = conn.execute(
            "INSERT INTO budget_proposals (tenant_id,channel,current_usd,proposed_usd,delta_usd,rationale,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (tenant_id, channel, current_usd, proposed_usd, delta, rationale, "PENDING_HUMAN_APPROVAL", int(time.time())),
        )
        conn.commit()
        return {
            "proposal_id": cur.lastrowid,
            "channel": channel,
            "delta_usd": round(delta, 2),
            "status": "PENDING_HUMAN_APPROVAL",
            "note": "Budget proposals always require explicit human authorization.",
        }
    finally:
        conn.close()


GROWTH_TOOL_HANDLERS = {
    "fetch_market_signals": fetch_market_signals,
    "generate_seo_content": generate_seo_content,
    "adjust_ad_budget": adjust_ad_budget,
}

GROWTH_TOOLS = [
    {
        "name": "fetch_market_signals",
        "description": "Fetch market trend signals for given keywords.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keywords": {"type": "array", "items": {"type": "string"}},
                "source": {"type": "string", "enum": ["trends", "news", "social"]},
            },
        },
    },
    {
        "name": "generate_seo_content",
        "description": "Draft SEO content brief for a topic. Pre-screened for injection; queued for human review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "topic": {"type": "string"},
                "target_keywords": {"type": "array", "items": {"type": "string"}},
                "word_count": {"type": "integer"},
            },
            "required": ["topic"],
        },
    },
    {
        "name": "adjust_ad_budget",
        "description": "Propose an advertising budget change. Human must authorize before any spend changes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string"},
                "current_usd": {"type": "number"},
                "proposed_usd": {"type": "number"},
                "rationale": {"type": "string"},
            },
            "required": ["channel", "proposed_usd"],
        },
    },
]
