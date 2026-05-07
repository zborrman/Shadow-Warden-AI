"""
warden/communities/reputation.py
─────────────────────────────────
Community reputation engine — points, badges, leaderboard.

Points ledger
  PUBLISH_ENTRY   +5   — tenant published a new UECIID to the SEP hub
  SEARCH_HIT      +1   — one of their entries matched another tenant's search
  REC_ADOPTED    +10   — a recommendation they published was applied by another tenant
  TRUSTED_ENTRY   +3   — entry received zero takedown reports for 30 days

Badges (cumulative thresholds)
  NEWCOMER         0 pts  — default
  CONTRIBUTOR     25 pts
  TOP_SHARER     100 pts
  GUARDIAN       300 pts
  ELITE          750 pts  — invitation-only via admin

GDPR: tenant_id stored only in the private table.  Public leaderboard
returns rank + badge + entry_count + points with no tenant identifier.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Generator

log = logging.getLogger("warden.communities.reputation")

_DB_PATH = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")

BADGE_THRESHOLDS = [
    ("ELITE",       750),
    ("GUARDIAN",    300),
    ("TOP_SHARER",  100),
    ("CONTRIBUTOR",  25),
    ("NEWCOMER",      0),
]

BADGE_EMOJI = {
    "ELITE":       "🏆",
    "GUARDIAN":    "🛡️",
    "TOP_SHARER":  "📡",
    "CONTRIBUTOR": "⭐",
    "NEWCOMER":    "🌱",
}

POINT_EVENTS = {
    "PUBLISH_ENTRY":  5,
    "SEARCH_HIT":     1,
    "REC_ADOPTED":   10,
    "TRUSTED_ENTRY":  3,
}


class Badge(str, Enum):
    NEWCOMER    = "NEWCOMER"
    CONTRIBUTOR = "CONTRIBUTOR"
    TOP_SHARER  = "TOP_SHARER"
    GUARDIAN    = "GUARDIAN"
    ELITE       = "ELITE"


@dataclass
class ReputationRecord:
    tenant_id:   str
    points:      int
    badge:       str
    entry_count: int

    @property
    def badge_emoji(self) -> str:
        return BADGE_EMOJI.get(self.badge, "")

    def to_public_dict(self, rank: int) -> dict:
        """Return only non-identifying fields for the public leaderboard."""
        return {
            "rank":        rank,
            "badge":       self.badge,
            "badge_emoji": self.badge_emoji,
            "points":      self.points,
            "entry_count": self.entry_count,
        }

    def to_dict(self) -> dict:
        return {
            "tenant_id":   self.tenant_id,
            "points":      self.points,
            "badge":       self.badge,
            "badge_emoji": self.badge_emoji,
            "entry_count": self.entry_count,
        }


def _badge_for(points: int, forced: str | None = None) -> str:
    if forced:
        return forced
    for badge, threshold in BADGE_THRESHOLDS:
        if points >= threshold:
            return badge
    return "NEWCOMER"


@contextmanager
def _db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS community_reputation (
                tenant_id   TEXT PRIMARY KEY,
                points      INTEGER NOT NULL DEFAULT 0,
                badge       TEXT    NOT NULL DEFAULT 'NEWCOMER',
                entry_count INTEGER NOT NULL DEFAULT 0,
                forced_badge TEXT,
                updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reputation_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id  TEXT    NOT NULL,
                event_type TEXT    NOT NULL,
                delta      INTEGER NOT NULL,
                ref_ueciid TEXT,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
        yield conn
    finally:
        conn.close()


def award_points(tenant_id: str, event_type: str, ref_ueciid: str = "") -> ReputationRecord:
    """Award points for a reputation event and return updated record."""
    delta = POINT_EVENTS.get(event_type, 0)
    if delta == 0:
        log.debug("reputation: unknown event_type=%s — no points awarded", event_type)

    with _db() as conn:
        conn.execute("""
            INSERT INTO community_reputation (tenant_id, points, entry_count)
            VALUES (?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                points      = points + excluded.points,
                entry_count = entry_count + CASE WHEN ?='PUBLISH_ENTRY' THEN 1 ELSE 0 END,
                updated_at  = datetime('now')
        """, (tenant_id, delta, 1 if event_type == "PUBLISH_ENTRY" else 0, event_type))

        conn.execute("""
            INSERT INTO reputation_events (tenant_id, event_type, delta, ref_ueciid)
            VALUES (?, ?, ?, ?)
        """, (tenant_id, event_type, delta, ref_ueciid))

        row = conn.execute(
            "SELECT * FROM community_reputation WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        conn.commit()

    new_badge = _badge_for(row["points"], row["forced_badge"])

    with _db() as conn:
        conn.execute(
            "UPDATE community_reputation SET badge=? WHERE tenant_id=?",
            (new_badge, tenant_id),
        )
        conn.commit()

    log.info("reputation: tenant=%s event=%s delta=%d badge=%s", tenant_id, event_type, delta, new_badge)
    return ReputationRecord(
        tenant_id=tenant_id,
        points=row["points"] + delta,
        badge=new_badge,
        entry_count=row["entry_count"] + (1 if event_type == "PUBLISH_ENTRY" else 0),
    )


def get_reputation(tenant_id: str) -> ReputationRecord:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM community_reputation WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    if not row:
        return ReputationRecord(tenant_id=tenant_id, points=0, badge="NEWCOMER", entry_count=0)
    return ReputationRecord(
        tenant_id=row["tenant_id"],
        points=row["points"],
        badge=row["badge"],
        entry_count=row["entry_count"],
    )


def get_leaderboard(limit: int = 10) -> list[dict]:
    """Return anonymised leaderboard (no tenant_id)."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT points, badge, entry_count FROM community_reputation ORDER BY points DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "rank":        i + 1,
            "badge":       r["badge"],
            "badge_emoji": BADGE_EMOJI.get(r["badge"], ""),
            "points":      r["points"],
            "entry_count": r["entry_count"],
        }
        for i, r in enumerate(rows)
    ]


def force_badge(tenant_id: str, badge: str) -> None:
    """Admin-only: manually grant ELITE badge."""
    with _db() as conn:
        conn.execute("""
            INSERT INTO community_reputation (tenant_id, badge, forced_badge)
            VALUES (?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET forced_badge=?, badge=?, updated_at=datetime('now')
        """, (tenant_id, badge, badge, badge, badge))
        conn.commit()
