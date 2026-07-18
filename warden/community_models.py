"""
Community data models + SQLite schema.
Uses the same SEP_DB_PATH pattern as sep.py / stix_audit.py.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

_DB_PATH = data_path("warden_community.db", "COMMUNITY_DB_PATH")

_COMMUNITY_MODELS_DDL = """
CREATE TABLE IF NOT EXISTS community_members (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',
    joined_at   TEXT NOT NULL,
    UNIQUE(tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS community_posts (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    author_id    TEXT NOT NULL,
    content      TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'manual',
    obsidian_ueciid TEXT,
    nim_verdict  TEXT,
    nim_score    REAL,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS community_comments (
    id        TEXT PRIMARY KEY,
    post_id   TEXT NOT NULL REFERENCES community_posts(id),
    tenant_id TEXT NOT NULL,
    author_id TEXT NOT NULL,
    content   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_tenant   ON community_posts(tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_comments_post  ON community_comments(post_id);
"""
register("community_models", "warden.community_models", _COMMUNITY_MODELS_DDL)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with open_db("community_models", _DB_PATH, module_default_path=_DB_PATH) as con:
        yield con


def init_db() -> None:
    """Schema is ensured automatically by _conn(); kept as a no-op entry point
    for callers (warden/api/community.py) that invoke it eagerly at import."""
    with _conn():
        pass


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class Member:
    id: str
    tenant_id: str
    user_id: str
    display_name: str
    role: str = "member"
    joined_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def summary(self) -> str:
        return f"Member({self.display_name}, role={self.role}, tenant={self.tenant_id})"


@dataclass
class Post:
    id: str
    tenant_id: str
    author_id: str
    content: str
    source: str = "manual"          # "manual" | "obsidian" | "api"
    obsidian_ueciid: str | None = None
    nim_verdict: str | None = None  # SAFE | WARN | BLOCK
    nim_score: float | None = None
    status: str = "pending"         # pending | approved | blocked
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def summary(self) -> str:
        preview = self.content[:60].replace("\n", " ")
        return (
            f"Post({self.id[:8]}, status={self.status}, "
            f"nim={self.nim_verdict}, source={self.source}): {preview!r}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "author_id": self.author_id,
            "content": self.content,
            "source": self.source,
            "obsidian_ueciid": self.obsidian_ueciid,
            "nim_verdict": self.nim_verdict,
            "nim_score": self.nim_score,
            "status": self.status,
            "created_at": self.created_at,
        }


@dataclass
class Comment:
    id: str
    post_id: str
    tenant_id: str
    author_id: str
    content: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


# ── DB helpers ────────────────────────────────────────────────────────────────

def create_post(post: Post) -> Post:
    with _conn() as c:
        c.execute(
            "INSERT INTO community_posts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (post.id, post.tenant_id, post.author_id, post.content,
             post.source, post.obsidian_ueciid, post.nim_verdict,
             post.nim_score, post.status, post.created_at, post.updated_at),
        )
    return post


def update_post_status(post_id: str, status: str, nim_verdict: str | None,
                       nim_score: float | None) -> None:
    now = datetime.now(UTC).isoformat()
    with _conn() as c:
        c.execute(
            "UPDATE community_posts SET status=?, nim_verdict=?, nim_score=?, updated_at=? WHERE id=?",
            (status, nim_verdict, nim_score, now, post_id),
        )


def get_feed(tenant_id: str, limit: int = 50, offset: int = 0) -> list[Post]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM community_posts WHERE tenant_id=? AND status='approved' "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (tenant_id, limit, offset),
        ).fetchall()
    return [Post(**dict(r)) for r in rows]


def get_post(post_id: str) -> Post | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM community_posts WHERE id=?", (post_id,)).fetchone()
    return Post(**dict(row)) if row else None


def create_comment(comment: Comment) -> Comment:
    with _conn() as c:
        c.execute(
            "INSERT INTO community_comments VALUES (?,?,?,?,?,?)",
            (comment.id, comment.post_id, comment.tenant_id,
             comment.author_id, comment.content, comment.created_at),
        )
    return comment


def get_comments(post_id: str) -> list[Comment]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM community_comments WHERE post_id=? ORDER BY created_at",
            (post_id,),
        ).fetchall()
    return [Comment(**dict(r)) for r in rows]


def register_member(member: Member) -> Member:
    with _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO community_members VALUES (?,?,?,?,?,?)",
            (member.id, member.tenant_id, member.user_id,
             member.display_name, member.role, member.joined_at),
        )
    return member


def get_members(tenant_id: str) -> list[Member]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM community_members WHERE tenant_id=? ORDER BY joined_at",
            (tenant_id,),
        ).fetchall()
    return [Member(**dict(r)) for r in rows]
