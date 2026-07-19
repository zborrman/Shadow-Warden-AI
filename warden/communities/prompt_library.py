"""
warden/communities/prompt_library.py  (CM-37)
──────────────────────────────────────────────
Shared Prompt Library — community-scoped prompt templates with UECIID
provenance tracking, versioning, and SEP-based cross-community sharing.

Each prompt is screened through the warden filter before storage to prevent
injection attacks embedded in shared prompts.

Tiers: Community Business+ (prompt_library_enabled)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.communities.prompt_library")

_DB_PATH = data_path("warden_sep.db", "SEP_DB_PATH")
_db_lock = threading.RLock()

_VISIBILITIES = {"community", "peered", "private"}
_STATUSES     = {"active", "deprecated", "draft"}


@dataclass
class PromptEntry:
    prompt_id:   str
    ueciid:      str
    community_id: str
    created_by:  str
    title:       str
    description: str
    prompt_text: str
    category:    str
    tags:        list
    version:     int
    parent_id:   str | None
    use_count:   int
    status:      str
    visibility:  str
    created_at:  str
    updated_at:  str

    def to_dict(self) -> dict:
        return {
            "prompt_id":    self.prompt_id,
            "ueciid":       self.ueciid,
            "community_id": self.community_id,
            "created_by":   self.created_by,
            "title":        self.title,
            "description":  self.description,
            "prompt_text":  self.prompt_text,
            "category":     self.category,
            "tags":         self.tags,
            "version":      self.version,
            "parent_id":    self.parent_id,
            "use_count":    self.use_count,
            "status":       self.status,
            "visibility":   self.visibility,
            "created_at":   self.created_at,
            "updated_at":   self.updated_at,
        }


_PROMPT_LIBRARY_DDL = """
    CREATE TABLE IF NOT EXISTS prompt_library (
        prompt_id    TEXT PRIMARY KEY,
        ueciid       TEXT NOT NULL UNIQUE,
        community_id TEXT NOT NULL,
        created_by   TEXT NOT NULL,
        title        TEXT NOT NULL,
        description  TEXT NOT NULL DEFAULT '',
        prompt_text  TEXT NOT NULL,
        category     TEXT NOT NULL DEFAULT 'general',
        tags         TEXT NOT NULL DEFAULT '[]',
        version      INTEGER NOT NULL DEFAULT 1,
        parent_id    TEXT,
        use_count    INTEGER NOT NULL DEFAULT 0,
        status       TEXT NOT NULL DEFAULT 'active',
        visibility   TEXT NOT NULL DEFAULT 'community',
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_pl_community ON prompt_library(community_id);
    CREATE INDEX IF NOT EXISTS idx_pl_ueciid    ON prompt_library(ueciid);
    CREATE INDEX IF NOT EXISTS idx_pl_category  ON prompt_library(community_id, category);
    CREATE INDEX IF NOT EXISTS idx_pl_status    ON prompt_library(community_id, status);
"""
register("sep", "warden.communities.prompt_library", _PROMPT_LIBRARY_DDL)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "sep", db_path, turso_name="sep", module_default_path=_DB_PATH
    ) as con:
        yield con


def _assign_ueciid() -> str:
    """Assign SEP UECIID. Falls back to uuid-based ID if SEP unavailable."""
    try:
        from warden.communities.sep import new_ueciid  # noqa: PLC0415
        _, ueciid = new_ueciid()
        return ueciid
    except Exception:
        return f"PROMPT-{uuid.uuid4().hex[:11].upper()}"


def _screen_prompt(prompt_text: str) -> bool:
    """Run warden filter on prompt_text. Returns True if safe, False if blocked."""
    try:
        import httpx  # noqa: PLC0415
        base = os.getenv("WARDEN_URL", "http://localhost:8001")
        key  = os.getenv("WARDEN_API_KEY", "")
        r    = httpx.post(
            f"{base}/filter",
            json={"content": prompt_text},
            headers={"X-API-Key": key} if key else {},
            timeout=5.0,
        )
        if r.status_code == 200:
            verdict = r.json().get("verdict", "ALLOW")
            return verdict not in ("BLOCK", "HIGH")
    except Exception as exc:
        log.debug("prompt_library: filter screen unavailable — %s", exc)
    return True  # fail-open if filter unreachable


def add_prompt(
    community_id: str,
    created_by: str,
    title: str,
    prompt_text: str,
    category: str = "general",
    tags: list | None = None,
    visibility: str = "community",
    description: str = "",
    db_path: str = _DB_PATH,
) -> dict:
    """
    Add a new prompt to the library.
    Screens the prompt via the warden filter before saving.
    Raises ValueError if the prompt is flagged as HIGH_RISK/BLOCK.
    """
    if not _screen_prompt(prompt_text):
        raise ValueError("Prompt rejected by security filter — possible injection content")

    visibility = visibility if visibility in _VISIBILITIES else "community"
    ueciid     = _assign_ueciid()
    now        = datetime.now(UTC).isoformat()
    prompt_id  = str(uuid.uuid4())
    tags_list  = tags or []

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO prompt_library
               (prompt_id, ueciid, community_id, created_by, title, description,
                prompt_text, category, tags, version, parent_id, use_count,
                status, visibility, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (prompt_id, ueciid, community_id, created_by, title, description,
             prompt_text, category.lower(), json.dumps(tags_list), 1, None, 0,
             "active", visibility, now, now),
        )

    log.info("prompt_library: added %s ueciid=%s community=%s", prompt_id, ueciid, community_id)
    entry = PromptEntry(
        prompt_id=prompt_id, ueciid=ueciid, community_id=community_id,
        created_by=created_by, title=title, description=description,
        prompt_text=prompt_text, category=category.lower(), tags=tags_list,
        version=1, parent_id=None, use_count=0, status="active",
        visibility=visibility, created_at=now, updated_at=now,
    )
    return entry.to_dict()


def get_prompt(prompt_id: str, db_path: str = _DB_PATH) -> dict | None:
    with _conn(db_path) as con:
        row = con.execute("SELECT * FROM prompt_library WHERE prompt_id = ?", (prompt_id,)).fetchone()
    return _row_to_dict(row) if row else None


def search_prompts(
    community_id: str,
    query: str = "",
    category: str | None = None,
    visibility: str | None = None,
    limit: int = 20,
    db_path: str = _DB_PATH,
) -> list[dict]:
    sql    = "SELECT * FROM prompt_library WHERE community_id = ? AND status = 'active'"
    params: list = [community_id]
    if category:
        sql += " AND category = ?"
        params.append(category.lower())
    if visibility:
        sql += " AND visibility = ?"
        params.append(visibility)
    if query:
        sql += " AND (title LIKE ? OR description LIKE ?)"
        q = f"%{query}%"
        params.extend([q, q])
    sql += f" ORDER BY use_count DESC LIMIT {int(limit)}"
    with _conn(db_path) as con:
        rows = con.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def increment_use(prompt_id: str, db_path: str = _DB_PATH) -> None:
    with _db_lock, _conn(db_path) as con:
        con.execute(
            "UPDATE prompt_library SET use_count = use_count + 1, updated_at = ? WHERE prompt_id = ?",
            (datetime.now(UTC).isoformat(), prompt_id),
        )


def create_version(
    prompt_id: str,
    new_text: str,
    updated_by: str,
    db_path: str = _DB_PATH,
) -> dict:
    """Create a new version of a prompt (old one deprecated, new one active)."""
    if not _screen_prompt(new_text):
        raise ValueError("Revised prompt rejected by security filter")

    original = get_prompt(prompt_id, db_path=db_path)
    if not original:
        raise ValueError(f"Prompt {prompt_id!r} not found")

    now       = datetime.now(UTC).isoformat()
    new_id    = str(uuid.uuid4())
    ueciid    = _assign_ueciid()
    new_ver   = original["version"] + 1

    with _db_lock, _conn(db_path) as con:
        con.execute(
            "UPDATE prompt_library SET status = 'deprecated', updated_at = ? WHERE prompt_id = ?",
            (now, prompt_id),
        )
        con.execute(
            """INSERT INTO prompt_library
               (prompt_id, ueciid, community_id, created_by, title, description,
                prompt_text, category, tags, version, parent_id, use_count,
                status, visibility, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (new_id, ueciid, original["community_id"], updated_by,
             original["title"], original["description"],
             new_text, original["category"], json.dumps(original["tags"]),
             new_ver, prompt_id, 0, "active", original["visibility"], now, now),
        )
    log.info("prompt_library: versioned %s → %s (v%d)", prompt_id, new_id, new_ver)
    return get_prompt(new_id, db_path=db_path) or {}


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "[]")
    return d


def get_library_stats(community_id: str, db_path: str = _DB_PATH) -> dict:
    with _conn(db_path) as con:
        total   = con.execute("SELECT COUNT(*) FROM prompt_library WHERE community_id = ? AND status = 'active'", (community_id,)).fetchone()[0]
        uses    = con.execute("SELECT SUM(use_count) FROM prompt_library WHERE community_id = ?", (community_id,)).fetchone()[0] or 0
        cats    = con.execute(
            "SELECT category, COUNT(*) as cnt FROM prompt_library WHERE community_id = ? AND status = 'active' GROUP BY category",
            (community_id,),
        ).fetchall()
    return {
        "total_prompts":  total,
        "total_uses":     uses,
        "by_category":    {r["category"]: r["cnt"] for r in cats},
    }
