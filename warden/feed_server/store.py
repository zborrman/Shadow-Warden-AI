"""
warden/feed_server/store.py
────────────────────────────
SQLite store for the central Threat Intelligence Feed server.

Tables
──────
  rules          Submitted (anonymised) rules waiting for vetting / publication
  subscriptions  API keys for feed subscribers (tier: free | pro | msp)
  audit_log      Immutable append-only log of all rule state transitions

Thread-safe: all writes protected by threading.Lock + WAL journal mode.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.feed_server.store")

_DB_PATH = Path(__import__("os").getenv("FEED_DB_PATH", "/warden/data/feed_server.db"))

# Submission rate cap per source_id per calendar day
_DAILY_SUBMIT_CAP = int(__import__("os").getenv("FEED_DAILY_SUBMIT_CAP", "50"))


class FeedStore:
    """Central registry: stores submissions and serves the public feed."""

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self._path = db_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = self._open()
        self._init_schema()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id     TEXT PRIMARY KEY,
                    rule_type   TEXT NOT NULL,
                    value       TEXT NOT NULL UNIQUE,
                    attack_type TEXT NOT NULL DEFAULT 'jailbreak',
                    risk_level  TEXT NOT NULL DEFAULT 'high',
                    source_id   TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    published   TEXT,
                    submitted   TEXT NOT NULL,
                    downloads   INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_rules_status  ON rules(status);
                CREATE INDEX IF NOT EXISTS idx_rules_source  ON rules(source_id);

                -- Tracks every source that has submitted a given rule value.
                -- Populated on first submit AND on every dedup hit (different source,
                -- same value) so that auto_vet can correctly count unique sources.
                CREATE TABLE IF NOT EXISTS rule_sources (
                    rule_id   TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    submitted TEXT NOT NULL,
                    UNIQUE(rule_id, source_id)
                );
                CREATE INDEX IF NOT EXISTS idx_rule_sources_rule ON rule_sources(rule_id);

                CREATE TABLE IF NOT EXISTS subscriptions (
                    sub_id      TEXT PRIMARY KEY,
                    key_hash    TEXT NOT NULL UNIQUE,
                    tier        TEXT NOT NULL DEFAULT 'free',
                    label       TEXT NOT NULL DEFAULT '',
                    active      INTEGER NOT NULL DEFAULT 1,
                    created_at  TEXT NOT NULL,
                    last_seen   TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,
                    rule_id     TEXT,
                    action      TEXT NOT NULL,
                    detail      TEXT
                );
            """)
            self._conn.commit()

    def _audit(self, action: str, rule_id: str | None = None, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO audit_log (ts, rule_id, action, detail) VALUES (?, ?, ?, ?)",
            (datetime.now(UTC).isoformat(), rule_id, action, detail),
        )

    # ── Submission ────────────────────────────────────────────────────────────

    def submit(
        self,
        rule_type:   str,
        value:       str,
        attack_type: str,
        risk_level:  str,
        source_id:   str,
    ) -> dict:
        """
        Accept an anonymised rule submission.

        Returns a dict with ``rule_id`` and ``status``.
        Raises ``ValueError`` on rate-limit breach, duplicate, or invalid input.
        """
        value = value.strip()
        if not value or len(value) < 10:
            raise ValueError("Rule value too short.")
        if rule_type not in ("semantic_example", "regex_pattern"):
            raise ValueError(f"Unknown rule_type {rule_type!r}.")
        if risk_level not in ("high", "block", "medium"):
            raise ValueError(f"Unknown risk_level {risk_level!r}.")

        today = datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock:
            # Rate cap: max N submissions per source_id per day
            (count,) = self._conn.execute(
                "SELECT COUNT(*) FROM rules WHERE source_id=? AND submitted LIKE ?",
                (source_id, f"{today}%"),
            ).fetchone()
            if count >= _DAILY_SUBMIT_CAP:
                raise ValueError(
                    f"Daily submission cap ({_DAILY_SUBMIT_CAP}) reached for this source."
                )

            # Dedup by value — if value already exists, record this source
            # in rule_sources so auto_vet can count unique contributors.
            existing = self._conn.execute(
                "SELECT rule_id, status FROM rules WHERE value=?", (value,)
            ).fetchone()
            if existing:
                rid_existing = existing["rule_id"]
                now_existing = datetime.now(UTC).isoformat()
                self._conn.execute(
                    "INSERT OR IGNORE INTO rule_sources (rule_id, source_id, submitted)"
                    " VALUES (?, ?, ?)",
                    (rid_existing, source_id, now_existing),
                )
                self._conn.commit()
                return {"rule_id": rid_existing, "status": existing["status"]}

            rule_id = str(uuid.uuid4())
            now     = datetime.now(UTC).isoformat()
            self._conn.execute(
                """INSERT INTO rules
                   (rule_id, rule_type, value, attack_type, risk_level,
                    source_id, status, submitted)
                   VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (rule_id, rule_type, value, attack_type, risk_level, source_id, now),
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO rule_sources (rule_id, source_id, submitted)"
                " VALUES (?, ?, ?)",
                (rule_id, source_id, now),
            )
            self._audit("submit", rule_id, f"source={source_id} type={attack_type}")
            self._conn.commit()

        log.info("FeedStore: new rule %s (attack=%s).", rule_id, attack_type)
        return {"rule_id": rule_id, "status": "pending"}

    # ── Vetting (auto-publish after threshold) ────────────────────────────────

    def auto_vet(self, min_unique_sources: int = 2) -> int:
        """
        Publish rules that have been submitted by at least N distinct source_ids.
        Returns number of newly published rules.
        This provides basic crowd-vetting without manual review.
        """
        now = datetime.now(UTC).isoformat()
        with self._lock:
            # Join with rule_sources to get an accurate count of distinct
            # contributors — the rules table only stores the first source_id.
            rows = self._conn.execute(
                """
                SELECT r.rule_id, r.value
                FROM rules r
                JOIN (
                    SELECT rule_id, COUNT(DISTINCT source_id) AS src_count
                    FROM rule_sources
                    GROUP BY rule_id
                ) rs ON rs.rule_id = r.rule_id
                WHERE r.status = 'pending'
                  AND rs.src_count >= ?
                """,
                (min_unique_sources,),
            ).fetchall()

            published = 0
            for row in rows:
                self._conn.execute(
                    "UPDATE rules SET status='published', published=? WHERE rule_id=?",
                    (now, row["rule_id"]),
                )
                self._audit("publish", row["rule_id"], "auto-vet passed")
                published += 1

            if published:
                self._conn.commit()

        if published:
            log.info("FeedStore: auto-vetted %d rule(s).", published)
        return published

    def reject(self, rule_id: str, reason: str = "") -> bool:
        """Manually reject a pending rule."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE rules SET status='rejected' WHERE rule_id=? AND status='pending'",
                (rule_id,),
            )
            if cur.rowcount:
                self._audit("reject", rule_id, reason)
                self._conn.commit()
            return bool(cur.rowcount)

    def publish(self, rule_id: str) -> bool:
        """Manually approve a pending rule. No-op if already rejected or published."""
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE rules SET status='published', published=?"
                " WHERE rule_id=? AND status='pending'",
                (now, rule_id),
            )
            if cur.rowcount:
                self._audit("publish", rule_id, "manual")
                self._conn.commit()
            return bool(cur.rowcount)

    # ── Feed serving ──────────────────────────────────────────────────────────

    def get_feed(self, since: str | None = None, limit: int = 500) -> dict:
        """
        Return the published feed as a dict ready to JSON-serialise.
        ``since`` is an ISO-8601 timestamp — only newer rules are returned.
        """
        params: list = []
        where = "status = 'published'"
        if since:
            where += " AND published > ?"
            params.append(since)

        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT rule_id, rule_type, value, attack_type,
                       risk_level, source_id, published, downloads
                FROM rules WHERE {where}
                ORDER BY published DESC LIMIT ?
                """,
                (*params, limit),
            ).fetchall()

            total = self._conn.execute(
                "SELECT COUNT(*) FROM rules WHERE status='published'"
            ).fetchone()[0]

            # Increment download counter
            if rows:
                ids = [r["rule_id"] for r in rows]
                self._conn.execute(
                    f"UPDATE rules SET downloads = downloads + 1 WHERE rule_id IN ({','.join('?'*len(ids))})",
                    ids,
                )
                self._conn.commit()

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "total_published": total,
            "rules": [
                {
                    "rule_id":     r["rule_id"],
                    "rule_type":   r["rule_type"],
                    "value":       r["value"],
                    "attack_type": r["attack_type"],
                    "risk_level":  r["risk_level"],
                    "source_id":   r["source_id"],
                    "published":   r["published"],
                    "downloads":   r["downloads"],
                }
                for r in rows
            ],
        }

    # ── Subscription management ───────────────────────────────────────────────

    def add_subscription(self, key_hash: str, tier: str, label: str) -> str:
        """Register a new subscriber API key (hash only — raw key never stored)."""
        sub_id = str(uuid.uuid4())
        now    = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO subscriptions
                   (sub_id, key_hash, tier, label, created_at) VALUES (?, ?, ?, ?, ?)""",
                (sub_id, key_hash, tier, label, now),
            )
            self._conn.commit()
        return sub_id

    def verify_key(self, api_key: str) -> dict | None:
        """Return subscription row if key is valid and active, else None."""
        import hashlib as _hl
        h = _hl.sha256(api_key.encode()).hexdigest()
        with self._lock:
            row = self._conn.execute(
                "SELECT sub_id, tier, label FROM subscriptions WHERE key_hash=? AND active=1",
                (h,),
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE subscriptions SET last_seen=? WHERE sub_id=?",
                    (datetime.now(UTC).isoformat(), row["sub_id"]),
                )
                self._conn.commit()
        return dict(row) if row else None

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            (total,)     = self._conn.execute("SELECT COUNT(*) FROM rules").fetchone()
            (published,) = self._conn.execute("SELECT COUNT(*) FROM rules WHERE status='published'").fetchone()
            (pending,)   = self._conn.execute("SELECT COUNT(*) FROM rules WHERE status='pending'").fetchone()
            (subs,)      = self._conn.execute("SELECT COUNT(*) FROM subscriptions WHERE active=1").fetchone()
        return {
            "total_rules":      total,
            "published_rules":  published,
            "pending_rules":    pending,
            "active_subs":      subs,
        }

    def close(self) -> None:
        self._conn.close()
