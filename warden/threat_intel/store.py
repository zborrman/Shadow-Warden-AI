"""
warden/threat_intel/store.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
SQLite-backed persistence for the Threat Intelligence Engine.

Two tables
──────────
  threat_intel_items          One row per collected + analyzed threat.
  threat_intel_countermeasures  Rules synthesized from each threat item.

Thread-safe: all writes protected by threading.Lock + WAL journal mode.
Fail-open: read errors return empty results; write errors are logged.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from warden.schemas import ThreatIntelItem, ThreatIntelStats, ThreatIntelStatus

log = logging.getLogger("warden.threat_intel.store")

THREAT_INTEL_DB_PATH = Path(
    os.getenv("THREAT_INTEL_DB_PATH", "/warden/data/threat_intel.db")
)


class ThreatIntelStore:
    """
    Persistent store for threat intelligence items and generated countermeasures.

    Usage::

        store = ThreatIntelStore()
        inserted = store.upsert_item(item)          # False when duplicate URL
        store.mark_analyzed(item.id, ...)
        store.record_countermeasure(item.id, ...)
        items = store.list_items(status="analyzed")
        stats = store.stats()
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or THREAT_INTEL_DB_PATH
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
                CREATE TABLE IF NOT EXISTS threat_intel_items (
                    id               TEXT PRIMARY KEY,
                    source           TEXT NOT NULL,
                    title            TEXT NOT NULL DEFAULT '',
                    url              TEXT NOT NULL DEFAULT '',
                    source_url_hash  TEXT NOT NULL UNIQUE,
                    published_at     TEXT,
                    raw_description  TEXT NOT NULL DEFAULT '',
                    relevance_score  REAL,
                    owasp_category   TEXT,
                    attack_pattern   TEXT NOT NULL DEFAULT '',
                    detection_hint   TEXT NOT NULL DEFAULT '',
                    countermeasure   TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'new',
                    rules_generated  INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL,
                    analyzed_at      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ti_status
                    ON threat_intel_items(status);
                CREATE INDEX IF NOT EXISTS idx_ti_source
                    ON threat_intel_items(source);
                CREATE INDEX IF NOT EXISTS idx_ti_owasp
                    ON threat_intel_items(owasp_category);
                CREATE INDEX IF NOT EXISTS idx_ti_created
                    ON threat_intel_items(created_at DESC);

                CREATE TABLE IF NOT EXISTS threat_intel_countermeasures (
                    id              TEXT PRIMARY KEY,
                    threat_item_id  TEXT NOT NULL
                        REFERENCES threat_intel_items(id),
                    rule_id         TEXT NOT NULL,
                    rule_type       TEXT NOT NULL,
                    rule_value      TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cm_threat
                    ON threat_intel_countermeasures(threat_item_id);
            """)
            self._conn.commit()

    # ── Write ─────────────────────────────────────────────────────────────────

    def upsert_item(self, item: ThreatIntelItem) -> bool:
        """
        Insert if url_hash is new.  Returns True when a new row was inserted.
        Silent no-op (returns False) when the URL was already collected.
        """
        import hashlib
        url_hash = hashlib.sha256(item.url.encode()).hexdigest()
        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO threat_intel_items
                        (id, source, title, url, source_url_hash, published_at,
                         raw_description, status, rules_generated, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.id, item.source, item.title, item.url, url_hash,
                        item.published_at, item.raw_description,
                        str(item.status), 0,
                        item.created_at,
                    ),
                )
                inserted = self._conn.execute(
                    "SELECT changes() AS n"
                ).fetchone()["n"]
                self._conn.commit()
            return bool(inserted)
        except Exception as exc:
            log.error("ThreatIntelStore.upsert_item failed: %s", exc)
            return False

    def mark_analyzed(
        self,
        item_id: str,
        *,
        relevance_score: float,
        owasp_category: str | None,
        attack_pattern: str,
        detection_hint: str,
        countermeasure: str,
        status: str = ThreatIntelStatus.ANALYZED,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                UPDATE threat_intel_items
                SET relevance_score=?, owasp_category=?, attack_pattern=?,
                    detection_hint=?, countermeasure=?, status=?, analyzed_at=?
                WHERE id=?
                """,
                (
                    relevance_score, owasp_category, attack_pattern,
                    detection_hint, countermeasure, status, now, item_id,
                ),
            )
            self._conn.commit()

    def mark_rules_generated(self, item_id: str, count: int) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE threat_intel_items
                SET status='rules_generated', rules_generated=rules_generated+?
                WHERE id=?
                """,
                (count, item_id),
            )
            self._conn.commit()

    def record_countermeasure(
        self,
        *,
        threat_item_id: str,
        rule_id: str,
        rule_type: str,
        rule_value: str,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO threat_intel_countermeasures
                    (id, threat_item_id, rule_id, rule_type, rule_value, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), threat_item_id, rule_id, rule_type, rule_value, now),
            )
            self._conn.commit()

    def dismiss(self, item_id: str) -> bool:
        with self._lock:
            self._conn.execute(
                "UPDATE threat_intel_items SET status='dismissed' WHERE id=?",
                (item_id,),
            )
            changed = self._conn.execute("SELECT changes() AS n").fetchone()["n"]
            self._conn.commit()
        return bool(changed)

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_item(self, item_id: str) -> ThreatIntelItem | None:
        row = self._conn.execute(
            "SELECT * FROM threat_intel_items WHERE id=?", (item_id,)
        ).fetchone()
        return self._row_to_item(row) if row else None

    def list_items(
        self,
        *,
        status: str | None = None,
        source: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ThreatIntelItem]:
        clauses: list[str] = []
        params: list[object] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if source:
            clauses.append("source=?")
            params.append(source)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params += [limit, offset]
        rows = self._conn.execute(
            f"SELECT * FROM threat_intel_items {where} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [self._row_to_item(r) for r in rows]

    def get_pending_analysis(self, limit: int = 20) -> list[ThreatIntelItem]:
        """Items collected but not yet analyzed."""
        return self.list_items(status=ThreatIntelStatus.NEW, limit=limit)

    def get_pending_synthesis(self, limit: int = 20) -> list[ThreatIntelItem]:
        """Analyzed items whose rules haven't been synthesized yet."""
        return self.list_items(status=ThreatIntelStatus.ANALYZED, limit=limit)

    def get_url_hashes(self) -> set[str]:
        """Return all source_url_hashes for O(1) dedup lookups."""
        rows = self._conn.execute(
            "SELECT source_url_hash FROM threat_intel_items"
        ).fetchall()
        return {r["source_url_hash"] for r in rows}

    def stats(self) -> ThreatIntelStats:
        total = self._conn.execute(
            "SELECT COUNT(*) AS n FROM threat_intel_items"
        ).fetchone()["n"]

        by_source: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT source, COUNT(*) AS n FROM threat_intel_items GROUP BY source"
        ).fetchall():
            by_source[row["source"]] = row["n"]

        by_owasp: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT owasp_category, COUNT(*) AS n FROM threat_intel_items "
            "WHERE owasp_category IS NOT NULL GROUP BY owasp_category"
        ).fetchall():
            by_owasp[row["owasp_category"]] = row["n"]

        by_status: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM threat_intel_items GROUP BY status"
        ).fetchall():
            by_status[row["status"]] = row["n"]

        rules_total = self._conn.execute(
            "SELECT COALESCE(SUM(rules_generated), 0) AS n FROM threat_intel_items"
        ).fetchone()["n"]

        last_row = self._conn.execute(
            "SELECT created_at FROM threat_intel_items ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        last_at = last_row["created_at"] if last_row else None

        return ThreatIntelStats(
            total=total,
            by_source=by_source,
            by_owasp=by_owasp,
            by_status=by_status,
            rules_generated_total=int(rules_total),
            last_collection_at=last_at,
        )

    def get_countermeasures(self, threat_item_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM threat_intel_countermeasures WHERE threat_item_id=?",
            (threat_item_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        from contextlib import suppress
        with suppress(Exception):
            self._conn.close()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> ThreatIntelItem:
        return ThreatIntelItem(
            id=row["id"],
            source=row["source"],
            title=row["title"],
            url=row["url"],
            published_at=row["published_at"],
            raw_description=row["raw_description"],
            relevance_score=row["relevance_score"],
            owasp_category=row["owasp_category"],
            attack_pattern=row["attack_pattern"] or "",
            detection_hint=row["detection_hint"] or "",
            countermeasure=row["countermeasure"] or "",
            status=ThreatIntelStatus(row["status"]),
            rules_generated=row["rules_generated"],
            created_at=row["created_at"],
            analyzed_at=row["analyzed_at"],
        )
