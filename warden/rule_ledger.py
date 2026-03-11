"""
warden/rule_ledger.py
─────────────────────
SQLite-backed effectiveness ledger for evolution-generated detection rules.

Tracks for every rule:
  • activation_count  — how many times it has fired on live traffic
  • last_fired_at     — timestamp of most recent activation
  • fp_reports        — number of false-positive reports submitted by operators
  • status            — pending_review | active | retired

Rule lifecycle
──────────────
  evolution engine creates rule  →  status=pending_review
  first match on live traffic    →  status=active, activation_count++
  operator reports false positive →  fp_reports++ → retired when ≥ FP_RETIRE_THRESHOLD
  retire_stale() sweep           →  retired when activation_count=0 AND age > RETIRE_AFTER_DAYS

Thread-safe: all writes are protected by a threading.Lock.
Database uses WAL journal mode for concurrent reads without blocking writes.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

log = logging.getLogger("warden.rule_ledger")

# ── Config ────────────────────────────────────────────────────────────────────

LEDGER_PATH = Path(
    os.getenv("RULE_LEDGER_PATH", "/warden/data/rule_ledger.db")
)
RETIRE_AFTER_DAYS    = int(os.getenv("RULE_RETIRE_DAYS",    "30"))
FP_RETIRE_THRESHOLD  = int(os.getenv("RULE_FP_THRESHOLD",   "3"))


# ── RuleLedger ────────────────────────────────────────────────────────────────

class RuleLedger:
    """
    Thread-safe SQLite ledger for evolution-generated rule lifecycle management.

    Typical usage (warden/main.py)::

        _ledger = RuleLedger()

        # At startup — retire any stale rules from last run
        _ledger.retire_stale()

        # Pass to EvolutionEngine so it writes new rules
        _evolve = EvolutionEngine(semantic_guard=_brain_guard, ledger=_ledger)

        # In filter pipeline Stage 2.5 — when a dynamic rule fires
        _ledger.increment(rule_id)

        # POST /rules/{rule_id}/report-fp
        _ledger.report_fp(rule_id)
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or LEDGER_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = self._open()
        self._init_schema()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id          TEXT PRIMARY KEY,
                    source           TEXT NOT NULL DEFAULT 'evolution',
                    created_at       TEXT NOT NULL,
                    pattern_snippet  TEXT NOT NULL,
                    rule_type        TEXT NOT NULL DEFAULT 'regex_pattern',
                    activation_count INTEGER NOT NULL DEFAULT 0,
                    last_fired_at    TEXT,
                    fp_reports       INTEGER NOT NULL DEFAULT 0,
                    status           TEXT NOT NULL DEFAULT 'pending_review'
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(rule_type)"
            )
            self._conn.commit()

    # ── Write ─────────────────────────────────────────────────────────────────

    def write_rule(
        self,
        rule_id:         str,
        source:          str,
        created_at:      str,
        pattern_snippet: str,
        rule_type:       str = "regex_pattern",
        status:          str = "pending_review",
    ) -> None:
        """
        Insert a new rule record.  Idempotent — silently ignores duplicate
        rule_id (INSERT OR IGNORE) so safe to call on restart.
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO rules
                    (rule_id, source, created_at, pattern_snippet, rule_type, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rule_id, source, created_at, pattern_snippet, rule_type, status),
            )
            self._conn.commit()
        log.debug("RuleLedger: wrote rule %s (type=%s status=%s)", rule_id, rule_type, status)

    # ── Activate ──────────────────────────────────────────────────────────────

    def increment(self, rule_id: str) -> None:
        """
        Record that *rule_id* matched an incoming request.

        Side-effects:
          • activation_count incremented by 1
          • last_fired_at updated to now (UTC)
          • status promoted from 'pending_review' → 'active' on first match
        """
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                UPDATE rules
                SET activation_count = activation_count + 1,
                    last_fired_at    = ?,
                    status           = CASE
                        WHEN status = 'pending_review' THEN 'active'
                        ELSE status
                    END
                WHERE rule_id = ?
                """,
                (now, rule_id),
            )
            self._conn.commit()

    # ── False-positive reporting ───────────────────────────────────────────────

    def report_fp(self, rule_id: str) -> bool:
        """
        Increment fp_reports for *rule_id*.

        Returns True if the rule was found, False if the rule_id is unknown.
        Auto-retires the rule when fp_reports reaches FP_RETIRE_THRESHOLD.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT fp_reports FROM rules WHERE rule_id = ?", (rule_id,)
            )
            row = cur.fetchone()
            if row is None:
                return False

            new_fp     = row[0] + 1
            new_status = "retired" if new_fp >= FP_RETIRE_THRESHOLD else "active"
            self._conn.execute(
                """
                UPDATE rules
                SET fp_reports = ?,
                    status     = ?
                WHERE rule_id = ?
                """,
                (new_fp, new_status, rule_id),
            )
            self._conn.commit()

        if new_fp >= FP_RETIRE_THRESHOLD:
            log.info(
                "RuleLedger: rule %s retired — FP threshold (%d) reached.",
                rule_id, FP_RETIRE_THRESHOLD,
            )
        return True

    # ── Retirement sweep ──────────────────────────────────────────────────────

    def retire_stale(self) -> int:
        """
        Retire rules that have never fired AND were created more than
        RETIRE_AFTER_DAYS days ago.

        Returns the number of rules retired in this sweep.
        """
        cutoff = (
            datetime.now(UTC) - timedelta(days=RETIRE_AFTER_DAYS)
        ).isoformat()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE rules
                SET status = 'retired'
                WHERE status IN ('pending_review', 'active')
                  AND activation_count = 0
                  AND created_at < ?
                """,
                (cutoff,),
            )
            self._conn.commit()
        count = cur.rowcount
        if count:
            log.info(
                "RuleLedger: retired %d stale rule(s) (no activations in %d days).",
                count, RETIRE_AFTER_DAYS,
            )
        return count

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_rule(self, rule_id: str) -> dict | None:
        """Return the full ledger record for *rule_id*, or None."""
        cur = self._conn.execute(
            "SELECT rule_id, source, created_at, pattern_snippet, rule_type, "
            "activation_count, last_fired_at, fp_reports, status "
            "FROM rules WHERE rule_id = ?",
            (rule_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "rule_id":          row[0],
            "source":           row[1],
            "created_at":       row[2],
            "pattern_snippet":  row[3],
            "rule_type":        row[4],
            "activation_count": row[5],
            "last_fired_at":    row[6],
            "fp_reports":       row[7],
            "status":           row[8],
        }

    def list_rules(
        self,
        status: str | None = None,
        limit:  int        = 100,
    ) -> list[dict]:
        """Return up to *limit* rules, optionally filtered by *status*."""
        _cols = (
            "rule_id, source, created_at, pattern_snippet, rule_type, "
            "activation_count, last_fired_at, fp_reports, status"
        )
        if status:
            cur = self._conn.execute(
                f"SELECT {_cols} FROM rules WHERE status = ? LIMIT ?",
                (status, limit),
            )
        else:
            cur = self._conn.execute(
                f"SELECT {_cols} FROM rules LIMIT ?",
                (limit,),
            )
        col_names = [
            "rule_id", "source", "created_at", "pattern_snippet", "rule_type",
            "activation_count", "last_fired_at", "fp_reports", "status",
        ]
        return [dict(zip(col_names, row, strict=False)) for row in cur.fetchall()]

    def get_active_regex_rules(self) -> list[dict]:
        """
        Return all non-retired regex_pattern rules suitable for dynamic matching.

        Used at startup to build the in-memory pattern list, and by the hot-reload
        callback when the evolution engine produces a new regex rule.
        """
        cur = self._conn.execute(
            "SELECT rule_id, pattern_snippet FROM rules "
            "WHERE rule_type = 'regex_pattern' AND status != 'retired'"
        )
        return [{"rule_id": row[0], "pattern": row[1]} for row in cur.fetchall()]

    # ── Admin / manual lifecycle ──────────────────────────────────────────────

    def approve_rule(self, rule_id: str) -> bool:
        """
        Manually promote a *pending_review* rule to *active*.

        Called by ``POST /admin/rules/{rule_id}/approve`` when
        ``RULE_REVIEW_MODE=manual``.  Returns True if the rule was found and
        promoted, False if the rule_id is unknown or was not in pending_review.
        """
        with self._lock:
            cur = self._conn.execute(
                "UPDATE rules SET status='active' WHERE rule_id=? AND status='pending_review'",
                (rule_id,),
            )
            self._conn.commit()
        found = cur.rowcount > 0
        if found:
            log.info("RuleLedger: rule %s manually approved → active", rule_id)
        return found

    def retire_rule(self, rule_id: str) -> bool:
        """
        Manually retire a rule regardless of its current status.

        Called by ``DELETE /admin/rules/{rule_id}``.  Returns True if the rule
        was found, False if the rule_id is unknown.
        """
        with self._lock:
            cur = self._conn.execute(
                "UPDATE rules SET status='retired' WHERE rule_id=?",
                (rule_id,),
            )
            self._conn.commit()
        found = cur.rowcount > 0
        if found:
            log.info("RuleLedger: rule %s manually retired", rule_id)
        return found

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()
