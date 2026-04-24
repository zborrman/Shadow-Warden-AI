"""
warden/agentic/action_whitelist.py  (Q4.10)
────────────────────────────────────────────
Agent Action Whitelist — per-agent CRUD permission enforcement.

Each registered agent carries a whitelist of permitted:
  • HTTP methods  (GET, POST, PUT, DELETE, PATCH)
  • Endpoint patterns (glob-style: "/files/*", "/users/*/read")
  • Max requests-per-second rate ceiling

check_action() is the hot-path gate called before every agent tool invocation.
Returns (allowed: bool, reason: str).

Storage: SQLite table `agent_action_whitelist` in the same DB as AgentRegistry.
Thread-safe: inherits AgentRegistry's threading.Lock.

API endpoints (mounted in main.py):
  GET    /agents/{agent_id}/whitelist          → list rules
  POST   /agents/{agent_id}/whitelist          → add rule
  DELETE /agents/{agent_id}/whitelist/{rule_id}→ remove rule
  POST   /agents/{agent_id}/whitelist/check    → check action
"""
from __future__ import annotations

import fnmatch
import logging
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime

log = logging.getLogger("warden.agentic.action_whitelist")

_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_action_whitelist (
    rule_id        TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    http_method    TEXT NOT NULL DEFAULT '*',
    endpoint_glob  TEXT NOT NULL DEFAULT '*',
    max_rps        REAL NOT NULL DEFAULT 0.0,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_awl_agent ON agent_action_whitelist(agent_id);

CREATE TABLE IF NOT EXISTS agent_action_rate (
    agent_id   TEXT PRIMARY KEY,
    window_start REAL NOT NULL DEFAULT 0.0,
    count        INTEGER NOT NULL DEFAULT 0
);
"""


class ActionWhitelist:
    """Manages per-agent action whitelist rules in the existing AgentRegistry DB."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn = conn
        self._lock = lock
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ── Rule CRUD ─────────────────────────────────────────────────────────────

    def add_rule(
        self,
        agent_id:      str,
        http_method:   str = "*",
        endpoint_glob: str = "*",
        max_rps:       float = 0.0,
    ) -> dict:
        method = http_method.upper()
        if method != "*" and method not in _ALLOWED_METHODS:
            raise ValueError(f"Invalid HTTP method: {method}")
        rule_id = str(uuid.uuid4())
        now     = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO agent_action_whitelist "
                "(rule_id, agent_id, http_method, endpoint_glob, max_rps, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (rule_id, agent_id, method, endpoint_glob, max_rps, now),
            )
            self._conn.commit()
        log.info("whitelist: rule added agent=%s method=%s glob=%s", agent_id, method, endpoint_glob)
        return self.get_rule(rule_id)  # type: ignore[return-value]

    def get_rules(self, agent_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM agent_action_whitelist WHERE agent_id=? ORDER BY created_at",
            (agent_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_rule(self, rule_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM agent_action_whitelist WHERE rule_id=?", (rule_id,)
        ).fetchone()
        return dict(row) if row else None

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM agent_action_whitelist WHERE rule_id=?", (rule_id,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    # ── Action check ──────────────────────────────────────────────────────────

    def check_action(
        self,
        agent_id:    str,
        http_method: str,
        endpoint:    str,
    ) -> tuple[bool, str]:
        """
        Return (allowed, reason).

        Logic:
          1. If no rules defined for the agent → allow (open policy, log warning).
          2. If any rule matches (method + glob) → allowed, enforce max_rps.
          3. If no rule matches → deny.
        """
        rules = self.get_rules(agent_id)
        if not rules:
            log.warning("whitelist: agent=%s has no rules — open policy (consider restricting)", agent_id)
            return True, "no_rules_open_policy"

        method = http_method.upper()
        for rule in rules:
            method_ok = rule["http_method"] in ("*", method)
            glob_ok   = fnmatch.fnmatch(endpoint, rule["endpoint_glob"])
            if method_ok and glob_ok:
                # Rate check
                rps_limit = rule["max_rps"]
                if rps_limit > 0 and not self._check_rate(agent_id, rps_limit):
                    return False, f"rate_limit_exceeded:{rps_limit}_rps"
                return True, f"rule:{rule['rule_id']}"

        return False, f"no_matching_rule:{method}:{endpoint}"

    def _check_rate(self, agent_id: str, max_rps: float) -> bool:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT window_start, count FROM agent_action_rate WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO agent_action_rate (agent_id, window_start, count) VALUES (?, ?, 1)",
                    (agent_id, now),
                )
                self._conn.commit()
                return True

            window_start, count = row["window_start"], row["count"]
            window_age = now - window_start

            if window_age >= 1.0:
                # New 1-second window
                self._conn.execute(
                    "UPDATE agent_action_rate SET window_start=?, count=1 WHERE agent_id=?",
                    (now, agent_id),
                )
                self._conn.commit()
                return True

            if count >= max_rps:
                return False

            self._conn.execute(
                "UPDATE agent_action_rate SET count=count+1 WHERE agent_id=?",
                (agent_id,),
            )
            self._conn.commit()
            return True
