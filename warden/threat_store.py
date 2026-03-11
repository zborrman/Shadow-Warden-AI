"""
warden/threat_store.py
──────────────────────
SQLite-backed persistent threat intelligence store.

Closes the "threat intelligence amnesia" gap (v0.5 Gap 2): session data that
previously lived only in Redis with a 30-minute TTL is now persisted across
restarts.  Cross-session IP correlation becomes possible.

Three tables
────────────
  threat_events       One row per detected threat event (block or session anomaly).
  attacker_profiles   Aggregated view per (ip, tenant_id) — no TTL, grows forever.
  blocked_ips         Manual and auto-populated IP blocklist, with optional expiry.

Rule lifecycle integration
──────────────────────────
  filter pipeline (BLOCK/HIGH)   → record_block_event()
  agentic session anomaly        → record_session_threat()
  POST /threats/block-ip         → block_ip()
  DELETE /threats/blocked/{ip}   → unblock_ip()
  early filter check             → is_blocked()

Thread-safe: all writes are protected by a threading.Lock.
Database uses WAL journal mode for concurrent reads without blocking writes.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

log = logging.getLogger("warden.threat_store")

# ── Config ────────────────────────────────────────────────────────────────────

THREAT_DB_PATH = Path(
    os.getenv("THREAT_DB_PATH", "/warden/data/threat_store.db")
)

# Auto-block: if an IP accumulates this many block events within the window,
# it is automatically added to blocked_ips.  Set 0 to disable auto-block.
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", "20"))
AUTO_BLOCK_WINDOW    = int(os.getenv("AUTO_BLOCK_WINDOW",    "300"))   # seconds
AUTO_BLOCK_DURATION  = int(os.getenv("AUTO_BLOCK_DURATION",  "3600"))  # seconds; 0=permanent


# ── ThreatStore ───────────────────────────────────────────────────────────────

class ThreatStore:
    """
    Persistent threat intelligence ledger for cross-session IP tracking.

    Typical usage (warden/main.py)::

        _threat_store = ThreatStore()

        # Early pipeline check — reject blocked IPs before any processing
        if _threat_store.is_blocked(client_ip, tenant_id):
            raise HTTPException(403, "IP address is blocked.")

        # On BLOCK/HIGH decision
        _threat_store.record_block_event(client_ip, tenant_id, risk_level, flags)

        # When AgentMonitor detects a session anomaly
        _threat_store.record_session_threat(client_ip, tenant_id, session_id, pattern, severity)

        # POST /threats/block-ip
        _threat_store.block_ip(ip, tenant_id, reason, blocked_by="manual")
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or THREAT_DB_PATH
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
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts         TEXT NOT NULL,
                    ip         TEXT NOT NULL DEFAULT '',
                    tenant_id  TEXT NOT NULL DEFAULT 'default',
                    event_type TEXT NOT NULL,
                    risk_level TEXT NOT NULL DEFAULT '',
                    flags      TEXT NOT NULL DEFAULT '[]',
                    pattern    TEXT NOT NULL DEFAULT '',
                    severity   TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_te_ip
                    ON threat_events(ip);
                CREATE INDEX IF NOT EXISTS idx_te_tenant
                    ON threat_events(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_te_ts
                    ON threat_events(ts);

                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    ip           TEXT NOT NULL,
                    tenant_id    TEXT NOT NULL DEFAULT 'default',
                    first_seen   TEXT NOT NULL,
                    last_seen    TEXT NOT NULL,
                    block_count  INTEGER NOT NULL DEFAULT 0,
                    threat_count INTEGER NOT NULL DEFAULT 0,
                    threat_types TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (ip, tenant_id)
                );

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip         TEXT NOT NULL,
                    tenant_id  TEXT NOT NULL DEFAULT 'default',
                    reason     TEXT NOT NULL DEFAULT '',
                    blocked_at TEXT NOT NULL,
                    blocked_by TEXT NOT NULL DEFAULT 'manual',
                    expires_at TEXT,
                    PRIMARY KEY (ip, tenant_id)
                );
            """)
            self._conn.commit()

    # ── Event recording ───────────────────────────────────────────────────────

    def record_block_event(
        self,
        ip:         str,
        tenant_id:  str,
        risk_level: str,
        flags:      list[str] | None = None,
    ) -> None:
        """
        Persist a BLOCK/HIGH filter decision for this IP.

        Updates attacker_profiles and may trigger auto-block when the IP
        exceeds AUTO_BLOCK_THRESHOLD events within AUTO_BLOCK_WINDOW seconds.
        """
        if not ip:
            return
        now = datetime.now(UTC).isoformat()
        flags_json = json.dumps(flags or [])
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO threat_events
                    (ts, ip, tenant_id, event_type, risk_level, flags)
                VALUES (?, ?, ?, 'block_event', ?, ?)
                """,
                (now, ip, tenant_id, risk_level, flags_json),
            )
            self._upsert_profile(ip, tenant_id, now, block_inc=1)
            self._conn.commit()

        self._maybe_auto_block(ip, tenant_id, now)
        log.debug(
            "ThreatStore: block_event ip=%s tenant=%s risk=%s",
            ip, tenant_id, risk_level,
        )

    def record_session_threat(
        self,
        ip:         str,
        tenant_id:  str,
        session_id: str,
        pattern:    str,
        severity:   str,
    ) -> None:
        """
        Persist an AgentMonitor session anomaly for this IP.
        Updates attacker_profiles.threat_count and threat_types.
        """
        if not ip:
            return
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO threat_events
                    (ts, ip, tenant_id, event_type, pattern, severity, session_id)
                VALUES (?, ?, ?, 'session_threat', ?, ?, ?)
                """,
                (now, ip, tenant_id, pattern, severity, session_id),
            )
            self._upsert_profile(ip, tenant_id, now, threat_inc=1, pattern=pattern)
            self._conn.commit()
        log.debug(
            "ThreatStore: session_threat ip=%s pattern=%s severity=%s",
            ip, pattern, severity,
        )

    # ── Profile upsert (called inside lock) ───────────────────────────────────

    def _upsert_profile(
        self,
        ip:         str,
        tenant_id:  str,
        now:        str,
        block_inc:  int = 0,
        threat_inc: int = 0,
        pattern:    str = "",
    ) -> None:
        """INSERT OR upsert attacker_profiles row.  Must be called inside _lock."""
        row = self._conn.execute(
            "SELECT block_count, threat_count, threat_types, first_seen "
            "FROM attacker_profiles WHERE ip=? AND tenant_id=?",
            (ip, tenant_id),
        ).fetchone()

        if row is None:
            types = json.dumps([pattern] if pattern else [])
            self._conn.execute(
                """
                INSERT INTO attacker_profiles
                    (ip, tenant_id, first_seen, last_seen, block_count,
                     threat_count, threat_types)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ip, tenant_id, now, now, block_inc, threat_inc, types),
            )
        else:
            existing_types: list[str] = json.loads(row[2] or "[]")
            if pattern and pattern not in existing_types:
                existing_types.append(pattern)
            self._conn.execute(
                """
                UPDATE attacker_profiles
                SET last_seen    = ?,
                    block_count  = block_count  + ?,
                    threat_count = threat_count + ?,
                    threat_types = ?
                WHERE ip=? AND tenant_id=?
                """,
                (now, block_inc, threat_inc, json.dumps(existing_types), ip, tenant_id),
            )

    # ── Auto-block ────────────────────────────────────────────────────────────

    def _maybe_auto_block(self, ip: str, tenant_id: str, now_iso: str) -> None:
        """Auto-block an IP that has exceeded the block-event rate threshold."""
        if AUTO_BLOCK_THRESHOLD <= 0:
            return
        cutoff = (
            datetime.fromisoformat(now_iso) - timedelta(seconds=AUTO_BLOCK_WINDOW)
        ).isoformat()
        count = self._conn.execute(
            """
            SELECT COUNT(*) FROM threat_events
            WHERE ip=? AND tenant_id=? AND event_type='block_event' AND ts >= ?
            """,
            (ip, tenant_id, cutoff),
        ).fetchone()[0]

        if count >= AUTO_BLOCK_THRESHOLD and not self.is_blocked(ip, tenant_id):
            expires: str | None = None
            if AUTO_BLOCK_DURATION > 0:
                expires = (
                    datetime.fromisoformat(now_iso)
                    + timedelta(seconds=AUTO_BLOCK_DURATION)
                ).isoformat()
            self.block_ip(
                ip        = ip,
                tenant_id = tenant_id,
                reason    = (
                    f"Auto-blocked: {count} block events in "
                    f"{AUTO_BLOCK_WINDOW}s window"
                ),
                blocked_by = "auto",
                expires_at = expires,
            )
            log.info(
                "ThreatStore: auto-blocked ip=%s tenant=%s (count=%d)",
                ip, tenant_id, count,
            )

    # ── IP blocklist ──────────────────────────────────────────────────────────

    def block_ip(
        self,
        ip:         str,
        tenant_id:  str = "default",
        reason:     str = "",
        blocked_by: str = "manual",
        expires_at: str | None = None,
    ) -> None:
        """
        Add or replace an IP in the blocklist.  Upsert-safe.
        """
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO blocked_ips
                    (ip, tenant_id, reason, blocked_at, blocked_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, tenant_id) DO UPDATE SET
                    reason     = excluded.reason,
                    blocked_at = excluded.blocked_at,
                    blocked_by = excluded.blocked_by,
                    expires_at = excluded.expires_at
                """,
                (ip, tenant_id, reason, now, blocked_by, expires_at),
            )
            self._conn.commit()
        log.info(
            "ThreatStore: ip=%s tenant=%s blocked (by=%s reason=%r)",
            ip, tenant_id, blocked_by, reason,
        )

    def unblock_ip(self, ip: str, tenant_id: str = "default") -> bool:
        """
        Remove an IP from the blocklist.
        Returns True if the IP was found and removed, False if it was not blocked.
        """
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM blocked_ips WHERE ip=? AND tenant_id=?",
                (ip, tenant_id),
            )
            self._conn.commit()
        found = cur.rowcount > 0
        if found:
            log.info("ThreatStore: ip=%s tenant=%s unblocked", ip, tenant_id)
        return found

    def is_blocked(self, ip: str, tenant_id: str = "default") -> bool:
        """
        Fast check: is this IP currently in the blocklist?
        Respects expires_at — expired entries are treated as unblocked and
        pruned lazily on the next check.
        """
        if not ip:
            return False
        now = datetime.now(UTC).isoformat()
        row = self._conn.execute(
            "SELECT expires_at FROM blocked_ips WHERE ip=? AND tenant_id=?",
            (ip, tenant_id),
        ).fetchone()
        if row is None:
            return False
        expires_at = row[0]
        if expires_at is not None and expires_at < now:
            # Lazy expiry — prune stale record
            with self._lock:
                self._conn.execute(
                    "DELETE FROM blocked_ips WHERE ip=? AND tenant_id=? AND expires_at < ?",
                    (ip, tenant_id, now),
                )
                self._conn.commit()
            return False
        return True

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_profiles(
        self,
        tenant_id: str | None = None,
        limit:     int        = 50,
    ) -> list[dict]:
        """
        Return attacker profiles sorted by most recent activity.
        Optionally filtered to a single tenant.
        """
        if tenant_id:
            rows = self._conn.execute(
                """
                SELECT ip, tenant_id, first_seen, last_seen,
                       block_count, threat_count, threat_types
                FROM attacker_profiles
                WHERE tenant_id=?
                ORDER BY last_seen DESC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT ip, tenant_id, first_seen, last_seen,
                       block_count, threat_count, threat_types
                FROM attacker_profiles
                ORDER BY last_seen DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "ip":           row[0],
                "tenant_id":    row[1],
                "first_seen":   row[2],
                "last_seen":    row[3],
                "block_count":  row[4],
                "threat_count": row[5],
                "threat_types": json.loads(row[6] or "[]"),
            }
            for row in rows
        ]

    def get_blocked_ips(
        self,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Return all currently-blocked IPs (expired entries excluded)."""
        now = datetime.now(UTC).isoformat()
        if tenant_id:
            rows = self._conn.execute(
                """
                SELECT ip, tenant_id, reason, blocked_at, blocked_by, expires_at
                FROM blocked_ips
                WHERE tenant_id=?
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY blocked_at DESC
                """,
                (tenant_id, now),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT ip, tenant_id, reason, blocked_at, blocked_by, expires_at
                FROM blocked_ips
                WHERE expires_at IS NULL OR expires_at > ?
                ORDER BY blocked_at DESC
                """,
                (now,),
            ).fetchall()
        return [
            {
                "ip":         row[0],
                "tenant_id":  row[1],
                "reason":     row[2],
                "blocked_at": row[3],
                "blocked_by": row[4],
                "expires_at": row[5],
            }
            for row in rows
        ]

    def get_recent_events(
        self,
        ip:        str | None = None,
        tenant_id: str | None = None,
        limit:     int        = 100,
    ) -> list[dict]:
        """Return recent threat events, optionally filtered by IP and/or tenant."""
        clauses: list[str] = []
        params:  list      = []
        if ip:
            clauses.append("ip=?")
            params.append(ip)
        if tenant_id:
            clauses.append("tenant_id=?")
            params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"""
            SELECT ts, ip, tenant_id, event_type, risk_level,
                   flags, pattern, severity, session_id
            FROM threat_events
            {where}
            ORDER BY ts DESC LIMIT ?
            """,
            params,
        ).fetchall()
        return [
            {
                "ts":         row[0],
                "ip":         row[1],
                "tenant_id":  row[2],
                "event_type": row[3],
                "risk_level": row[4],
                "flags":      json.loads(row[5] or "[]"),
                "pattern":    row[6],
                "severity":   row[7],
                "session_id": row[8],
            }
            for row in rows
        ]

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()
