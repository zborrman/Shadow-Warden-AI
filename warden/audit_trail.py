"""
warden/audit_trail.py
━━━━━━━━━━━━━━━━━━━━━
Cryptographic tamper-evident audit trail for SOC 2 Type II evidence.

Design
──────
Every filter decision is appended to a SQLite table as one row.  Each row's
``entry_hash`` is SHA-256(prev_entry_hash + canonical_JSON_payload).  The
first row chains off ``_GENESIS_HASH`` ("0" * 64).

Verifying the chain walks every row in insertion order, recomputes each hash,
and returns (is_valid, entry_count).  Any edit, deletion, or reordering of
rows breaks the chain and is immediately detected.

SOC 2 controls addressed
────────────────────────
  CC6.1  Logical access     — every decision records tenant_id + request_id
  CC6.7  Data protection    — GDPR-safe: risk_level / action / reason / flags
                              only; content is NEVER stored
  CC7.2  Security monitoring — tamper-evident record of every threat event

REST endpoints (mounted by main.py on the admin router)
────────────────────────────────────────────────────────
  GET /admin/audit/verify
      → {"valid": true, "entries": N}

  GET /admin/audit/export?start=<ISO>&end=<ISO>&limit=<int>
      → {"entries": [...], "count": N, "valid": true}

Thread-safe: all writes serialised through a threading.Lock.
Database runs in WAL mode for concurrent reads without blocking writes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("warden.audit_trail")

AUDIT_DB_PATH  = Path(os.getenv("AUDIT_TRAIL_PATH", "/warden/data/audit_trail.db"))
_GENESIS_HASH  = "0" * 64   # sentinel prev_hash for the very first entry
_ENABLED       = os.getenv("AUDIT_TRAIL_ENABLED", "true").lower() != "false"


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    seq:           int
    recorded_at:   str
    request_id:    str
    tenant_id:     str
    risk_level:    str
    action:        str           # "allowed" | "blocked" | "honey"
    reason:        str
    flags:         list[str]
    processing_ms: float
    prev_hash:     str
    entry_hash:    str


# ── AuditTrail ────────────────────────────────────────────────────────────────

class AuditTrail:
    """
    Cryptographic hash-chain audit log.

    Instantiate once during lifespan startup::

        _audit = AuditTrail()

    Append after every filter decision::

        _audit.record(
            request_id    = rid,
            tenant_id     = tenant_id,
            risk_level    = risk_level,
            action        = "blocked" if not allowed else "allowed",
            reason        = reason,
            flags         = [f.flag.value for f in guard_result.flags],
            processing_ms = timings.get("total", 0.0),
        )

    Verify integrity::

        valid, count = _audit.verify_chain()

    Export for auditors::

        entries = _audit.export_range(start="2026-01-01", end="2026-03-31")
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path    = db_path or AUDIT_DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock    = threading.Lock()
        self._conn    = self._open()
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
                CREATE TABLE IF NOT EXISTS audit_chain (
                    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at    TEXT    NOT NULL,
                    request_id     TEXT    NOT NULL,
                    tenant_id      TEXT    NOT NULL,
                    risk_level     TEXT    NOT NULL,
                    action         TEXT    NOT NULL,
                    reason         TEXT    NOT NULL DEFAULT '',
                    flags          TEXT    NOT NULL DEFAULT '[]',
                    processing_ms  REAL    NOT NULL DEFAULT 0.0,
                    prev_hash      TEXT    NOT NULL,
                    entry_hash     TEXT    NOT NULL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_tenant    ON audit_chain(tenant_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_recorded  ON audit_chain(recorded_at)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_chain(action)"
            )
            self._conn.commit()

    @staticmethod
    def _compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
        canonical = prev_hash + json.dumps(payload, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ── Write ─────────────────────────────────────────────────────────────────

    def record(
        self,
        *,
        request_id:    str,
        tenant_id:     str,
        risk_level:    str,
        action:        str,
        reason:        str            = "",
        flags:         list[str] | None = None,
        processing_ms: float          = 0.0,
    ) -> str:
        """
        Append one filter decision to the audit chain.

        Returns the ``entry_hash`` of the recorded row so callers can log it.
        When ``AUDIT_TRAIL_ENABLED=false`` returns an empty string immediately.
        Thread-safe; never raises (fail-open).
        """
        if not _ENABLED:
            return ""

        try:
            recorded_at = datetime.now(UTC).isoformat()
            flags_list  = flags or []

            payload: dict[str, Any] = {
                "recorded_at":   recorded_at,
                "request_id":    request_id,
                "tenant_id":     tenant_id,
                "risk_level":    risk_level,
                "action":        action,
                "reason":        reason,
                "flags":         flags_list,
                "processing_ms": processing_ms,
            }

            with self._lock:
                cur = self._conn.execute(
                    "SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
                )
                row      = cur.fetchone()
                prev_hash = row[0] if row else _GENESIS_HASH

                entry_hash = self._compute_hash(prev_hash, payload)

                self._conn.execute(
                    """
                    INSERT INTO audit_chain
                        (recorded_at, request_id, tenant_id, risk_level, action,
                         reason, flags, processing_ms, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        recorded_at, request_id, tenant_id, risk_level, action,
                        reason, json.dumps(flags_list), processing_ms,
                        prev_hash, entry_hash,
                    ),
                )
                self._conn.commit()

            return entry_hash

        except Exception as exc:
            log.debug("AuditTrail.record: fail-open — %s", exc)
            return ""

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_chain(self) -> tuple[bool, int]:
        """
        Walk every entry in insertion order and recompute each hash.

        Returns ``(is_valid, entry_count)``.
        An empty chain is valid by definition: ``(True, 0)``.
        Complexity: O(N) — full table scan.
        """
        try:
            cur = self._conn.execute(
                "SELECT seq, recorded_at, request_id, tenant_id, risk_level, action, "
                "reason, flags, processing_ms, prev_hash, entry_hash "
                "FROM audit_chain ORDER BY seq ASC"
            )
            rows = cur.fetchall()
        except Exception as exc:
            log.error("AuditTrail.verify_chain: DB error — %s", exc)
            return False, 0

        if not rows:
            return True, 0

        expected_prev = _GENESIS_HASH
        for row in rows:
            (seq, recorded_at, request_id, tenant_id, risk_level, action,
             reason, flags_raw, processing_ms, stored_prev, stored_hash) = row

            if stored_prev != expected_prev:
                log.error(
                    "AuditTrail: chain break at seq=%d "
                    "(expected prev=%.16s… stored=%.16s…)",
                    seq, expected_prev, stored_prev,
                )
                return False, seq

            try:
                flags = json.loads(flags_raw) if flags_raw else []
            except json.JSONDecodeError:
                flags = []

            payload: dict[str, Any] = {
                "recorded_at":   recorded_at,
                "request_id":    request_id,
                "tenant_id":     tenant_id,
                "risk_level":    risk_level,
                "action":        action,
                "reason":        reason,
                "flags":         flags,
                "processing_ms": processing_ms,
            }
            computed = self._compute_hash(stored_prev, payload)
            if computed != stored_hash:
                log.error(
                    "AuditTrail: tampered entry seq=%d "
                    "(stored=%.16s… computed=%.16s…)",
                    seq, stored_hash, computed,
                )
                return False, seq

            expected_prev = stored_hash

        return True, len(rows)

    # ── Export ────────────────────────────────────────────────────────────────

    def export_range(
        self,
        start: str | None = None,
        end:   str | None = None,
        limit: int        = 10_000,
    ) -> list[dict[str, Any]]:
        """
        Return audit entries (insertion order) optionally filtered by ISO-8601
        UTC ``recorded_at`` range.  Both *start* and *end* are inclusive.
        """
        _cols = (
            "seq, recorded_at, request_id, tenant_id, risk_level, "
            "action, reason, flags, processing_ms, prev_hash, entry_hash"
        )
        args: list[Any] = []
        where_parts: list[str] = []
        if start:
            where_parts.append("recorded_at >= ?")
            args.append(start)
        if end:
            where_parts.append("recorded_at <= ?")
            args.append(end)

        where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
        args.append(limit)

        try:
            cur = self._conn.execute(
                f"SELECT {_cols} FROM audit_chain {where} ORDER BY seq ASC LIMIT ?",
                args,
            )
        except Exception as exc:
            log.error("AuditTrail.export_range: DB error — %s", exc)
            return []

        col_names = [
            "seq", "recorded_at", "request_id", "tenant_id", "risk_level",
            "action", "reason", "flags", "processing_ms", "prev_hash", "entry_hash",
        ]
        results = []
        for row in cur.fetchall():
            d = dict(zip(col_names, row, strict=False))
            try:
                d["flags"] = json.loads(d["flags"]) if d["flags"] else []
            except json.JSONDecodeError:
                d["flags"] = []
            results.append(d)
        return results

    # ── Utility ───────────────────────────────────────────────────────────────

    def count(self) -> int:
        """Total number of audit entries in the chain."""
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM audit_chain")
            row = cur.fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()
