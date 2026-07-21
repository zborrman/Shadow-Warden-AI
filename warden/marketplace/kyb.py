"""
warden/marketplace/kyb.py
─────────────────────────
Know Your Business (KYB) — verification of the legal entity that owns a
marketplace agent, sitting *behind* KYA (Know Your Agent).

KYA (kya.py) screens the agent's own behavior (ERS-based risk heuristic).
KYB is one level up: does the tenant/business that owns the agent's DID
check out? An agent's owner starts unverified (PENDING) and stays that way
until manually reviewed — v1 has no external provider wired in, only a
manual-review queue an operator drives through approve_kyb()/reject_kyb().

Pluggable provider interface (`KYBProvider`) exists so a Persona/Sumsub
adapter can be dropped in later without touching call sites; only
`ManualReviewProvider` is implemented for v1 — it always defers to a human
(returns PENDING, never auto-decides).

Enforcement is opt-in: `warden.marketplace.autonomy.check_action()` only
consults KYB status when `KYB_ENFORCEMENT_ENABLED=true` (default false) —
existing tenants are not retroactively capped the moment this module ships.

Env vars
────────
  KYB_ENFORCEMENT_ENABLED  true/false (default false) — gate autonomy.check_action()
                            on the agent owner's KYB status
  MARKETPLACE_DB_PATH      SQLite path (shared with kya.py/autonomy.py)
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Protocol

from warden.config import data_path
from warden.db.sqlite_pragmas import init_pragmas

log = logging.getLogger("warden.marketplace.kyb")

_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock = threading.RLock()

_VALID_STATUSES = frozenset({"PENDING", "VERIFIED", "FLAGGED", "REJECTED"})


def enforcement_enabled() -> bool:
    """True when autonomy.check_action() should cap unverified owners at L1."""
    return os.getenv("KYB_ENFORCEMENT_ENABLED", "false").lower() == "true"


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class KYBRecord:
    tenant_id:     str
    kyb_status:    str          # PENDING | VERIFIED | FLAGGED | REJECTED
    business_name: str = ""
    provider:      str = "manual"
    submitted_at:  str = ""
    reviewed_at:   str = ""
    reviewer:      str = ""
    notes:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Provider interface (v1: manual review only) ──────────────────────────────

class KYBProvider(Protocol):
    """Pluggable owner-verification backend. v2: Persona/Sumsub adapters."""

    def verify(self, tenant_id: str, business_name: str) -> str:
        """Return a kyb_status. May defer (PENDING) for out-of-band review."""
        ...


class ManualReviewProvider:
    """v1 default: never auto-decides — every submission waits for a human."""

    def verify(self, tenant_id: str, business_name: str) -> str:
        return "PENDING"


# ── Schema ────────────────────────────────────────────────────────────────────

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_kyb_records (
            tenant_id     TEXT PRIMARY KEY,
            kyb_status    TEXT NOT NULL DEFAULT 'PENDING',
            business_name TEXT NOT NULL DEFAULT '',
            provider      TEXT NOT NULL DEFAULT 'manual',
            submitted_at  TEXT NOT NULL DEFAULT '',
            reviewed_at   TEXT NOT NULL DEFAULT '',
            reviewer      TEXT NOT NULL DEFAULT '',
            notes         TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_kyb_status ON marketplace_kyb_records(kyb_status);
    """)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    init_pragmas(con)
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _row_to_record(row: sqlite3.Row) -> KYBRecord:
    import json
    try:
        notes = json.loads(row["notes"] or "[]")
    except Exception:
        notes = []
    return KYBRecord(
        tenant_id=row["tenant_id"], kyb_status=row["kyb_status"],
        business_name=row["business_name"], provider=row["provider"],
        submitted_at=row["submitted_at"], reviewed_at=row["reviewed_at"],
        reviewer=row["reviewer"], notes=notes,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def submit_for_review(
    tenant_id: str, business_name: str = "", provider: KYBProvider | None = None,
) -> KYBRecord:
    """Create/reset a tenant's KYB record to PENDING and run the provider once.

    v1's only provider (ManualReviewProvider) always defers to PENDING —
    this call queues the tenant for a human reviewer, it never auto-verifies.
    Idempotent: re-submitting an already-PENDING tenant just refreshes the
    timestamp/business_name.
    """
    active_provider = provider or ManualReviewProvider()
    now = _now()
    status = active_provider.verify(tenant_id, business_name)
    if status not in _VALID_STATUSES:
        status = "PENDING"

    with _db_lock, _conn() as con:
        con.execute(
            """INSERT INTO marketplace_kyb_records
               (tenant_id, kyb_status, business_name, provider, submitted_at, notes)
               VALUES (?,?,?,?,?,'[]')
               ON CONFLICT(tenant_id) DO UPDATE SET
                 kyb_status=excluded.kyb_status,
                 business_name=excluded.business_name,
                 submitted_at=excluded.submitted_at""",
            (tenant_id, status, business_name, "manual", now),
        )
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    log.info("kyb: submitted tenant=%s status=%s", tenant_id[:32], status)
    return _row_to_record(row)


def get_kyb_status(tenant_id: str) -> str:
    """Return kyb_status for *tenant_id*. Unknown/missing tenant → 'PENDING'.

    Fail-safe default: any read error also returns 'PENDING' — an unverified
    tenant is the conservative assumption, never 'VERIFIED'.
    """
    if not tenant_id:
        return "PENDING"
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT kyb_status FROM marketplace_kyb_records WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        return row["kyb_status"] if row else "PENDING"
    except Exception as exc:
        log.debug("kyb: get_kyb_status error for tenant=%s: %s", tenant_id[:32], exc)
        return "PENDING"


def get_kyb_record(tenant_id: str) -> KYBRecord | None:
    """Return the full KYBRecord, or None if the tenant was never submitted."""
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT * FROM marketplace_kyb_records WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        return _row_to_record(row) if row else None
    except Exception as exc:
        log.warning("kyb: get_kyb_record error for tenant=%s: %s", tenant_id[:32], exc)
        return None


def approve_kyb(tenant_id: str, reviewer: str, notes: str = "") -> KYBRecord:
    """Set kyb_status → VERIFIED. Raises if the tenant has no record to review."""
    return _resolve(tenant_id, "VERIFIED", reviewer, notes)


def reject_kyb(tenant_id: str, reviewer: str, reason: str) -> KYBRecord:
    """Set kyb_status → REJECTED. Raises if the tenant has no record to review."""
    return _resolve(tenant_id, "REJECTED", reviewer, reason)


def flag_kyb(tenant_id: str, reviewer: str, reason: str) -> KYBRecord:
    """Set kyb_status → FLAGGED (needs a second look, not an outright reject)."""
    return _resolve(tenant_id, "FLAGGED", reviewer, reason)


def _resolve(tenant_id: str, status: str, reviewer: str, note: str) -> KYBRecord:
    import json
    now = _now()
    with _db_lock, _conn() as con:
        existing = con.execute(
            "SELECT notes FROM marketplace_kyb_records WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if existing is None:
            raise ValueError(f"no KYB submission on file for tenant={tenant_id!r}")
        try:
            notes = json.loads(existing["notes"] or "[]")
        except Exception:
            notes = []
        if note:
            notes.append(f"{status}:{note}")
        con.execute(
            """UPDATE marketplace_kyb_records
               SET kyb_status=?, reviewed_at=?, reviewer=?, notes=?
               WHERE tenant_id=?""",
            (status, now, reviewer, json.dumps(notes), tenant_id),
        )
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    log.info("kyb: %s tenant=%s reviewer=%s", status, tenant_id[:32], reviewer)
    return _row_to_record(row)
