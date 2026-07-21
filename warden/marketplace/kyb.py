"""
warden/marketplace/kyb.py
─────────────────────────
Know Your Business (KYB) — behind KYA (FT-5).

KYA (`marketplace/kya.py`) screens individual *agents*; KYB screens the
*owning tenant* behind a flagged agent. KYB is never triggered on its own —
`require_kyb()` is called from `kya.screen_agent()` when an agent comes back
FLAGGED, so a business only ever enters this flow because its own agent's
risk screening warranted it (hence "KYB behind KYA").

Draft-only pattern (mirrors refund intents / SAR drafts elsewhere in the
codebase): a tenant can SUBMIT its business identity, but only an explicit
`verify_kyb()` compliance-officer call can move it to VERIFIED or REJECTED.
The system never self-verifies.

Status lifecycle:
    (none) → REQUIRED → SUBMITTED → VERIFIED | REJECTED
                                 ↖________________/
                                  (resubmission after rejection)

`kyb_blocks_participation()` is a pure read — any status other than VERIFIED
or NOT_REQUIRED blocks. Nothing calls it yet in this slice (wiring an actual
enforcement gate into clearing/listing is deliberately deferred, the same way
FT-4's outbox shipped before its retention/reconciliation follow-ons).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.marketplace.kyb")

_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock = threading.RLock()

_BLOCKING_STATUSES = frozenset({"REQUIRED", "SUBMITTED", "REJECTED"})

_KYB_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_kyb_records (
        owner_tenant_id     TEXT PRIMARY KEY,
        kyb_status          TEXT NOT NULL DEFAULT 'REQUIRED',
        triggered_by        TEXT NOT NULL DEFAULT '',
        business_name       TEXT NOT NULL DEFAULT '',
        jurisdiction        TEXT NOT NULL DEFAULT '',
        registration_number TEXT NOT NULL DEFAULT '',
        requested_at        TEXT NOT NULL,
        submitted_at        TEXT NOT NULL DEFAULT '',
        verified_at         TEXT NOT NULL DEFAULT '',
        reviewed_by         TEXT NOT NULL DEFAULT '',
        flags               TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS idx_kyb_status ON marketplace_kyb_records(kyb_status);
"""
register("marketplace", "warden.marketplace.kyb", _KYB_DDL)


@dataclass
class KYBRecord:
    owner_tenant_id:     str
    kyb_status:          str    # REQUIRED | SUBMITTED | VERIFIED | REJECTED
    triggered_by:        str
    business_name:       str = ""
    jurisdiction:        str = ""
    registration_number: str = ""
    requested_at:        str = ""
    submitted_at:        str = ""
    verified_at:         str = ""
    reviewed_by:         str = ""
    flags:               list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with open_db("marketplace", _DB_PATH, module_default_path=_DB_PATH) as con:
        yield con


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _row_to_record(row: sqlite3.Row) -> KYBRecord:
    try:
        flags = json.loads(row["flags"] or "[]")
    except Exception:
        flags = []
    return KYBRecord(
        owner_tenant_id=row["owner_tenant_id"],
        kyb_status=row["kyb_status"],
        triggered_by=row["triggered_by"],
        business_name=row["business_name"],
        jurisdiction=row["jurisdiction"],
        registration_number=row["registration_number"],
        requested_at=row["requested_at"],
        submitted_at=row["submitted_at"],
        verified_at=row["verified_at"],
        reviewed_by=row["reviewed_by"],
        flags=flags,
    )


def require_kyb(owner_tenant_id: str, reason: str) -> KYBRecord:
    """Flag *owner_tenant_id* as needing KYB. Idempotent: an existing record
    (at any status) is returned unchanged — this never downgrades a tenant
    that already submitted, was verified, or was rejected back to REQUIRED.
    """
    with _db_lock, _conn() as con:
        existing = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?", (owner_tenant_id,)
        ).fetchone()
        if existing:
            return _row_to_record(existing)

        now = _now()
        con.execute(
            """INSERT INTO marketplace_kyb_records
               (owner_tenant_id, kyb_status, triggered_by, requested_at, flags)
               VALUES (?, 'REQUIRED', ?, ?, ?)""",
            (owner_tenant_id, reason, now, json.dumps([reason])),
        )
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?", (owner_tenant_id,)
        ).fetchone()
    log.info("kyb: required for tenant=%s reason=%s", owner_tenant_id, reason)
    return _row_to_record(row)


def submit_kyb(
    owner_tenant_id: str, business_name: str, jurisdiction: str = "", registration_number: str = ""
) -> KYBRecord:
    """Tenant submits its business identity for review.

    Allowed from REQUIRED or REJECTED (resubmission after a rejection).
    A no-op returning the existing record if already SUBMITTED or VERIFIED —
    submission never regresses a record already past this stage.
    """
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?", (owner_tenant_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"no KYB requirement on file for tenant {owner_tenant_id!r}")
        record = _row_to_record(row)
        if record.kyb_status in ("SUBMITTED", "VERIFIED"):
            return record

        now = _now()
        con.execute(
            """UPDATE marketplace_kyb_records
               SET kyb_status='SUBMITTED', business_name=?, jurisdiction=?,
                   registration_number=?, submitted_at=?
               WHERE owner_tenant_id=?""",
            (business_name, jurisdiction, registration_number, now, owner_tenant_id),
        )
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?", (owner_tenant_id,)
        ).fetchone()
    log.info("kyb: submitted for tenant=%s business_name=%s", owner_tenant_id, business_name)
    return _row_to_record(row)


def verify_kyb(owner_tenant_id: str, reviewed_by: str, approved: bool) -> KYBRecord:
    """Compliance-officer decision — the only path to VERIFIED or REJECTED.

    Requires a prior SUBMITTED record; the system never self-verifies.
    """
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?", (owner_tenant_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"no KYB requirement on file for tenant {owner_tenant_id!r}")
        record = _row_to_record(row)
        if record.kyb_status != "SUBMITTED":
            raise ValueError(
                f"tenant {owner_tenant_id!r} KYB status is {record.kyb_status!r}, not SUBMITTED"
            )

        now = _now()
        new_status = "VERIFIED" if approved else "REJECTED"
        con.execute(
            """UPDATE marketplace_kyb_records
               SET kyb_status=?, verified_at=?, reviewed_by=?
               WHERE owner_tenant_id=?""",
            (new_status, now, reviewed_by, owner_tenant_id),
        )
        row = con.execute(
            "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?", (owner_tenant_id,)
        ).fetchone()
    log.info("kyb: %s for tenant=%s by=%s", new_status.lower(), owner_tenant_id, reviewed_by)
    return _row_to_record(row)


def get_kyb_status(owner_tenant_id: str) -> str:
    """Return kyb_status, or 'NOT_REQUIRED' if KYB was never triggered."""
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT kyb_status FROM marketplace_kyb_records WHERE owner_tenant_id=?",
                (owner_tenant_id,),
            ).fetchone()
        return row["kyb_status"] if row else "NOT_REQUIRED"
    except Exception as exc:
        log.warning("kyb: get_kyb_status error: %s", exc)
        return "NOT_REQUIRED"


def get_kyb_record(owner_tenant_id: str) -> KYBRecord | None:
    """Return the full KYBRecord, or None if KYB was never triggered."""
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT * FROM marketplace_kyb_records WHERE owner_tenant_id=?",
                (owner_tenant_id,),
            ).fetchone()
        return _row_to_record(row) if row else None
    except Exception as exc:
        log.warning("kyb: get_kyb_record error: %s", exc)
        return None


def kyb_blocks_participation(owner_tenant_id: str) -> bool:
    """True if this tenant's KYB status should block further marketplace
    participation (REQUIRED, SUBMITTED-pending-review, or REJECTED).
    NOT_REQUIRED and VERIFIED do not block. Not yet wired into any
    enforcement path — see module docstring.
    """
    return get_kyb_status(owner_tenant_id) in _BLOCKING_STATUSES
