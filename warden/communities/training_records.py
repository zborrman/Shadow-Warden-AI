"""
warden/communities/training_records.py  (CM-38)
─────────────────────────────────────────────────
Employee AI Training Records — track training program completions with
HMAC-SHA256 signed attestations and behavioral.py integration.

Each completion fires `behavioral.record_event(community_id, "ai_training_completed", score)`,
enabling anomaly detection over training patterns (e.g. suspiciously perfect scores).

Tiers: Community Business+ (training_records_enabled)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Generator

log = logging.getLogger("warden.communities.training_records")

_DB_PATH  = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_HMAC_KEY = os.getenv("VAULT_MASTER_KEY", "training-default-key")
_db_lock  = threading.RLock()


@dataclass
class TrainingProgram:
    program_id:    str
    community_id:  str
    title:         str
    description:   str
    required_for:  list
    passing_score: float
    valid_days:    int
    created_at:    str

    def to_dict(self) -> dict:
        return {
            "program_id":    self.program_id,
            "community_id":  self.community_id,
            "title":         self.title,
            "description":   self.description,
            "required_for":  self.required_for,
            "passing_score": self.passing_score,
            "valid_days":    self.valid_days,
            "created_at":    self.created_at,
        }


@dataclass
class TrainingCompletion:
    completion_id: str
    program_id:    str
    community_id:  str
    employee_id:   str
    score:         float
    passed:        bool
    completed_at:  str
    expires_at:    str
    attestation:   str

    def to_dict(self) -> dict:
        return {
            "completion_id": self.completion_id,
            "program_id":    self.program_id,
            "community_id":  self.community_id,
            "employee_id":   self.employee_id,
            "score":         self.score,
            "passed":        self.passed,
            "completed_at":  self.completed_at,
            "expires_at":    self.expires_at,
            "attestation":   self.attestation,
        }


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS ai_training_programs (
            program_id    TEXT PRIMARY KEY,
            community_id  TEXT NOT NULL,
            title         TEXT NOT NULL,
            description   TEXT NOT NULL DEFAULT '',
            required_for  TEXT NOT NULL DEFAULT '[]',
            passing_score REAL NOT NULL DEFAULT 0.8,
            valid_days    INTEGER NOT NULL DEFAULT 365,
            created_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_atp_community ON ai_training_programs(community_id);

        CREATE TABLE IF NOT EXISTS ai_training_completions (
            completion_id TEXT PRIMARY KEY,
            program_id    TEXT NOT NULL,
            community_id  TEXT NOT NULL,
            employee_id   TEXT NOT NULL,
            score         REAL NOT NULL DEFAULT 1.0,
            passed        INTEGER NOT NULL DEFAULT 1,
            completed_at  TEXT NOT NULL,
            expires_at    TEXT NOT NULL,
            attestation   TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_atc_employee ON ai_training_completions(community_id, employee_id);
        CREATE INDEX IF NOT EXISTS idx_atc_program  ON ai_training_completions(program_id);
        CREATE INDEX IF NOT EXISTS idx_atc_expires  ON ai_training_completions(expires_at);
    """)
    con.commit()


def _sign_completion(completion_id: str, program_id: str, employee_id: str, score: float, ts: str) -> str:
    """HMAC-SHA256 attestation over completion fields."""
    payload = f"{completion_id}|{program_id}|{employee_id}|{score:.4f}|{ts}"
    key     = _HMAC_KEY.encode() if isinstance(_HMAC_KEY, str) else _HMAC_KEY
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def verify_attestation(completion: dict) -> bool:
    """Re-derive HMAC and compare. Returns True if untampered."""
    expected = _sign_completion(
        completion["completion_id"],
        completion["program_id"],
        completion["employee_id"],
        float(completion["score"]),
        completion["completed_at"],
    )
    return hmac.compare_digest(expected, completion.get("attestation", ""))


# ── Program management ────────────────────────────────────────────────────────

def create_program(
    community_id: str,
    title: str,
    description: str = "",
    required_for: list | None = None,
    passing_score: float = 0.8,
    valid_days: int = 365,
    db_path: str = _DB_PATH,
) -> TrainingProgram:
    now           = datetime.now(UTC).isoformat()
    program_id    = str(uuid.uuid4())
    roles         = required_for or []
    passing_score = max(0.0, min(1.0, passing_score))

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO ai_training_programs
               (program_id, community_id, title, description, required_for, passing_score, valid_days, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (program_id, community_id, title, description, json.dumps(roles),
             max(0.0, min(1.0, passing_score)), max(1, valid_days), now),
        )

    log.info("training_records: program %s created community=%s", program_id, community_id)
    return TrainingProgram(
        program_id=program_id, community_id=community_id, title=title,
        description=description, required_for=roles,
        passing_score=passing_score, valid_days=valid_days, created_at=now,
    )


def get_program(program_id: str, db_path: str = _DB_PATH) -> TrainingProgram | None:
    with _conn(db_path) as con:
        row = con.execute("SELECT * FROM ai_training_programs WHERE program_id = ?", (program_id,)).fetchone()
    if not row:
        return None
    return TrainingProgram(
        program_id=row["program_id"], community_id=row["community_id"],
        title=row["title"], description=row["description"],
        required_for=json.loads(row["required_for"] or "[]"),
        passing_score=row["passing_score"], valid_days=row["valid_days"],
        created_at=row["created_at"],
    )


def list_programs(community_id: str, db_path: str = _DB_PATH) -> list[TrainingProgram]:
    with _conn(db_path) as con:
        rows = con.execute(
            "SELECT * FROM ai_training_programs WHERE community_id = ? ORDER BY created_at DESC",
            (community_id,),
        ).fetchall()
    return [TrainingProgram(
        program_id=r["program_id"], community_id=r["community_id"],
        title=r["title"], description=r["description"],
        required_for=json.loads(r["required_for"] or "[]"),
        passing_score=r["passing_score"], valid_days=r["valid_days"],
        created_at=r["created_at"],
    ) for r in rows]


# ── Completion recording ──────────────────────────────────────────────────────

def record_completion(
    program_id: str,
    community_id: str,
    employee_id: str,
    score: float,
    db_path: str = _DB_PATH,
) -> TrainingCompletion:
    prog = get_program(program_id, db_path=db_path)
    if not prog:
        raise ValueError(f"Training program {program_id!r} not found")

    score         = max(0.0, min(1.0, score))
    passed        = score >= prog.passing_score
    now           = datetime.now(UTC).isoformat()
    expires_at    = (datetime.now(UTC) + timedelta(days=prog.valid_days)).isoformat()
    completion_id = str(uuid.uuid4())
    attestation   = _sign_completion(completion_id, program_id, employee_id, score, now)

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO ai_training_completions
               (completion_id, program_id, community_id, employee_id, score, passed,
                completed_at, expires_at, attestation)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (completion_id, program_id, community_id, employee_id, score,
             1 if passed else 0, now, expires_at, attestation),
        )

    # Behavioral integration
    _fire_behavioral_event(community_id, score, passed, db_path)

    log.info("training_records: completion %s employee=%s passed=%s", completion_id, employee_id, passed)
    return TrainingCompletion(
        completion_id=completion_id, program_id=program_id,
        community_id=community_id, employee_id=employee_id,
        score=score, passed=passed,
        completed_at=now, expires_at=expires_at, attestation=attestation,
    )


def _fire_behavioral_event(community_id: str, score: float, passed: bool, db_path: str) -> None:
    try:
        from warden.communities.behavioral import record_event  # noqa: PLC0415
        record_event(community_id, "ai_training_completed", value=score)
    except Exception as exc:
        log.debug("training_records: behavioral event skipped — %s", exc)


# ── Employee status ───────────────────────────────────────────────────────────

def get_employee_status(
    community_id: str,
    employee_id: str,
    db_path: str = _DB_PATH,
) -> dict:
    """Return compliance status for an employee across all community programs."""
    programs = list_programs(community_id, db_path=db_path)
    now      = datetime.now(UTC).isoformat()
    results  = []

    with _conn(db_path) as con:
        for prog in programs:
            row = con.execute(
                """SELECT * FROM ai_training_completions
                   WHERE program_id = ? AND employee_id = ? AND passed = 1
                   ORDER BY completed_at DESC LIMIT 1""",
                (prog.program_id, employee_id),
            ).fetchone()
            if row:
                expired = row["expires_at"] < now
                status  = "expired" if expired else "compliant"
            else:
                status = "not_completed"
                row    = None

            results.append({
                "program_id":   prog.program_id,
                "title":        prog.title,
                "status":       status,
                "completed_at": row["completed_at"] if row else None,
                "expires_at":   row["expires_at"] if row else None,
                "score":        row["score"] if row else None,
            })

    overall = "compliant" if results and all(r["status"] == "compliant" for r in results) else "non_compliant"
    return {
        "employee_id":    employee_id,
        "community_id":   community_id,
        "overall_status": overall,
        "programs":       results,
    }


def get_compliance_report(community_id: str, db_path: str = _DB_PATH) -> dict:
    """Community-wide training compliance report."""
    now = datetime.now(UTC).isoformat()
    with _conn(db_path) as con:
        total_completions = con.execute(
            "SELECT COUNT(*) FROM ai_training_completions WHERE community_id = ?",
            (community_id,),
        ).fetchone()[0]
        passed_count = con.execute(
            "SELECT COUNT(*) FROM ai_training_completions WHERE community_id = ? AND passed = 1",
            (community_id,),
        ).fetchone()[0]
        expiring_soon = con.execute(
            """SELECT COUNT(*) FROM ai_training_completions
               WHERE community_id = ? AND passed = 1
                 AND expires_at <= ?""",
            (community_id, (datetime.now(UTC) + timedelta(days=30)).isoformat()),
        ).fetchone()[0]
        expired_count = con.execute(
            "SELECT COUNT(*) FROM ai_training_completions WHERE community_id = ? AND passed = 1 AND expires_at < ?",
            (community_id, now),
        ).fetchone()[0]
        unique_employees = con.execute(
            "SELECT COUNT(DISTINCT employee_id) FROM ai_training_completions WHERE community_id = ?",
            (community_id,),
        ).fetchone()[0]
        program_count = con.execute(
            "SELECT COUNT(*) FROM ai_training_programs WHERE community_id = ?",
            (community_id,),
        ).fetchone()[0]

    pass_rate = round(passed_count / total_completions, 3) if total_completions else 0.0
    return {
        "community_id":      community_id,
        "total_programs":    program_count,
        "total_completions": total_completions,
        "passed":            passed_count,
        "pass_rate":         pass_rate,
        "expiring_soon_30d": expiring_soon,
        "expired":           expired_count,
        "unique_employees":  unique_employees,
    }
