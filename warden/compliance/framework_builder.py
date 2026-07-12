"""
warden/compliance/framework_builder.py  (ENT-03)
──────────────────────────────────────────────────
Custom Compliance Framework Builder — Enterprise feature.

Allows enterprises to create custom compliance frameworks on top of
the built-in GDPR/SOC2/ISO27001/HIPAA controls. Each custom framework
is a named set of controls with categories, thresholds, and evidence links.

Storage: SQLite at COMPLIANCE_BUILDER_DB_PATH (default /tmp/warden_frameworks.db)
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import asdict, dataclass, field

from warden.config import data_path

log = logging.getLogger("warden.compliance.framework_builder")

_DB_PATH  = data_path("warden_frameworks.db", "COMPLIANCE_BUILDER_DB_PATH")
_db_lock  = threading.RLock()


@dataclass
class Control:
    id:          str
    name:        str
    description: str        = ""
    category:    str        = "General"
    status:      str        = "Not Started"
    evidence:    list[str]  = field(default_factory=list)
    weight:      float      = 1.0


@dataclass
class Framework:
    id:          str
    tenant_id:   str
    name:        str
    description: str            = ""
    controls:    list[Control]  = field(default_factory=list)
    created_at:  str            = ""
    updated_at:  str            = ""

    def score(self) -> float:
        if not self.controls:
            return 0.0
        implemented = sum(c.weight for c in self.controls if c.status == "Implemented")
        total       = sum(c.weight for c in self.controls)
        return round(implemented / total * 100, 1) if total else 0.0


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def _ensure_schema() -> None:
    with _db_lock:
        con = _db()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS custom_frameworks (
                id          TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                name        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                controls    TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
        """)
        con.commit()
        con.close()


_ensure_schema()


def _ts() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()


# ── CRUD ───────────────────────────────────────────────────────────────────────

def create_framework(tenant_id: str, name: str, description: str = "",
                     controls: list[dict] | None = None) -> Framework:
    import secrets  # noqa: PLC0415
    fid = "fw_" + secrets.token_hex(8)
    ts  = _ts()
    ctrl_objs = [Control(**c) for c in (controls or [])]
    with _db_lock:
        con = _db()
        con.execute(
            "INSERT INTO custom_frameworks(id,tenant_id,name,description,controls,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (fid, tenant_id, name, description, json.dumps([asdict(c) for c in ctrl_objs]), ts, ts),
        )
        con.commit()
        con.close()
    return Framework(id=fid, tenant_id=tenant_id, name=name, description=description,
                     controls=ctrl_objs, created_at=ts, updated_at=ts)


def get_framework(framework_id: str, tenant_id: str) -> Framework | None:
    with _db_lock:
        con = _db()
        row = con.execute(
            "SELECT * FROM custom_frameworks WHERE id=? AND tenant_id=?", (framework_id, tenant_id)
        ).fetchone()
        con.close()
    if not row:
        return None
    controls = [Control(**c) for c in json.loads(row["controls"])]
    return Framework(id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
                     description=row["description"], controls=controls,
                     created_at=row["created_at"], updated_at=row["updated_at"])


def list_frameworks(tenant_id: str) -> list[Framework]:
    with _db_lock:
        con = _db()
        rows = con.execute(
            "SELECT * FROM custom_frameworks WHERE tenant_id=? ORDER BY created_at DESC", (tenant_id,)
        ).fetchall()
        con.close()
    result = []
    for row in rows:
        controls = [Control(**c) for c in json.loads(row["controls"])]
        result.append(Framework(id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
                                description=row["description"], controls=controls,
                                created_at=row["created_at"], updated_at=row["updated_at"]))
    return result


def update_framework(framework_id: str, tenant_id: str,
                     name: str | None = None, description: str | None = None,
                     controls: list[dict] | None = None) -> Framework | None:
    fw = get_framework(framework_id, tenant_id)
    if not fw:
        return None
    if name        is not None:
        fw.name        = name
    if description is not None:
        fw.description = description
    if controls    is not None:
        fw.controls    = [Control(**c) for c in controls]
    fw.updated_at = _ts()
    with _db_lock:
        con = _db()
        con.execute(
            "UPDATE custom_frameworks SET name=?,description=?,controls=?,updated_at=? WHERE id=? AND tenant_id=?",
            (fw.name, fw.description, json.dumps([asdict(c) for c in fw.controls]),
             fw.updated_at, framework_id, tenant_id),
        )
        con.commit()
        con.close()
    return fw


def delete_framework(framework_id: str, tenant_id: str) -> bool:
    with _db_lock:
        con = _db()
        cur = con.execute(
            "DELETE FROM custom_frameworks WHERE id=? AND tenant_id=?", (framework_id, tenant_id)
        )
        con.commit()
        con.close()
    return cur.rowcount > 0


def update_control_status(framework_id: str, tenant_id: str,
                          control_id: str, status: str) -> bool:
    fw = get_framework(framework_id, tenant_id)
    if not fw:
        return False
    for ctrl in fw.controls:
        if ctrl.id == control_id:
            ctrl.status = status
            update_framework(framework_id, tenant_id, controls=[asdict(c) for c in fw.controls])
            return True
    return False
