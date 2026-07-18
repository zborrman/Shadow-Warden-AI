"""
warden/tests/test_no_raw_sqlite_connect.py — DE-6 data-layer ratchet (P1).

Counts raw ``sqlite3.connect(...)`` call sites across warden/ and enforces a
committed baseline that may only DROP. New per-module DB code must go through
``warden.db.connect.open_db(db_key, db_path)``, which applies the standard
pragmas (WAL + 5s busy_timeout — audit finding F1), runs ``ensure_schema`` once
via the DDL registry (F2), and handles commit/close. See
docs/data-layer-analysis.md.

Why a ratchet and not a ban: ~148 legacy sites remain; they are migrated in
follow-on slices under this same umbrella. Freezing the count blocks *new* raw
connections — the pragma-less, DDL-on-every-connect pattern — while the existing
ones are drained over time.

Sanctioned to call ``sqlite3.connect`` directly:
  db/connect.py — IS the seam (the single place the raw connect now lives)
  db/turso.py   — the Turso adapter's local-SQLite fallback path

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_SQLITE_CONNECT_BASELINE=1 pytest warden/tests/test_no_raw_sqlite_connect.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent
_BASELINE = Path(__file__).parent / "raw_sqlite_connect_baseline.json"

_PAT = re.compile(r"sqlite3\.connect\s*\(")

# Files allowed to call sqlite3.connect directly (the seam + its fallback).
_EXEMPT = {"connect.py", "turso.py"}


def count_raw_sqlite_connect() -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for py in sorted(_WARDEN.rglob("*.py")):
        rel = py.relative_to(_WARDEN)
        if rel.parts[0] == "tests" or py.name in _EXEMPT:
            continue
        try:
            src = py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        n = len(_PAT.findall(src))
        if n:
            per_file[str(rel).replace("\\", "/")] = n
        total += n
    return total, per_file


def test_no_raw_sqlite_connect():
    total, per_file = count_raw_sqlite_connect()
    current = {"total": total, "per_file": dict(sorted(per_file.items()))}

    if os.getenv("UPDATE_SQLITE_CONNECT_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_SQLITE_CONNECT_BASELINE") == "1":
            import pytest
            pytest.skip(f"raw sqlite3.connect baseline regenerated: total={total}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"Raw sqlite3.connect call sites rose: {total} > baseline {base['total']}. "
        "New per-module DB code must open connections via "
        "warden.db.connect.open_db(db_key, db_path) so it gets WAL + busy_timeout "
        "pragmas and DDL-once via the registry — never a bare sqlite3.connect(...). "
        "After a genuine reduction: UPDATE_SQLITE_CONNECT_BASELINE=1 pytest "
        "warden/tests/test_no_raw_sqlite_connect.py"
    )
