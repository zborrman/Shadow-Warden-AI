"""warden/tests/test_sqlite_journal_mode_probe.py — SW-16.

The probe that reports journal mode has to be right about real files, because
its whole reason for existing is that the cheaper signals were wrong.

`GF_DATABASE_WAL=true` is set, Grafana logs the override at startup, and #435
read that as confirmation WAL was on. Production's `grafana.db` says byte 18 is
1 — rollback journal — with no `-wal` sidecar, while `SQLITE_BUSY` errors kept
appearing. The log line only ever proved the variable was parsed.

So these build actual databases in each mode and check the probe agrees with
`PRAGMA journal_mode`, rather than asserting against a header byte the test
author also just made up.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from scripts.check_sqlite_journal_mode import journal_mode


def _make(path: Path, mode: str) -> None:
    con = sqlite3.connect(path)
    con.execute(f"PRAGMA journal_mode={mode}")
    con.execute("CREATE TABLE t (x INTEGER)")
    con.commit()
    con.close()


def test_the_probe_agrees_with_sqlite_itself(tmp_path: Path) -> None:
    for mode, expected in (("WAL", "wal"), ("DELETE", "journal"), ("TRUNCATE", "journal")):
        db = tmp_path / f"{mode.lower()}.db"
        _make(db, mode)

        con = sqlite3.connect(db)
        actual_pragma = con.execute("PRAGMA journal_mode").fetchone()[0].lower()
        con.close()

        assert journal_mode(db) == expected, (
            f"probe read {journal_mode(db)!r} for a database sqlite reports as "
            f"{actual_pragma!r}"
        )


def test_wal_survives_a_clean_close(tmp_path: Path) -> None:
    """The header keeps saying WAL after the sidecars are gone.

    This is what makes the check meaningful against a stopped container: WAL is
    a property of the file, not of whether a `-wal` file happens to exist right
    now. Production's grafana.db has neither the header nor the sidecars.
    """
    db = tmp_path / "closed.db"
    _make(db, "WAL")
    assert not db.with_name(db.name + "-wal").exists(), "sidecar left behind"
    assert journal_mode(db) == "wal"


def test_a_file_that_cannot_answer_says_so(tmp_path: Path) -> None:
    """No mode is reported for something that is not a database.

    Returning "journal" for an empty or missing file would be the same defect
    one layer down — a confident answer from no measurement.
    """
    empty = tmp_path / "empty.db"
    empty.touch()
    assert journal_mode(empty) == "empty"

    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database at all, but long enough to read")
    assert journal_mode(junk) == "not-sqlite"

    assert "unreadable" in journal_mode(tmp_path / "nope.db") or journal_mode(
        tmp_path / "nope.db"
    ).startswith("unreadable")
