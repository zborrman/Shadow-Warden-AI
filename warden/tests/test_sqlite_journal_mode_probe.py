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

import os
import sqlite3
from pathlib import Path

import pytest

from scripts.check_sqlite_journal_mode import journal_mode, main


def _make(path: Path, mode: str) -> None:
    """Build a database in `mode`.

    Deliberately raw `sqlite3`, not `warden.db.connect.open_db`: that applies
    `init_pragmas`, which runs `PRAGMA journal_mode=WAL` on every connection.
    Every fixture here would come out in WAL and the journal-mode cases would
    pass without ever testing anything.
    """
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


def test_a_header_whose_two_versions_disagree_is_not_called_wal(
    tmp_path: Path,
) -> None:
    """WAL needs bytes 18 AND 19 to be 2.

    Reading byte 18 alone reported `wal` for a header the other half
    contradicts, and `--expect-wal` passed on it. A file in a state neither
    value describes is precisely what this script exists to notice, so it has
    to say `unknown` rather than pick the reassuring answer.
    """
    db = tmp_path / "mismatched.db"
    _make(db, "WAL")
    raw = bytearray(db.read_bytes())
    raw[19] = 1  # write_version=2, read_version=1
    db.write_bytes(bytes(raw))

    assert journal_mode(db) == "unknown(2,1)", (
        f"a mismatched header was classified as {journal_mode(db)!r}"
    )


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

    assert journal_mode(tmp_path / "nope.db").startswith("unreadable")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no mkfifo on this platform")
def test_a_fifo_is_refused_rather_than_opened(tmp_path: Path) -> None:
    """Opening a FIFO for reading blocks until someone writes to it.

    `Path.exists()` is true for FIFOs and device nodes, so `--expect-wal fifo`
    would hang with nothing to time it out and nothing to tell the operator why
    the pipeline stopped. A check that hangs is worse than one that fails: the
    failure at least says something.
    """
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    assert main(["--expect-wal", str(fifo)]) == 1, (
        "a FIFO was accepted as a target; if this test hangs instead of "
        "failing, the script opened it."
    )


def test_enforcement_cannot_be_switched_off_by_accident(tmp_path: Path) -> None:
    """A target that resolved to nothing, or a mistyped flag, must not pass.

    `--expect-wal good.db missing.db` exited 0 while never looking at the file
    the caller cared about, and `--expect-wla good.db` disabled enforcement
    silently — a check a typo turns into a no-op still reports success, which
    is the failure mode this whole change is about.
    """
    good = tmp_path / "good.db"
    _make(good, "WAL")

    assert main(["--expect-wal", str(good)]) == 0
    assert main(["--expect-wal", str(good), str(tmp_path / "gone.db")]) == 1, (
        "a target that does not exist was not counted as a failure"
    )
    assert main(["--expect-wla", str(good)]) == 2, (
        "a mistyped flag was ignored instead of rejected, so enforcement was "
        "silently off"
    )
