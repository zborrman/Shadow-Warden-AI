#!/usr/bin/env python3
"""Report the journal mode of SQLite files by reading their headers.

SW-16. `GF_DATABASE_WAL=true` is set on the Grafana container, and Grafana logs
`Config overridden from Environment variable var="GF_DATABASE_WAL=true"` at
startup. #435 took that line as confirmation. It is not: it says the variable
was parsed, not that the pragma took effect.

Measured on production 2026-09-05, `grafana.db` bytes 18 and 19 are 1 — a
rollback journal — and no `-wal` or `-shm` sidecar exists. That is a statement
about the file now, not about its history: SQLite can be switched back from WAL
to DELETE, which resets these bytes and removes the sidecars, so "not in WAL
today" is all this measures. `SQLITE_BUSY` "database is locked" errors were
still being logged on 2026-09-04, which is the symptom the setting was meant to
remove.

Reading byte 18 is the only statement about journal mode that cannot be made by
a database that is not in that mode. A log line, a compose variable and an
`ini` default are all upstream of the thing they claim.

Also useful beyond Grafana: `docs/data-layer-analysis.md` records that
`init_pragmas` (WAL + `busy_timeout=5000`) is imported by 13 of ~138 connect
sites, so most of this product's databases are expected to be in journal mode.
Expected is not measured. Point this at `data_dir()` to find out.

Usage:
    python scripts/check_sqlite_journal_mode.py <path-or-directory> [...]
    python scripts/check_sqlite_journal_mode.py --expect-wal /var/lib/grafana

Exit code is 1 if --expect-wal is given and any file is not in WAL.
"""
from __future__ import annotations

import sys
from pathlib import Path

#: Bytes 18 and 19 of a SQLite file are the write and read format versions.
#: 1 = rollback journal, 2 = WAL, and WAL requires *both* to be 2.
#: https://sqlite.org/fileformat.html#the_database_header
#:
#: Reading only byte 18 would report `wal` for a header whose two versions
#: disagree, and `--expect-wal` would pass on it. A file in a state neither
#: value describes is exactly what this script exists to notice.
_WRITE_VERSION_OFFSET = 18
_READ_VERSION_OFFSET = 19
_HEADER_MAGIC = b"SQLite format 3\x00"

MODES = {1: "journal", 2: "wal"}


def journal_mode(path: Path) -> str:
    """`wal`, `journal`, or a reason the file cannot say.

    Reads 20 bytes. It does not open the database, so it is safe to run against
    a file a live process is writing — which is the whole point, since the
    question is usually about a running service.
    """
    try:
        with path.open("rb") as fh:
            header = fh.read(20)
    except OSError as exc:
        return f"unreadable ({exc.strerror or exc})"

    if len(header) < 20:
        return "empty" if not header else "truncated"
    if not header.startswith(_HEADER_MAGIC):
        return "not-sqlite"

    write_v = header[_WRITE_VERSION_OFFSET]
    read_v = header[_READ_VERSION_OFFSET]
    if write_v != read_v or write_v not in MODES:
        return f"unknown({write_v},{read_v})"
    return MODES[write_v]


#: The only flag this takes. An unrecognised one is rejected rather than
#: ignored: `--expect-wla` used to disable enforcement silently, so a typo in a
#: CI invocation turned the check into a no-op that still exited 0.
KNOWN_FLAGS = frozenset({"--expect-wal"})


def _targets(args: list[str]) -> tuple[list[Path], list[str]]:
    """(files to check, arguments that resolved to nothing)."""
    out: list[Path] = []
    missing: list[str] = []
    for arg in args:
        p = Path(arg)
        if p.is_dir():
            found = sorted(q for q in p.rglob("*.db") if q.is_file())
            out.extend(found)
            if not found:
                missing.append(f"{arg} (directory contains no .db files)")
        elif p.exists():
            out.append(p)
        else:
            missing.append(arg)
    return out, missing


def main(argv: list[str]) -> int:
    unknown = [a for a in argv if a.startswith("--") and a not in KNOWN_FLAGS]
    if unknown:
        print(f"unknown option(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    expect_wal = "--expect-wal" in argv
    paths, missing = _targets([a for a in argv if not a.startswith("--")])
    if not paths and not missing:
        print("usage: check_sqlite_journal_mode.py [--expect-wal] <path|dir>...",
              file=sys.stderr)
        return 2

    # A target that resolved to nothing is a failure, not a warning. Otherwise
    # `--expect-wal good.db missing.db` exits 0 while never looking at the file
    # the caller cared about.
    for m in missing:
        print(f"  missing   {m}", file=sys.stderr)

    bad = len(missing)
    for path in paths:
        mode = journal_mode(path)
        sidecars = "".join(
            s for s, suffix in (("w", "-wal"), ("s", "-shm"))
            if path.with_name(path.name + suffix).exists()
        )
        note = f"  [{sidecars}]" if sidecars else ""
        print(f"  {mode:<9} {path}{note}")
        if expect_wal and mode != "wal":
            bad += 1

    if bad and (expect_wal or missing):
        print(
            f"\n{bad} target(s) failed. A setting that enables WAL is not "
            "evidence that WAL is on; this is.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
