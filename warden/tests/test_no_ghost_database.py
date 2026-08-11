"""
warden/tests/test_no_ghost_database.py

F8 ratchet: **no module may open a database file that no module writes.**

`compliance/soc2_collector.py` opened four such files. Each one produced a
confident, plausible zero rather than an error, because `open_db_readonly()` on
a missing file and a query returning no rows are indistinguishable downstream:

  * `warden_uptime.db` / `uptime_checks` — uptime has lived in Timescale
    (`warden_core.probe_results`) since D-1. SOC 2 A1.1/A1.2 reported
    `0 checks, availability None` against 548 k rows one engine away.
  * `warden_secrets_inv.db` / `access_log` — the secrets subsystem is
    `warden_secrets.db`, and it has no access log at all.
  * `warden_marketplace_clearing.db` — `marketplace/clearing.py` writes
    `marketplace_clearing_log` into `warden_marketplace.db`.
  * `warden_m2m.db` — the m2m store is `warden_m2m_store.db`.

This is the same defect class as the journal ghost fields
(`test_journal_field_contract.py`), one level up: not a key that is never
written, a **database** that is never written. The cure is the same — a reader
must consume a contract the writer publishes, not a path it guesses.

The check: collect every `data_path("<name>.db", ...)` literal and every
`settings.<x>_db_path`-backed default, then assert each name is claimed by at
least one module that also writes (DDL, `open_db(`, `open_persistent_db(`).
A name that only ever appears in read-only modules is a ghost.

Baseline may only shrink.
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1]
_BASELINE = Path(__file__).parent / "ghost_database_baseline.json"

# A module is a *writer* of the paths it names if it can create schema or open
# a read-write handle. Read-only modules are consumers and prove nothing about
# whether the file exists.
_WRITER_MARKERS = ("open_db(", "open_persistent_db(", "CREATE TABLE", "sqlite3.connect(")

_DATA_PATH_RE = re.compile(r'data_path\(\s*["\']([^"\']+\.db)["\']')
# warden/config.py declares module defaults as `_db_env("X_DB_PATH", "warden_x.db")`;
# a module reaching them through `settings.x_db_path` is still naming that file.
_DB_ENV_RE = re.compile(r'_db_env\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']+\.db)["\']')


def _iter_modules():
    for path in sorted(_SRC.rglob("*.py")):
        parts = path.relative_to(_SRC).parts
        if "tests" in parts or "migrations" in parts:
            continue
        yield path, path.read_text(encoding="utf-8", errors="replace")


def _classify(modules) -> tuple[dict[str, set[str]], set[str]]:
    """(db name -> reader modules that are not writers, all writer-claimed names).

    Takes ``(Path, source)`` pairs so the classification itself is testable on
    synthetic input rather than only on the tree it is guarding.
    """
    readers: dict[str, set[str]] = {}
    written: set[str] = set()

    for path, src in modules:
        rel = path.as_posix()
        names = set(_DATA_PATH_RE.findall(src))
        # config.py is the declaration site for every settings-backed default;
        # a name declared there is claimed by whichever module reads it, which
        # this pass credits as written (config.py itself opens nothing).
        if path.name == "config.py":
            written.update(_DB_ENV_RE.findall(src))
            continue
        if not names:
            continue
        if any(marker in src for marker in _WRITER_MARKERS):
            written.update(names)
        else:
            for name in names:
                readers.setdefault(name, set()).add(rel)

    return readers, written


def _collect() -> tuple[dict[str, set[str]], set[str]]:
    return _classify(
        (p.relative_to(_SRC.parent), src) for p, src in _iter_modules()
    )


def _ghosts() -> dict[str, list[str]]:
    readers, written = _collect()
    return {
        name: sorted(mods)
        for name, mods in sorted(readers.items())
        if name not in written
    }


def test_no_module_reads_a_database_nobody_writes():
    ghosts = _ghosts()
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))

    if os.getenv("UPDATE_GHOST_DB_BASELINE") == "1":  # pragma: no cover - maintenance
        _BASELINE.write_text(
            json.dumps(ghosts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return

    new = sorted(set(ghosts) - set(baseline))
    if new:
        detail = "\n".join(f"  {n}  <- {', '.join(ghosts[n])}" for n in new)
        raise AssertionError(
            "These modules open a database file that no module writes. The read "
            "will not raise — it returns empty, which is indistinguishable from "
            "'measured, and there was nothing there'.\n"
            f"{detail}\n\n"
            "Ask the owning module for a read contract instead of naming its file. "
            "If this really is a new store, give it a writer."
        )


def test_baseline_only_shrinks():
    ghosts = _ghosts()
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    stale = sorted(set(baseline) - set(ghosts))
    assert not stale, (
        "These are fixed and must be removed from ghost_database_baseline.json "
        f"so they cannot come back: {stale}. "
        "Regenerate with UPDATE_GHOST_DB_BASELINE=1."
    )


def test_the_check_can_actually_see_a_ghost():
    """A guard that cannot fail is not a guard.

    Several of this session's fixes were tests that agreed with the bug they
    were meant to catch, so drive the real classifier with a writer, a reader
    of that writer's file, and a reader of a file nobody writes.
    """
    writer = (
        Path("warden/fake/store.py"),
        'P = data_path("warden_real.db", "REAL_DB_PATH")\n'
        'def _c():\n    with open_db("real", P) as c: ...\n',
    )
    honest_reader = (
        Path("warden/fake/report.py"),
        'p = data_path("warden_real.db", "REAL_DB_PATH")\nopen_db_readonly(p)\n',
    )
    ghost_reader = (
        Path("warden/fake/ghost.py"),
        'p = data_path("warden_imaginary.db", "IMAGINARY_DB_PATH")\nopen_db_readonly(p)\n',
    )

    readers, written = _classify([writer, honest_reader, ghost_reader])
    ghosts = {n for n in readers if n not in written}
    assert ghosts == {"warden_imaginary.db"}, ghosts
    assert "warden/fake/ghost.py" in readers["warden_imaginary.db"]


def test_config_declared_defaults_are_not_ghosts():
    """`warden/config.py` declares module defaults via `_db_env(...)`; a module
    reaching one through `settings.x_db_path` is a legitimate reader, not a
    ghost. Without this, `api/billing_audit.py` reads as a false positive."""
    config = (
        Path("warden/config.py"),
        'x: str = field(default_factory=lambda: _db_env("AUDIT_DB_PATH", "warden_audit.db"))\n',
    )
    reader = (
        Path("warden/api/audit.py"),
        'P = data_path("warden_audit.db", "AUDIT_DB_PATH")\nopen_db_readonly(P)\n',
    )
    readers, written = _classify([config, reader])
    assert "warden_audit.db" in written
    assert not {n for n in readers if n not in written}


def test_soc2_collector_no_longer_names_the_four_ghost_files():
    src = (_SRC / "compliance" / "soc2_collector.py").read_text(encoding="utf-8")
    code = "\n".join(
        ln for ln in src.splitlines() if not ln.lstrip().startswith("#")
    )
    for name in (
        "warden_uptime.db",
        "warden_secrets_inv.db",
        "warden_marketplace_clearing.db",
        "warden_m2m.db",
    ):
        assert f'"{name}"' not in code, (
            f"soc2_collector reaches for {name} again — nothing writes it"
        )


def test_ast_parse_of_every_scanned_module():
    """The regexes read source, so a file that stops parsing would silently
    drop out of the scan rather than fail it."""
    for path, src in _iter_modules():
        try:
            ast.parse(src)
        except SyntaxError as exc:  # pragma: no cover - would be a broken tree
            raise AssertionError(f"{path} does not parse: {exc}") from exc
