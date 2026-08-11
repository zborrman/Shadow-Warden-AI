"""
warden/tests/test_no_ghost_table.py

F8 ratchet, second half: **no SQL may name a table that no module creates.**

`test_no_ghost_database.py` catches a *file* nobody writes. This catches the
finer version — the file is real, the table inside it is not:

  * `compliance/evidence_bundle.py` read `training_records` and
    `vendor_records`. The stores are `ai_training_completions` and
    `ai_vendors`. Both reads raised, both `except` clauses returned `[]`, and
    the customer-facing SOC 2 evidence ZIP shipped an empty
    `training_records.json` and `vendor_dpa_report.json` in **every** pack ever
    generated.
  * `marketplace/api.py` read `marketplace_kya`, a third name for KYA data —
    the table in that database is `kya_agent_profiles`, while
    `marketplace/kya.py` declares a `marketplace_kya_records` that has never
    been created in production. Wrapped in `except Exception: pass`, so the
    KYA breakdown was silently all-zero.

SQLite raises on a missing table rather than defaulting, so unlike the journal
ghost fields these *did* fail loudly — into a `try/except` that turned the
failure back into a plausible empty result. A fail-open swallow is what makes a
loud error quiet.

Baseline may only shrink.
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1]
_REPO = _SRC.parent
_BASELINE = Path(__file__).parent / "ghost_table_baseline.json"

# A string is SQL only if it *starts* with a statement keyword. Matching the
# keyword anywhere pulls in English prose ("select the ... from the ...") and
# buries the real findings — the first pass of this check produced 40 lines of
# noise around 3 defects.
_SQL_START = re.compile(r"^\s*(?:--.*\n)*\s*(WITH|SELECT|INSERT|UPDATE|DELETE)\b", re.I)
_REF = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([A-Za-z_][\w.]*)", re.I)

_CREATE = re.compile(
    r"CREATE\s+(?:TABLE|(?:MATERIALIZED\s+)?VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?([\w.]+)",
    re.I,
)
_ALEMBIC = re.compile(r'create_table\(\s*["\'](\w+)["\']')

# Names that are never app tables: SQL syntax, system catalogues, and the
# aliases a query defines for itself.
_NOT_TABLES = {
    "sqlite_master", "sqlite_sequence", "dual", "unnest", "generate_series",
    "information_schema", "pg_extension", "pg_catalog", "alembic_version",
    "values", "select", "lateral", "set",
}

#: Only multi-word identifiers are judged. Every table in this repo is
#: `snake_case`, and requiring the underscore is what separates a real
#: reference from an English sentence that happens to open with "Select" or
#: "Update" — the un-narrowed version reported ~35 prose matches around 3 real
#: defects, which is how a guard gets muted instead of fixed. The cost is that
#: a hypothetical single-word table would go unchecked.
_TABLE_SHAPE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")


def _bare(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _known_tables() -> set[str]:
    known: set[str] = set()
    for path in list(_SRC.rglob("*.py")) + list((_REPO / "data").glob("*.sql")):
        src = path.read_text(encoding="utf-8", errors="replace")
        known.update(_bare(n) for n in _CREATE.findall(src))
        if path.suffix == ".py":
            known.update(n.lower() for n in _ALEMBIC.findall(src))
    return known


def _sql_literals(src: str):
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _SQL_START.match(node.value):
                yield node.value
        elif isinstance(node, ast.JoinedStr):
            # f-string: reconstruct the literal parts so `FROM x` is still seen
            joined = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if _SQL_START.match(joined):
                yield joined


def _ghosts() -> dict[str, list[str]]:
    known = _known_tables()
    found: dict[str, set[str]] = {}
    for path in _SRC.rglob("*.py"):
        if "tests" in path.relative_to(_SRC).parts:
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(_REPO).as_posix()
        for sql in _sql_literals(src):
            # Strip CTE names — `WITH x AS (...)` defines a table that exists
            # only for the statement.
            ctes = {m.lower() for m in re.findall(r"\b(\w+)\s+AS\s*\(", sql, re.I)}
            for ref in _REF.findall(sql):
                name = _bare(ref)
                if not _TABLE_SHAPE.match(name):
                    continue
                if name in known or name in _NOT_TABLES or name in ctes:
                    continue
                found.setdefault(name, set()).add(rel)
    return {k: sorted(v) for k, v in sorted(found.items())}


def test_no_sql_names_a_table_nobody_creates():
    ghosts = _ghosts()
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))

    if os.getenv("UPDATE_GHOST_TABLE_BASELINE") == "1":  # pragma: no cover
        _BASELINE.write_text(
            json.dumps(ghosts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return

    new = sorted(set(ghosts) - set(baseline))
    if new:
        detail = "\n".join(f"  {n}  <- {', '.join(ghosts[n])}" for n in new)
        raise AssertionError(
            "SQL names a table that no CREATE TABLE in this repo produces:\n"
            f"{detail}\n\n"
            "SQLite raises on a missing table, so this will fail at runtime — "
            "and if the call sits in a try/except, it will fail *quietly* and "
            "return an empty result that looks like real data."
        )


def test_baseline_only_shrinks():
    ghosts = _ghosts()
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    stale = sorted(set(baseline) - set(ghosts))
    assert not stale, (
        f"Fixed — drop from ghost_table_baseline.json so they cannot return: {stale}. "
        "Regenerate with UPDATE_GHOST_TABLE_BASELINE=1."
    )


def test_the_detector_finds_a_known_real_defect():
    """Proof the check works, run against the actual pre-fix statements.

    A guard that cannot fail is not a guard, and this session has now seen
    several tests that agreed with the bug they were written to catch.
    """
    known = _known_tables()
    # Real tables the fixes now use.
    assert "ai_training_completions" in known
    assert "ai_vendors" in known
    assert "kya_agent_profiles" in known
    # The three names the pre-fix code used, none of which any DDL produces.
    for ghost in ("training_records", "vendor_records", "marketplace_kya"):
        assert ghost not in known, f"{ghost} is not created anywhere"


def test_prose_is_not_mistaken_for_sql():
    """The naive version of this check reported 40 English sentences.

    `_SQL_START` anchors on the statement keyword, so a docstring that merely
    contains the words must not register.
    """
    prose = "We select the winner from the list and update the ledger."
    assert not list(_sql_literals(f'x = """{prose}"""'))
    real = 'q = "SELECT a FROM some_table WHERE b = ?"'
    assert list(_sql_literals(real))


def test_the_detector_fires_on_the_exact_pre_fix_statements():
    """End-to-end on the three statements that shipped, not on a stand-in."""
    known = _known_tables()
    pre_fix = [
        "SELECT record_json FROM training_records WHERE tenant_id=? ORDER BY completed_at DESC",
        "SELECT vendor_json FROM vendor_records WHERE tenant_id=? OR tenant_id IS NULL",
        "SELECT kya_status, COUNT(*) as cnt FROM marketplace_kya GROUP BY kya_status",
    ]
    flagged = set()
    for sql in pre_fix:
        assert _SQL_START.match(sql), sql
        for ref in _REF.findall(sql):
            name = _bare(ref)
            if _TABLE_SHAPE.match(name) and name not in known and name not in _NOT_TABLES:
                flagged.add(name)
    assert flagged == {"training_records", "vendor_records", "marketplace_kya"}, flagged


def test_the_fixed_statements_pass():
    known = _known_tables()
    for sql in (
        "SELECT completion_id FROM ai_training_completions WHERE community_id = ?",
        "SELECT * FROM ai_vendors WHERE tenant_id = ?",
        "SELECT kya_status, COUNT(*) as cnt FROM kya_agent_profiles GROUP BY kya_status",
        "SELECT DATE(created_at) as d FROM marketplace_agents",
    ):
        for ref in _REF.findall(sql):
            name = _bare(ref)
            if _TABLE_SHAPE.match(name):
                assert name in known, f"{name} should be a known table"
