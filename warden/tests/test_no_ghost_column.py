"""
warden/tests/test_no_ghost_column.py

F8 ratchet, third and finest level: **no SQL may name a column its table does
not have.** `test_no_ghost_database.py` catches a file nobody writes,
`test_no_ghost_table.py` a table nobody creates, this one a column nobody
declares.

Found by it, on the tree it was written against:

  * `communities/intelligence.py` asked `sep_transfers` for `source_community`,
    `target_community` and `target_data_class`. All three are wrong — the
    columns are `source_community_id` / `target_community_id`, and the table has
    no data-class column at all (it lives on `sep_pod_tags`). Every call raised
    into a `log.debug` and community intelligence reported an all-zero
    `TransferStats`, which is what a community that never transferred anything
    also looks like.
  * `marketplace/analytics.py` asked `marketplace_clearing_log` for
    `action_type`. That table has never had one, and the comment directly above
    the query asserted that it did — a belief written down and never checked
    against the DDL one module away. The `except` set `rows=[]`, so the
    "fall back to an estimate" branch ran 100% of the time while the function
    advertised itself as a measurement.

## Deliberate limits

Only the simple shape is judged: a single-table `SELECT`, no `JOIN`, no
subquery. Anything else is skipped rather than guessed at, because a
false positive in a ratchet is worse than a miss — it teaches people to
regenerate the baseline without reading it. String literals, `AS` aliases and
function names are stripped before identifiers are collected, and only
`snake_case` names are judged (see `test_no_ghost_table.py` for why).

Columns added by a *dynamically built* `ALTER TABLE` — `economics.py` adds
`cached_tokens` from a `for col, defn in [...]` loop — cannot be seen by a
static scan, so they live in the baseline as known limits, not as defects.

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
_BASELINE = Path(__file__).parent / "ghost_column_baseline.json"

_DDL_BLOCK = re.compile(
    r"CREATE TABLE (?:IF NOT EXISTS )?[\"']?(\w+)[\"']?\s*\((.*?)\n\s*\)\s*;?", re.S | re.I
)
_COLDEF = re.compile(
    r"^[\"']?(\w+)[\"']?\s+"
    r"(TEXT|INTEGER|REAL|BLOB|NUMERIC|BOOLEAN|TIMESTAMP|VARCHAR|DOUBLE|BIGINT|SMALLINT)",
    re.I,
)
_ALTER = re.compile(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", re.I)
_NOT_COLDEF = {"PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"}

_SELECT = re.compile(r"^\s*SELECT\b", re.I)
_ONE_TABLE = re.compile(r"^\s*SELECT\s+(.*?)\s+FROM\s+(\w+)\b(.*)$", re.I | re.S)
_TAIL = re.compile(r"\b(?:GROUP BY|ORDER BY|LIMIT)\b", re.I)
_IDENT = re.compile(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b")
_ALIAS = re.compile(r"\bAS\s+(\w+)", re.I)
_FUNC = re.compile(r"\b([a-z_]+)\s*\(", re.I)


def _ddl_sources():
    """Files that may legitimately create a table — **excluding tests.**

    Deliberately duplicated from `test_no_ghost_table.py` rather than imported:
    a ratchet that cannot be run standalone tends not to be run at all. The
    rationale is recorded there — in short, `marketplace_escrows` is created by
    one test fixture and by nothing else, and counting fixture DDL as proof let
    both guards agree with the bug.
    """
    for path in _SRC.rglob("*.py"):
        if "tests" in path.relative_to(_SRC).parts:
            continue
        yield path
    yield from (_REPO / "data").glob("*.sql")


def _split_columns(body: str) -> list[str]:
    """Split a CREATE TABLE body on top-level commas."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts]


def _table_columns() -> dict[str, set[str]]:
    tables: dict[str, set[str]] = {}
    # Tests are excluded on purpose — see `_ddl_sources` in
    # test_no_ghost_table.py. A fixture's CREATE TABLE is not evidence that
    # production has the table, and treating it as evidence is how
    # `marketplace_escrows` stayed invisible.
    for path in _ddl_sources():
        src = path.read_text(encoding="utf-8", errors="replace")
        for name, body in _DDL_BLOCK.findall(src):
            # Split on commas, not newlines: `(key TEXT PRIMARY KEY, payload
            # TEXT, expires_at REAL)` is written on one line in
            # marketplace/memory.py, and a line-based reader saw only `key` —
            # then reported the other two as ghosts. A parser gap that
            # manufactures findings is the fastest way to get a ratchet ignored.
            cols = {
                m.group(1).lower()
                for part in _split_columns(body)
                if (m := _COLDEF.match(part)) and m.group(1).upper() not in _NOT_COLDEF
            }
            if cols:
                tables.setdefault(name.lower(), set()).update(cols)
        for tbl, col in _ALTER.findall(src):
            tables.setdefault(tbl.lower(), set()).add(col.lower())
    return tables


def _sql_strings(src: str):
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _SELECT.match(node.value):
                yield node.value
        elif isinstance(node, ast.JoinedStr):
            joined = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if _SELECT.match(joined):
                yield joined


def _ghosts(tables: dict[str, set[str]] | None = None) -> dict[str, list[str]]:
    tables = tables if tables is not None else _table_columns()
    found: dict[str, set[str]] = {}
    for path in _SRC.rglob("*.py"):
        if "tests" in path.relative_to(_SRC).parts:
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(_REPO).as_posix()
        for sql in _sql_strings(src):
            low = sql.lower()
            if " join " in low or "(select" in low.replace(" ", ""):
                continue
            m = _ONE_TABLE.match(sql.strip())
            if not m:
                continue
            select_list, table, rest = m.groups()
            table = table.lower()
            if table not in tables or re.search(r"\bFROM\b|\bJOIN\b", rest, re.I):
                continue
            body = select_list + " " + _TAIL.split(rest)[0]
            body = re.sub(r"'[^']*'", " ", body)
            skip = {a.lower() for a in _ALIAS.findall(body)} | {
                f.lower() for f in _FUNC.findall(body)
            }
            for name in set(_IDENT.findall(body)) - tables[table] - skip:
                found.setdefault(f"{table}.{name}", set()).add(rel)
    return {k: sorted(v) for k, v in sorted(found.items())}


def test_no_sql_names_a_column_its_table_lacks():
    ghosts = _ghosts()
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))

    if os.getenv("UPDATE_GHOST_COLUMN_BASELINE") == "1":  # pragma: no cover
        _BASELINE.write_text(
            json.dumps(ghosts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return

    new = sorted(set(ghosts) - set(baseline))
    if new:
        detail = "\n".join(f"  {n}  <- {', '.join(ghosts[n])}" for n in new)
        raise AssertionError(
            "SQL names a column its table does not declare:\n"
            f"{detail}\n\n"
            "SQLite raises `no such column`, so this fails at runtime — and "
            "inside a try/except it fails quietly and returns an empty result "
            "that reads as real data. If the column is added by a dynamically "
            "built ALTER TABLE, add it to the baseline with a note."
        )


def test_baseline_only_shrinks():
    ghosts = _ghosts()
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    stale = sorted(set(baseline) - set(ghosts))
    assert not stale, (
        f"Resolved — drop from ghost_column_baseline.json: {stale}. "
        "Regenerate with UPDATE_GHOST_COLUMN_BASELINE=1."
    )


def test_the_detector_fires_on_the_statements_it_was_written_for():
    """Driven with the real DDL and the real pre-fix SQL."""
    tables = _table_columns()
    assert "source_community_id" in tables["sep_transfers"]
    assert "source_community" not in tables["sep_transfers"]
    assert "action_type" not in tables["marketplace_clearing_log"]

    pre_fix = (
        "SELECT status, target_data_class, target_community FROM sep_transfers "
        "WHERE source_community=?",
        "SELECT action_type, COUNT(*) as cnt FROM marketplace_clearing_log "
        "WHERE cleared_at >= ? GROUP BY action_type",
    )
    flagged: set[str] = set()
    for sql in pre_fix:
        m = _ONE_TABLE.match(sql.strip())
        assert m, sql
        select_list, table, rest = m.groups()
        body = re.sub(r"'[^']*'", " ", select_list + " " + _TAIL.split(rest)[0])
        skip = {a.lower() for a in _ALIAS.findall(body)} | {
            f.lower() for f in _FUNC.findall(body)
        }
        for name in set(_IDENT.findall(body)) - tables[table.lower()] - skip:
            flagged.add(f"{table.lower()}.{name}")
    assert flagged == {
        "sep_transfers.target_data_class",
        "sep_transfers.target_community",
        "sep_transfers.source_community",
        "marketplace_clearing_log.action_type",
    }, flagged


def test_aliases_and_literals_do_not_register():
    """`SELECT SUM(x) AS total_cost` must not read as a column `total_cost`,
    and `WHERE status='past_due'` must not read as a column `past_due`.

    The un-filtered version produced 45 findings, 33 of them this shape.
    """
    tables = {"t": {"amount_usd", "status"}}
    ok = "SELECT SUM(amount_usd) AS total_cost FROM t WHERE status='past_due'"
    m = _ONE_TABLE.match(ok)
    select_list, table, rest = m.groups()
    body = re.sub(r"'[^']*'", " ", select_list + " " + _TAIL.split(rest)[0])
    skip = {a.lower() for a in _ALIAS.findall(body)} | {
        f.lower() for f in _FUNC.findall(body)
    }
    assert not (set(_IDENT.findall(body)) - tables["t"] - skip)


def test_joins_are_skipped_not_guessed():
    """The fix for `intelligence.py` is itself a JOIN. A checker that guessed
    at multi-table queries would flag `pt.data_class` as missing from
    `sep_transfers` — a false positive on correct code."""
    joined = (
        "SELECT t.status, pt.data_class FROM sep_transfers t "
        "LEFT JOIN sep_pod_tags pt ON pt.entity_id = t.source_entity_id"
    )
    assert " join " in joined.lower()
    assert not any(k.startswith("sep_transfers.data_class") for k in _ghosts())
