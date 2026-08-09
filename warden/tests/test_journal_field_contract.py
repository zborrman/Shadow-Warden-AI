"""
warden/tests/test_journal_field_contract.py — journal readers may not invent keys.

Four separate features shipped reading fields `build_entry()` has never
written. Each produced confident, plausible numbers instead of an error,
because `dict.get()` on a missing key returns a default:

  * `api/compliance_report.py` (#302) — `verdict`, `latency_ms`, upper-case
    `"INJECTION"`. Five regulator-facing surfaces reported 0 blocked and 0
    injection hits against a truth of 3 100 and 3 100, and one payload listed
    `prompt_injection: 8300` in its own category breakdown while saying zero.
  * `business_intelligence/service.py` (#304) — `timestamp`, `verdict`,
    `processing_ms`, `category`. Usage reported no traffic at all, and the unit
    test fabricated its journal in the same wrong schema, so it agreed.
  * `xai/chain.py` (#303) — 20 of the 27 fields it reads. Four of the nine
    pipeline stages report SKIP on every record ever explained.
  * and the same shape one layer down in D-1: features assuming a step that
    never ran.

Any one of those is a typo. Four is a missing contract, so this is that
contract: `build_entry()` defines the journal's schema, and a consumer that
reads a key outside it is reading a default forever.

Mechanics follow the other gates here — a baseline that may only shrink, not a
hard zero, because `xai/chain.py`'s 20 fields are a known open decision (record
the stage metadata, or stop claiming the stages) and not something to block
merges on today. Regenerate after a genuine reduction:

    UPDATE_JOURNAL_CONTRACT_BASELINE=1 pytest warden/tests/test_journal_field_contract.py
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent          # warden/
_BASELINE = Path(__file__).parent / "journal_field_baseline.json"

# Receiver names that mean "a journal entry". Deliberately narrow: the point is
# to catch `e.get("verdict")`, not every `.get()` in the tree. `row` is
# excluded on purpose — it is the database-cursor idiom, and including it made
# the scan report `portal_router`'s user rows as journal entries.
_ENTRY_NAMES = {"e", "ev", "entry", "rec", "record", "evt"}

# Files that handle entries without calling load_entries themselves, because a
# caller hands the entries to them.
_INDIRECT_CONSUMERS = {"xai/chain.py"}

# How a function gets hold of entries. `load_entries` also matches
# `self._load_entries()`. The path markers matter because a consumer can open
# the journal itself instead of going through the reader — which is exactly
# what `business_intelligence/service.py` did, against a filename the journal
# has never had, and why it reported zero traffic for months (#304).
_ENTRY_SOURCE_MARKERS = ("load_entries", "LOGS_PATH", "logs.json")

# Keys a consumer may legitimately read that build_entry does not write:
# enrichment added downstream, or fields from a different dict that happens to
# use one of the receiver names above.
_ALLOWED_EXTRA = {
    # Attached by the request path after build_entry() returns, so it is real
    # in the file even though the builder does not name it. Confirmed present
    # on all 3 377 production entries.
    "tenant_id",
}


def _journal_schema() -> set[str]:
    """The keys `build_entry()` actually produces — the authority.

    It builds a dict literal and then adds four more keys conditionally
    (`session_id`, and the masking trio), so both forms are collected. Reading
    only the `return` would miss them and the guard would flag correct code.
    """
    src = (_REPO / "analytics" / "logger.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == "build_entry"):
            continue
        keys: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Dict):
                keys |= {
                    k.value for k in sub.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
            elif isinstance(sub, ast.Assign):
                for tgt in sub.targets:
                    if (
                        isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.slice, ast.Constant)
                        and isinstance(tgt.slice.value, str)
                    ):
                        keys.add(tgt.slice.value)
        if keys:
            return keys
    # `raise`, not `pytest.fail()`: CI's lint job installs mypy without pytest,
    # so `pytest.fail` is untyped there and does not read as NoReturn — the
    # function then looks like it can fall off the end and mypy fails the build.
    raise AssertionError("could not read build_entry()'s keys — the guard is not guarding")


def _is_consumer(path: Path, src: str) -> bool:
    rel = path.relative_to(_REPO).as_posix()
    if rel in _INDIRECT_CONSUMERS:
        return True
    # Same markers as the function-level scope check. An earlier draft gated the
    # file on `load_entries` alone, which excluded the one module that opened
    # the journal by path — the module this guard exists because of.
    return any(marker in src for marker in _ENTRY_SOURCE_MARKERS)


def _get_keys(node: ast.AST) -> set[str]:
    """`<entry-ish>.get("literal")` keys anywhere under *node*."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "get"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id in _ENTRY_NAMES
            and sub.args
            and isinstance(sub.args[0], ast.Constant)
            and isinstance(sub.args[0].value, str)
        ):
            out.add(sub.args[0].value)
    return out


def _keys_read(src: str, *, whole_file: bool) -> set[str]:
    """Keys read off an entry, scoped to functions that handle entries.

    The receiver name alone is not enough signal: `record` is also what a
    report dict and a community row are called, which made the first draft
    report `art30.py` and `public_stats.py` as journal consumers. So a `.get()`
    only counts when its enclosing function actually loads entries — matched on
    `load_entries`, which also catches `self._load_entries()`.

    `whole_file` is for the indirect consumers, which are handed entries by a
    caller and never load anything themselves.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    if whole_file:
        return _get_keys(tree)

    funcs = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    bodies = {f.name: ast.unparse(f) for f in funcs}

    # A function handles entries if it obtains them itself, or if it calls one
    # that does. `compliance/soc2_collector.py` is why the second half exists:
    # its `_iter_log_window()` generator opens the journal and every collector
    # iterates *that*, so a direct-only scan saw 1 of its 15 invented fields.
    handlers = {
        name for name, body in bodies.items()
        if any(marker in body for marker in _ENTRY_SOURCE_MARKERS)
    }
    for _ in range(3):        # transitive closure; depth 3 is plenty here
        grown = {
            name for name, body in bodies.items()
            if any(f"{h}(" in body for h in handlers)
        }
        if grown <= handlers:
            break
        handlers |= grown

    out: set[str] = set()
    for f in funcs:
        if f.name in handlers:
            out |= _get_keys(f)
    return out


def _scan() -> dict[str, list[str]]:
    schema = _journal_schema() | _ALLOWED_EXTRA
    findings: dict[str, list[str]] = {}
    for path in sorted(_REPO.rglob("*.py")):
        rel = path.relative_to(_REPO).as_posix()
        if rel.startswith("tests/"):
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not _is_consumer(path, src):
            continue
        indirect = rel in _INDIRECT_CONSUMERS
        unknown = sorted(_keys_read(src, whole_file=indirect) - schema)
        if unknown:
            findings[rel] = unknown
    return findings


def test_build_entry_is_readable_as_the_schema():
    schema = _journal_schema()
    # If this shrinks unexpectedly the guard silently stops guarding, so pin the
    # fields every consumer in the tree depends on.
    for required in ("ts", "request_id", "allowed", "risk_level", "flags",
                     "secrets_found", "elapsed_ms"):
        assert required in schema, f"build_entry no longer writes `{required}`"


def test_no_new_journal_fields_read_that_are_never_written():
    findings = _scan()
    total = sum(len(v) for v in findings.values())

    if os.getenv("UPDATE_JOURNAL_CONTRACT_BASELINE") == "1":
        _BASELINE.write_text(
            json.dumps({"total": total, "per_file": findings}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        pytest.skip(f"baseline regenerated: {total} unknown field reads")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"Journal consumers read {total} fields build_entry() never writes, up from "
        f"{base['total']}.\n\n"
        "A `.get()` on a key the journal does not have returns a default, not an "
        "error — the number will be zero forever and look deliberate. Either add "
        "the field to build_entry(), or read a field that exists.\n\n"
        f"Now: {json.dumps(findings, indent=2, sort_keys=True)}\n\n"
        "After a genuine reduction: "
        "UPDATE_JOURNAL_CONTRACT_BASELINE=1 pytest warden/tests/test_journal_field_contract.py"
    )


def test_scan_follows_helpers_through_three_levels_and_async():
    """Pure analysis, no repo state — the scoping rule itself.

    The first draft counted `.get()` only inside functions that obtain entries
    directly. `compliance/soc2_collector.py` opens the journal in one generator
    and iterates it from every collector, so that draft saw 1 of its 15
    invented fields. This pins the transitive walk, and pins that `async def`
    consumers are not skipped — several journal readers are coroutines.
    """
    src = '''
def _iter_log():
    with open(LOGS_PATH) as f:
        yield {}

def _level_one():
    for entry in _iter_log():
        entry.get("alpha")

def _level_two():
    _level_one()
    for entry in []:
        entry.get("beta")

async def _level_three():
    _level_two()
    for entry in []:
        entry.get("gamma")

def _unrelated(record):
    record.get("delta")
'''
    found = _keys_read(src, whole_file=False)
    assert {"alpha", "beta", "gamma"} <= found, f"transitive walk stopped early: {found}"
    assert "delta" not in found, "a function that never touches entries was scanned"


def test_soc2_collector_is_wired_into_the_scan():
    """Separate from the analysis above: is the real module actually reached?"""
    path = _REPO / "compliance" / "soc2_collector.py"
    src = path.read_text(encoding="utf-8")
    assert _is_consumer(path, src), (
        "soc2_collector is no longer recognised as a journal consumer — it opens "
        "the journal in _iter_log_window()"
    )


def test_the_fixed_defects_stay_fixed():
    """Named regressions, so a fix cannot quietly come undone under the baseline.

    Only what is fixed on `main` is asserted here. `business_intelligence/
    service.py` is still in the baseline on purpose — its fix is #304, and the
    entries drop out of the baseline when that lands.
    """
    findings = _scan()
    for rel, ghost, pr in (
        ("api/compliance_report.py", "verdict", "#302"),
        ("api/compliance_report.py", "latency_ms", "#302"),
        ("business_intelligence/service.py", "timestamp", "#304"),
        ("business_intelligence/service.py", "processing_ms", "#304"),
        ("financial/cost_allocation.py", "verdict", "this PR"),
        ("portal_router.py", "timestamp", "this PR"),
    ):
        assert ghost not in findings.get(rel, []), (
            f"{rel} reads `{ghost}` again — it was fixed in {pr}"
        )
