#!/usr/bin/env python3
"""
scripts/mutation_sweep.py — H-3: one module's mutation sweep, as a ratchet.

Mutation testing is too slow to gate a PR (causal_arbiter alone is ~650
mutants), so between manual sweeps the suite's strength on the money path was
unmeasured. ``.github/workflows/mutation-sweep.yml`` runs this weekly, one
matrix job per module:

    python scripts/mutation_sweep.py prepare <module>   # narrow [tool.mutmut]
    mutmut run --max-children 4
    mutmut export-cicd-stats
    python scripts/mutation_sweep.py check <module>     # compare with baseline

The baseline (``warden/tests/mutation_survivor_baseline.json``) holds, per
module, the source path, the test files that exercise it, and the number of
surviving mutants last measured. ``check`` fails when survivors went UP, when
the run checked nothing (a sweep that mutated nothing passes every ratchet),
or when any mutant was left unchecked. A ``null`` baseline means "not yet
measured": the run reports its number and passes, so the first sweep arms the
ratchet instead of guessing at it. Lowering a number is a manual edit, made
when a sweep reports fewer survivors — the floor never moves up on its own.

``prepare`` rewrites ``pyproject.toml`` in the CI checkout only; it is never
committed.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
BASELINE = _ROOT / "warden" / "tests" / "mutation_survivor_baseline.json"
_PYPROJECT = _ROOT / "pyproject.toml"
_STATS = _ROOT / "mutants" / "mutmut-cicd-stats.json"


def _load() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))["modules"]


def _toml_list(items: list[str]) -> str:
    return "[\n" + "".join(f'    "{i}",\n' for i in items) + "]"


def prepare(module: str) -> None:
    entry = _load()[module]
    text = _PYPROJECT.read_text(encoding="utf-8")
    new, n1 = re.subn(
        r"(?ms)^source_paths = \[.*?^\]",
        "source_paths = " + _toml_list([entry["source"]]),
        text,
    )
    new, n2 = re.subn(
        r"(?ms)^pytest_add_cli_args_test_selection = \[.*?^\]",
        "pytest_add_cli_args_test_selection = " + _toml_list(entry["tests"]),
        new,
    )
    if (n1, n2) != (1, 1):
        sys.exit(f"[tool.mutmut] layout changed - expected one of each key, got {n1}, {n2}")
    _PYPROJECT.write_text(new, encoding="utf-8")
    print(f"[tool.mutmut] narrowed to {entry['source']} ({len(entry['tests'])} test files)")


def evaluate(module: str, stats: dict, baseline: int | None) -> tuple[bool, str]:
    survived = stats["survived"]
    total = stats["total"]
    unchecked = stats.get("check_was_interrupted_by_user", 0)
    head = (
        f"{module}: {survived} survived / {stats['killed']} killed / {total} total "
        f"(timeout {stats.get('timeout', 0)}, no tests {stats.get('no_tests', 0)})"
    )
    if total == 0:
        return False, head + " - FAIL: no mutants were generated, so nothing was measured"
    if stats["killed"] == 0:
        return False, head + " - FAIL: nothing was killed; the tests did not run against mutants"
    if unchecked:
        return False, head + f" - FAIL: {unchecked} mutants were never checked"
    if baseline is None:
        return True, head + " - not yet baselined; record this number to arm the ratchet"
    if survived > baseline:
        return False, head + f" - FAIL: survivors rose from {baseline} to {survived}"
    if survived < baseline:
        return True, head + f" - improved from {baseline}; lower the baseline to {survived}"
    return True, head + f" - at baseline {baseline}"


def check(module: str) -> int:
    stats = json.loads(_STATS.read_text(encoding="utf-8"))
    ok, line = evaluate(module, stats, _load()[module]["survived"])
    print(line)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    match argv[1:]:
        case ["list"]:
            print(json.dumps(sorted(_load())))
            return 0
        case ["prepare", module]:
            prepare(module)
            return 0
        case ["check", module]:
            return check(module)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
