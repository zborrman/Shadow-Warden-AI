"""
warden/tests/test_no_new_suppressions.py — Deep-Eng P1 gate ratchet.

Freezes the count of lint/type suppressions (`# type: ignore`, `# noqa`) in
warden/ (excluding tests). Each suppression is an unverified assumption that
erodes the value of the ruff/mypy gates; this baseline may only DROP, so new
suppressions can no longer land silently and every removed one tightens it.

Regenerate after a genuine reduction:

    UPDATE_SUPPRESSION_BASELINE=1 pytest warden/tests/test_no_new_suppressions.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent
_BASELINE = Path(__file__).parent / "suppression_baseline.json"
_TYPE_IGNORE = re.compile(r"#\s*type:\s*ignore")
_NOQA = re.compile(r"#\s*noqa")


def count_suppressions() -> dict:
    ti = nq = 0
    per_file: dict[str, dict[str, int]] = {}
    for py in _WARDEN.rglob("*.py"):
        if py.relative_to(_WARDEN).parts[0] == "tests":
            continue
        try:
            src = py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        a, b = len(_TYPE_IGNORE.findall(src)), len(_NOQA.findall(src))
        if a or b:
            per_file[str(py.relative_to(_WARDEN)).replace("\\", "/")] = {
                "type_ignore": a, "noqa": b
            }
        ti += a
        nq += b
    return {"type_ignore": ti, "noqa": nq, "per_file": per_file}


def test_no_new_suppressions():
    current = count_suppressions()

    if os.getenv("UPDATE_SUPPRESSION_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_SUPPRESSION_BASELINE") == "1":
            import pytest
            pytest.skip(f"suppression baseline regenerated: {current['type_ignore']} ti / {current['noqa']} noqa")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert current["type_ignore"] <= base["type_ignore"], (
        f"`# type: ignore` count rose: {current['type_ignore']} > baseline "
        f"{base['type_ignore']}. Fix the underlying type instead of suppressing, "
        "or after a genuine reduction: UPDATE_SUPPRESSION_BASELINE=1 pytest "
        "warden/tests/test_no_new_suppressions.py"
    )
    assert current["noqa"] <= base["noqa"], (
        f"`# noqa` count rose: {current['noqa']} > baseline {base['noqa']}. "
        "Fix the lint finding instead of suppressing, or after a genuine "
        "reduction: UPDATE_SUPPRESSION_BASELINE=1 pytest "
        "warden/tests/test_no_new_suppressions.py"
    )
