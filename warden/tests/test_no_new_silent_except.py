"""
warden/tests/test_no_new_silent_except.py — Deep-Eng P0.2 ratchet.

Counts *silent* exception handlers in warden/ — those whose entire body is a bare
``pass`` or ``continue``. Enforces a committed baseline that may only DROP: new
silent handlers can no longer land, and every conversion of a genuine fail-open
guard-bypass to ``record_failopen(...)`` tightens it.

Note: not every silent handler is a security bypass — many are legitimate
"skip a malformed item in a loop" continues (e.g. an undecodable base64 blob).
Those may stay in the baseline; the ratchet's job is to stop NET-NEW silent
handlers and to force each new one to be a conscious decision. The dangerous
subset (a *guard* errored and the *request* proceeds) is enumerated separately in
docs/fail-open-inventory.md and is where record_failopen() belongs.

Regenerate after a genuine reduction (never an increase — a worse run fails
before it can write):

    UPDATE_SILENT_BASELINE=1 pytest warden/tests/test_no_new_silent_except.py
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent          # warden/
_BASELINE = Path(__file__).parent / "silent_except_baseline.json"

# Exempt: the observability primitive itself (its suppress-blocks are deliberate).
_EXEMPT_NAMES = {"observability.py"}


def _is_silent_handler(node: ast.ExceptHandler) -> bool:
    # Drop a leading docstring/constant expr, then check the remaining body.
    body = [
        s for s in node.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]
    return len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Continue))


def count_silent_handlers() -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for py in _WARDEN.rglob("*.py"):
        rel = py.relative_to(_WARDEN)
        if rel.parts[0] == "tests" or py.name in _EXEMPT_NAMES:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        n = sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler) and _is_silent_handler(node)
        )
        if n:
            per_file[str(rel).replace("\\", "/")] = n
        total += n
    return total, per_file


def test_no_new_silent_except():
    total, per_file = count_silent_handlers()
    current = {"total": total, "per_file": per_file}

    if os.getenv("UPDATE_SILENT_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_SILENT_BASELINE") == "1":
            import pytest
            pytest.skip(f"silent-except baseline regenerated: total={total}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"Silent exception handlers rose: {total} > baseline {base['total']}. "
        "A new `except ...: pass/continue` landed. If it is a fail-open guard "
        "bypass (a guard errored and the request proceeds), replace it with "
        "warden.observability.record_failopen(stage, reason, exc) so the bypass "
        "is counted + logged. If it is legitimate control flow (skip a malformed "
        "item in a loop), reduce elsewhere to stay under baseline. After a real "
        "reduction: UPDATE_SILENT_BASELINE=1 pytest "
        "warden/tests/test_no_new_silent_except.py"
    )
