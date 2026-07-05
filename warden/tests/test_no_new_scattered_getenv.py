"""
warden/tests/test_no_new_scattered_getenv.py — Deep-Eng P1 config ratchet.

Counts direct os.getenv / os.environ accesses across warden/ (excluding the
sanctioned home warden/config.py and the tests). Enforces a committed baseline
that may only DROP: new configuration must flow through warden.config.settings
(typed, validated, auditable) rather than being read inline. Every migration of
an inline read into config.py tightens the baseline.

Regenerate after a genuine reduction:

    UPDATE_GETENV_BASELINE=1 pytest warden/tests/test_no_new_scattered_getenv.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent
_BASELINE = Path(__file__).parent / "scattered_getenv_baseline.json"
_PAT = re.compile(r"\bos\.(?:getenv|environ)\b")

# Sanctioned to read env directly: config.py IS the typed home; observability's
# canary gate reads one flag pre-config-load.
_EXEMPT = {"config.py"}


def count_getenv() -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for py in _WARDEN.rglob("*.py"):
        rel = py.relative_to(_WARDEN)
        if rel.parts[0] == "tests" or py.name in _EXEMPT:
            continue
        try:
            src = py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        n = len(_PAT.findall(src))
        if n:
            per_file[str(rel).replace("\\", "/")] = n
        total += n
    return total, per_file


def test_no_new_scattered_getenv():
    total, per_file = count_getenv()
    current = {"total": total, "per_file": per_file}

    if os.getenv("UPDATE_GETENV_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_GETENV_BASELINE") == "1":
            import pytest
            pytest.skip(f"scattered-getenv baseline regenerated: total={total}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"Direct os.getenv/os.environ reads rose: {total} > baseline {base['total']}. "
        "Add a typed field to warden/config.py Settings and read it via "
        "`from warden.config import settings` instead of inline os.getenv. "
        "After a real reduction: UPDATE_GETENV_BASELINE=1 pytest "
        "warden/tests/test_no_new_scattered_getenv.py"
    )
