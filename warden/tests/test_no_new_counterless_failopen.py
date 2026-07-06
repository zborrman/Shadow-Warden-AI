"""
warden/tests/test_no_new_counterless_failopen.py — Deep-Eng P0.2 ratchet.

Enforces FAILOPEN-01: every fail-open site must be either protected-by-documented-
invariant or *covered* by a ``record_failopen()`` / ``failopen_guard()`` counter, so
no bypass can degrade a guard silently. The count of *counter-less* fail-open sites
(neither protected nor covered) may only DROP from a committed baseline.

This shares its classification with ``scripts/fail_open_inventory.py`` (single
source of truth) — the same regex + ±window coverage heuristic that generates
``docs/fail-open-inventory.md``. Each new ``record_failopen`` wiring tightens the
number; a net-new counter-less fail-open fails CI.

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_FAILOPEN_BASELINE=1 pytest warden/tests/test_no_new_counterless_failopen.py
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_BASELINE = Path(__file__).parent / "counterless_failopen_baseline.json"
_SCRIPT = _REPO / "scripts" / "fail_open_inventory.py"


def _load_inventory():
    spec = importlib.util.spec_from_file_location("_fail_open_inventory", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _count() -> tuple[int, dict[str, int]]:
    inv = _load_inventory()
    rows = inv.counterless_rows(inv.collect_rows())
    per_file: dict[str, int] = {}
    for rel, _ln, _ctx, _reason, _cov in rows:
        per_file[rel] = per_file.get(rel, 0) + 1
    return len(rows), per_file


def test_no_new_counterless_failopen():
    total, per_file = _count()
    current = {"total": total, "per_file": dict(sorted(per_file.items()))}

    if os.getenv("UPDATE_FAILOPEN_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_FAILOPEN_BASELINE") == "1":
            import pytest
            pytest.skip(f"counter-less fail-open baseline regenerated: total={total}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"Counter-less fail-open sites rose: {total} > baseline {base['total']}. "
        "A fail-open guard-bypass landed without observability. Wire it with "
        "warden.observability.record_failopen(stage, reason, exc) (or failopen_guard) "
        "so the bypass is a Prometheus counter + alert, then regenerate the baseline: "
        "UPDATE_FAILOPEN_BASELINE=1 pytest "
        "warden/tests/test_no_new_counterless_failopen.py"
    )
