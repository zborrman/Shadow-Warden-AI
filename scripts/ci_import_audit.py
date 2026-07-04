#!/usr/bin/env python3
"""
scripts/ci_import_audit.py
──────────────────────────
Route-parity diagnostic for CI (fix #2 — "force dep parity").

The route-inventory guard (warden/tests/test_route_inventory.py) tolerates whole
subsystems being absent when an optional dependency is missing in the current
environment. That keeps CI green, but it hides *which* dependency is missing.

This script names the gap deterministically: it walks every ``warden.*`` module
and tries to import it, reporting each failure with its root-cause exception. Run
it in the CI ``test`` job so the exact missing dep (or real import bug) appears in
the job summary — no local log required to pinpoint it.

A single failing import near the top of a main.py ``try`` block silently drops
every ``include_router`` after it, so one root cause can explain hundreds of
"removed" routes. This surfaces that root cause.

Exit code is always 0 — this is informational, never a merge gate.

Usage:
    python scripts/ci_import_audit.py            # human-readable
    python scripts/ci_import_audit.py --summary  # GitHub step-summary markdown
"""
from __future__ import annotations

import importlib
import pkgutil
import sys
import traceback
from pathlib import Path

# Make the repo root importable whether or not the package is pip-installed.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _root_cause(exc: BaseException) -> str:
    """Follow the __cause__/__context__ chain to the deepest exception."""
    cur: BaseException = exc
    while True:
        nxt = cur.__cause__ or cur.__context__
        if nxt is None or nxt is cur:
            break
        cur = nxt
    return f"{type(cur).__name__}: {cur}"


def audit() -> dict[str, str]:
    import warden  # noqa: PLC0415

    failures: dict[str, str] = {}
    for mod in pkgutil.walk_packages(warden.__path__, prefix="warden."):
        name = mod.name
        # Skip test packages and Streamlit page scripts — they are not routers and
        # legitimately import heavy UI-only deps.
        if ".tests" in name or "/tests" in name or ".analytics.pages" in name:
            continue
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 — we want every failure, not a crash
            failures[name] = _root_cause(exc)
        except BaseException as exc:  # noqa: BLE001 — e.g. SystemExit in a bad module
            failures[name] = f"(non-Exception) {type(exc).__name__}: {exc}"
    return failures


def main() -> int:
    summary = "--summary" in sys.argv
    try:
        failures = audit()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        print("import audit itself failed — see traceback above")
        return 0

    if summary:
        print("## Route-Parity Import Audit\n")
        if not failures:
            print("✅ All `warden.*` modules import cleanly — full route surface will mount.\n")
        else:
            print(f"⚠️ {len(failures)} module(s) failed to import (their routes will be absent):\n")
            print("| Module | Root cause |")
            print("| --- | --- |")
            for name, cause in sorted(failures.items()):
                print(f"| `{name}` | {cause} |")
            print("\nInstall the named dependency (or fix the import) to restore parity.\n")
        return 0

    if not failures:
        print("import audit: all warden.* modules import cleanly")
        return 0
    print(f"import audit: {len(failures)} module(s) failed to import\n")
    for name, cause in sorted(failures.items()):
        print(f"SKIP {name}\n     -> {cause}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
