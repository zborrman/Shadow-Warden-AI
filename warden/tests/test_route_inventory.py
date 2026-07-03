"""
warden/tests/test_route_inventory.py
──────────────────────────────────────
Phase-3 safety net: an OpenAPI/route-inventory guard.

Dissolving warden/main.py means moving 92 inline @app routes into warden/api/*
routers. A *move* must never change the app's externally-visible surface — same
paths, same methods. This test snapshots the full ``(method, path)`` set to a
committed fixture and fails if any route is added, removed, or renamed.

Workflow when intentionally changing routes:
  1. Make the change.
  2. Run: ``UPDATE_ROUTE_INVENTORY=1 pytest warden/tests/test_route_inventory.py``
     to regenerate the fixture.
  3. Review the fixture diff in the PR — it is the human-readable "OpenAPI diff".

A pure route *move* (Phase 3) should produce an EMPTY fixture diff.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_FIXTURE = Path(__file__).parent / "fixtures" / "route_inventory.json"


def _current_routes() -> list[str]:
    """Return sorted 'METHOD PATH' strings for every mounted route."""
    from warden.main import app

    seen: set[str] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        if not path:
            continue
        methods = getattr(route, "methods", None) or {"WS"}
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            seen.add(f"{m} {path}")
    return sorted(seen)


def test_route_inventory_unchanged():
    current = _current_routes()

    if os.getenv("UPDATE_ROUTE_INVENTORY") == "1" or not _FIXTURE.exists():
        _FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        _FIXTURE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_ROUTE_INVENTORY") == "1":
            return  # explicit regeneration — nothing to assert

    baseline = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    cur_set, base_set = set(current), set(baseline)
    added = sorted(cur_set - base_set)
    removed = sorted(base_set - cur_set)
    assert not added and not removed, (
        "Route surface changed — a Phase-3 move must not alter routes.\n"
        f"  ADDED:   {added}\n"
        f"  REMOVED: {removed}\n"
        "If intentional, regenerate: UPDATE_ROUTE_INVENTORY=1 pytest "
        "warden/tests/test_route_inventory.py"
    )
