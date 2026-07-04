"""
warden/tests/test_route_inventory.py
──────────────────────────────────────
Phase-3 safety net: an OpenAPI/route-inventory guard.

Dissolving warden/main.py means moving inline @app routes into warden/api/*
routers. A *move* must never change the app's externally-visible surface — same
paths, same methods. This test snapshots the ``(method, path)`` set and fails if
any route is added, removed, or renamed.

Environment tolerance
─────────────────────
Many routers mount conditionally (``register_router_safe`` / inline try/except)
and are skipped when an *optional* dependency is missing. CI installs a leaner
dependency set than a full dev machine, so a subsystem present locally may be
absent in CI. That must NOT trip the guard — it is an environment difference,
not a route regression.

To stay robust *and* still catch real regressions, the fixture is grouped by the
Python module that defines each endpoint (``endpoint.__module__``). The guard:

  • tolerates a whole module being absent this run (its optional dep is missing)
  • still fails on any route added/removed/renamed within a module that IS mounted
  • stays move-invisible: a path relocated to a different module keeps the same
    ``METHOD PATH`` string, so it never appears as removed.

The fixture must be regenerated on a machine with the FULL dependency set (so it
is a superset of every CI environment):

  UPDATE_ROUTE_INVENTORY=1 pytest warden/tests/test_route_inventory.py

A pure route *move* (Phase 3) still produces an EMPTY diff.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_FIXTURE = Path(__file__).parent / "fixtures" / "route_inventory.json"


def _current_groups() -> dict[str, list[str]]:
    """Map ``endpoint module`` → sorted ``'METHOD PATH'`` strings for every route."""
    from warden.main import app

    groups: dict[str, set[str]] = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        if not path:
            continue
        endpoint = getattr(route, "endpoint", None)
        module = getattr(endpoint, "__module__", None) or "__core__"
        methods = getattr(route, "methods", None) or {"WS"}
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            groups.setdefault(module, set()).add(f"{m} {path}")
    return {mod: sorted(routes) for mod, routes in sorted(groups.items())}


def _write_fixture(groups: dict[str, list[str]]) -> None:
    _FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    _FIXTURE.write_text(json.dumps(groups, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_route_inventory_unchanged():
    current = _current_groups()

    if os.getenv("UPDATE_ROUTE_INVENTORY") == "1" or not _FIXTURE.exists():
        _write_fixture(current)
        if os.getenv("UPDATE_ROUTE_INVENTORY") == "1":
            return  # explicit regeneration — nothing to assert

    baseline = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(baseline, dict), (
        "route_inventory.json is in the legacy flat-list format. Regenerate with "
        "the full dependency set: UPDATE_ROUTE_INVENTORY=1 pytest "
        "warden/tests/test_route_inventory.py"
    )

    current_modules = set(current)
    current_flat = {r for routes in current.values() for r in routes}
    baseline_flat = {r for routes in baseline.values() for r in routes}
    # path → owning module, from the (full-dependency) baseline
    owner = {r: mod for mod, routes in baseline.items() for r in routes}

    added = sorted(current_flat - baseline_flat)

    # A vanished route is a real regression only if its owning module is still
    # mounted this run. If the whole module is absent, an optional dependency is
    # missing in this environment — tolerate it.
    removed = sorted(
        r
        for r in baseline_flat - current_flat
        if owner.get(r) in current_modules
    )

    assert not added and not removed, (
        "Route surface changed — a Phase-3 move must not alter routes.\n"
        f"  ADDED:   {added}\n"
        f"  REMOVED: {removed}\n"
        "(Whole-module absences from missing optional deps are tolerated.)\n"
        "If intentional, regenerate on a full-dependency machine: "
        "UPDATE_ROUTE_INVENTORY=1 pytest warden/tests/test_route_inventory.py"
    )
