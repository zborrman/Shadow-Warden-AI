"""
warden/tests/test_route_inventory.py
──────────────────────────────────────
Phase-3 safety net: an OpenAPI/route-inventory guard.

Dissolving warden/main.py means moving inline @app routes into warden/api/*
routers. A *move* must never change the app's externally-visible surface — same
paths, same methods. This test snapshots the ``(method, path)`` set and fails if
any route is added, removed, or renamed.

Clean-import measurement
────────────────────────
The route surface is measured in a FRESH subprocess (`import warden.main`), not
from the in-process app. Running inside the full pytest suite, thousands of
earlier tests mutate global state / sys.modules, which can leave a conditional
router (mounted in main.py under try/except) unimportable — so the in-process
``app`` no longer reflects what a clean deploy actually serves. The subprocess
measures the true deployable surface, immune to that pollution.

Environment tolerance
─────────────────────
Many routers mount conditionally and are skipped when an *optional* dependency is
missing. CI installs a leaner set than a full dev machine, so a subsystem present
locally may be absent in CI. The fixture is grouped by the module that defines
each endpoint (``endpoint.__module__``); the guard tolerates a whole module being
absent this run, still fails on any route added/removed/renamed within a module
that IS mounted, and stays move-invisible (a relocated path keeps its
``METHOD PATH`` string).

Regenerate on a machine with the FULL dependency set (a superset of every CI
environment):

  UPDATE_ROUTE_INVENTORY=1 pytest warden/tests/test_route_inventory.py

A pure route *move* still produces an EMPTY diff.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_FIXTURE = Path(__file__).parent / "fixtures" / "route_inventory.json"
_REPO_ROOT = Path(__file__).resolve().parents[2]

# Child program: import the app cleanly and dump {endpoint_module: [ "METHOD PATH" ]}.
_CHILD = r"""
import json, sys
import warden.main as m

groups = {}
for route in m.app.routes:
    path = getattr(route, "path", None)
    if not path:
        continue
    endpoint = getattr(route, "endpoint", None)
    module = getattr(endpoint, "__module__", None) or "__core__"
    methods = getattr(route, "methods", None) or {"WS"}
    for meth in methods:
        if meth in ("HEAD", "OPTIONS"):
            continue
        groups.setdefault(module, set()).add(f"{meth} {path}")

out = {mod: sorted(routes) for mod, routes in groups.items()}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(out, fh)
"""


def _current_groups() -> dict[str, list[str]]:
    """Measure the route surface in a fresh subprocess (pollution-immune)."""
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_REPO_ROOT), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, out_path],
            capture_output=True, text=True, timeout=600,
            cwd=str(_REPO_ROOT), env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "route-inventory child failed to import warden.main "
                f"(rc={proc.returncode}).\nSTDERR tail:\n{proc.stderr[-2000:]}"
            )
        data = json.loads(Path(out_path).read_text(encoding="utf-8"))
    finally:
        with contextlib.suppress(OSError):
            os.unlink(out_path)
    return {mod: sorted(routes) for mod, routes in sorted(data.items())}


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
