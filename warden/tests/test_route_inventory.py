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

# Captured conditional-router fallback warnings from the last child import.
_child_diag: list[str] = []

# Child program: import the app cleanly and dump {endpoint_module: [ "METHOD PATH" ]}.
_CHILD = r"""
import json, logging, sys, traceback
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

# One-off: trace the marketplace include to see if its router is empty at
# include time (partial import) and what stack triggered it.
import fastapi as _f
_orig_inc = _f.FastAPI.include_router
def _traced_inc(self, router, *a, **k):
    try:
        pfx = getattr(router, "prefix", "") or k.get("prefix", "")
        rc = len(getattr(router, "routes", []) or [])
        if "marketplace" in str(pfx) or rc == 0:
            print(f"INCLUDE prefix={pfx!r} routes={rc}", file=sys.stderr)
            if rc == 0 and "marketplace" in str(pfx):
                print("STACK>>>\n" + "".join(traceback.format_stack()) + "<<<STACK", file=sys.stderr)
    except Exception as _e:
        print(f"INCLUDE trace error {_e!r}", file=sys.stderr)
    return _orig_inc(self, router, *a, **k)
_f.FastAPI.include_router = _traced_inc

import warden.main as m

# One-off structural probe: show any app.route that is not a plain APIRoute, plus
# whether marketplace paths exist anywhere, to locate the 25 "lost" routes.
try:
    _mkt = [str(getattr(r, "path", "")) for r in m.app.routes if "marketplace" in str(getattr(r, "path", ""))]
    print(f"STRUCT app.routes total={len(m.app.routes)} marketplace_paths={len(_mkt)}", file=sys.stderr)
    for r in m.app.routes:
        tn = type(r).__name__
        if tn not in ("APIRoute", "Route"):
            print(f"STRUCT container type={tn} path={getattr(r,'path','?')!r} "
                  f"has_routes={hasattr(r,'routes')} has_app={hasattr(r,'app')} "
                  f"nroutes={len(getattr(r,'routes',[]) or [])}", file=sys.stderr)
    print(f"STRUCT sample_mkt={_mkt[:3]}", file=sys.stderr)
except Exception as _e:
    print(f"STRUCT error {_e!r}", file=sys.stderr)

groups = {}

def _record(route):
    # A nested container (_IncludedRouter from include_router of a prefixed
    # router, a known FastAPI v8.x behaviour) lacks .path but holds the real
    # APIRoutes in .routes — and those children already carry their FULL path.
    # Recurse into it; do not compose prefixes (children are absolute).
    endpoint = getattr(route, "endpoint", None)
    path = getattr(route, "path", None)
    if endpoint is None and getattr(route, "routes", None):
        for child in route.routes:
            _record(child)
        return
    if not path:
        return
    module = getattr(endpoint, "__module__", None) or "__core__"
    methods = getattr(route, "methods", None) or {"WS"}
    for meth in methods:
        if meth in ("HEAD", "OPTIONS"):
            continue
        groups.setdefault(module, set()).add(f"{meth} {path}")

for route in m.app.routes:
    _record(route)

out = {mod: sorted(routes) for mod, routes in groups.items()}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(out, fh)
"""

# OS/interpreter-critical env vars passed through to the child. Everything else
# is dropped so the measured import matches a clean deploy — NOT the polluted
# pytest env, where conftest/test-set vars trigger an import-ordering cycle that
# grabs some routers (e.g. marketplace) mid-import and mounts them empty.
_ESSENTIAL_ENV = (
    "PATH", "PATHEXT", "LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH",
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
    "USER", "USERNAME", "LOGNAME", "LNAME",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "PYTHONHOME", "VIRTUAL_ENV",
    "CONDA_PREFIX", "SSL_CERT_FILE", "SSL_CERT_DIR", "PKG_CONFIG_PATH",
    "pythonLocation", "Python_ROOT_DIR", "Python2_ROOT_DIR", "Python3_ROOT_DIR",
)

# Canonical, deploy-representative warden config for the measurement import.
_CANONICAL_ENV = {
    "ANTHROPIC_API_KEY": "",
    "WARDEN_API_KEY": "",
    "ALLOW_UNAUTHENTICATED": "true",
    "REDIS_URL": "memory://",
    "SEMANTIC_THRESHOLD": "0.72",
    "IMAGE_GUARD_ENABLED": "false",
    "PROMETHEUS_METRICS_ENABLED": "false",
}


def _current_groups() -> dict[str, list[str]]:
    """Measure the route surface in a fresh subprocess (pollution-immune)."""
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    # Minimal, deploy-representative env — pass through only OS/interpreter
    # essentials, then set canonical warden config. This avoids the pytest-env
    # import-ordering pollution that mounts some routers empty.
    env = {k: os.environ[k] for k in _ESSENTIAL_ENV if k in os.environ}
    env.update(_CANONICAL_ENV)
    # NB: do NOT set PYTHONPATH. Prepending the repo root reorders sys.path and
    # triggers a partial import of warden.marketplace.api (empty router mounted).
    # cwd=_REPO_ROOT already puts the repo on sys.path[0] for `python -c`, exactly
    # like the audit cold-import probe (which mounts marketplace correctly).
    env["MODEL_CACHE_DIR"] = os.environ.get("MODEL_CACHE_DIR", str(Path(tempfile.gettempdir()) / "warden_ri_models"))
    for _var in ("LOGS_PATH", "DYNAMIC_RULES_PATH"):
        env[_var] = os.environ.get(_var, str(Path(tempfile.gettempdir()) / f"warden_ri_{_var.lower()}"))
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
        # Capture any conditional-router fallback warnings the child emitted —
        # these name the dependency behind a skipped subsystem.
        blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
        _child_diag[:] = [
            line.strip()
            for line in blob.splitlines()
            if ("not available" in line or "router skipped" in line
                or "router FAILED" in line or "skipped:" in line or "STRUCT " in line)
            and ("warden" in line.lower() or "STRUCT " in line or "marketplace" in line)
        ]
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

    diag = "\n".join(f"    {line}" for line in _child_diag) or "    (none)"
    assert not added and not removed, (
        "Route surface changed — a Phase-3 move must not alter routes.\n"
        f"  ADDED:   {added}\n"
        f"  REMOVED: {removed}\n"
        "(Whole-module absences from missing optional deps are tolerated.)\n"
        f"  Conditional routers the clean import skipped:\n{diag}\n"
        "If intentional, regenerate on a full-dependency machine: "
        "UPDATE_ROUTE_INVENTORY=1 pytest warden/tests/test_route_inventory.py"
    )
