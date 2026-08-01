"""
warden/tests/test_marketplace_route_auth.py — MP-1a ratchet.

Marketplace rule #23: every write route under the marketplace cluster carries an
authentication dependency. This test freezes the set of routes that do NOT, so
the set can only ever shrink.

Why a ratchet and not a flat assertion: a handful of routes are open on purpose
(first-contact M2M registration) and a further 14 are open pending MP-8. A flat
"everything must be authed" assertion would have to be skipped, which protects
nothing. A may-only-shrink baseline lets the known-open set stay visible and
fails the moment a *new* unauthenticated write route appears.

Enumeration mirrors ``test_route_inventory.py`` exactly, and for the same two
reasons:

  * Under starlette>=1.0 ``include_router()`` leaves a ``_IncludedRouter``
    placeholder instead of expanding sub-routes into ``app.routes``. A naive
    walk sees ~129 routes where the real surface is ~657 — an audit that misses
    this undercounts by roughly 80% and reports a clean bill of health.
  * The measurement runs in a **fresh subprocess** with a canonical, deploy-like
    env. Under the polluted pytest env an import-ordering cycle grabs some
    routers (marketplace among them) mid-import and mounts them empty, which
    would make this test measure nothing and pass vacuously.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Prefixes owned by the marketplace cluster (Track M).
_PREFIXES = ("/marketplace", "/m2m-store", "/business-community/commerce", "/acp", "/a2a", "/payments")

_WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# ── Baseline: write routes known to carry NO auth dependency ──────────────────
# This set MAY ONLY SHRINK. Adding to it requires a documented reason here.
_KNOWN_OPEN: frozenset[str] = frozenset({
    # Stage 1 of the advertised M2M first-contact protocol: the caller has no
    # relationship with us yet, so there is no credential it could present.
    # Gating these is a protocol change, not a bug fix — owner decision D-5 in
    # docs/marketplace-modernization-plan.md. Registration abuse is SybilGuard's
    # job (marketplace rule #4).
    "POST /marketplace/register",
    "POST /marketplace/agents/register",

    # Verifies a caller-supplied PEM and mutates nothing. POST only because it
    # takes a body.
    "POST /marketplace/certificates/verify",

    # Admin-gated in-handler via X-Admin-Key rather than by a dependency, so the
    # dependency scan below cannot see it. MP-1c makes that check fail closed.
    "POST /marketplace/agents/{agent_id}/kya/revoke",

    # Inbound payment-provider callback. An API key is the wrong control here —
    # an external provider cannot hold ours — and AP2 does not currently send a
    # signature to verify. It is safe only because the handler is inert: it logs
    # and changes no state, so a forged call achieves nothing beyond a log line.
    # Before it may settle an order, mark it paid or release escrow it needs a
    # real signature check keyed via resolve_key(..., purpose=...), rejecting
    # unconditionally when the key will not resolve. See the comment on the
    # handler itself.
    "POST /business-community/commerce/webhooks/ap2",
})

# Dependency callables that constitute authentication. A rate limiter and a
# feature/plan gate are deliberately NOT in this list — see MP-0. Note a
# feature gate may still *deny* an anonymous caller as a side effect of tier
# resolution (measured: /acp/* returns 403 anonymously because the feature is
# above the default tier). That is not authentication: it establishes no
# identity, so the handler still cannot tell one entitled tenant from another,
# and an entitlement change would silently become an access change.
_AUTH_CALLABLES = ("require_api_key", "require_ext_auth", "_require_admin")

_CHILD = r'''
import json, logging, sys
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
import warden.main as m

PREFIXES = tuple(json.loads(sys.argv[2]))
AUTH = tuple(json.loads(sys.argv[3]))
rows = {}

def _auth_names(route):
    names = set()
    def walk(deps):
        for dc in deps:
            call = getattr(dc, "call", None)
            n = getattr(call, "__name__", None)
            if n:
                names.add(n)
            walk(getattr(dc, "dependencies", []) or [])
    dep = getattr(route, "dependant", None)
    walk(getattr(dep, "dependencies", []) or [])
    return names

def _record(route, prefix=""):
    if type(route).__name__ == "_IncludedRouter":
        ctx = getattr(route, "include_context", None)
        sub = getattr(ctx, "prefix", "") or ""
        orig = getattr(route, "original_router", None)
        if orig is not None:
            for child in orig.routes:
                _record(child, prefix + sub)
        return
    endpoint = getattr(route, "endpoint", None)
    path = getattr(route, "path", None)
    if endpoint is None and getattr(route, "routes", None):
        for child in route.routes:
            _record(child, prefix)
        return
    if not path:
        return
    full = prefix + path
    if not full.startswith(PREFIXES):
        return
    names = _auth_names(route)
    authed = any(a in names for a in AUTH)
    for meth in (getattr(route, "methods", None) or set()):
        if meth in ("HEAD", "OPTIONS"):
            continue
        rows[meth + " " + full] = authed

for route in m.app.routes:
    _record(route)

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(rows, fh)
'''

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

_CANONICAL_ENV = {
    "ANTHROPIC_API_KEY": "",
    "WARDEN_API_KEY": "",
    "ALLOW_UNAUTHENTICATED": "true",
    "REDIS_URL": "memory://",
    "SEMANTIC_THRESHOLD": "0.72",
    "IMAGE_GUARD_ENABLED": "false",
    "PROMETHEUS_METRICS_ENABLED": "false",
}


def _measure() -> dict[str, bool]:
    """Return {"<METHOD> <path>": is_authenticated} for the cluster, pollution-immune."""
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = {k: os.environ[k] for k in _ESSENTIAL_ENV if k in os.environ}
    env.update(_CANONICAL_ENV)
    tmp = Path(tempfile.gettempdir())
    env["MODEL_CACHE_DIR"] = os.environ.get("MODEL_CACHE_DIR", str(tmp / "warden_mra_models"))
    for var in ("LOGS_PATH", "DYNAMIC_RULES_PATH"):
        env[var] = os.environ.get(var, str(tmp / f"warden_mra_{var.lower()}"))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, out_path,
             json.dumps(list(_PREFIXES)), json.dumps(list(_AUTH_CALLABLES))],
            capture_output=True, text=True, timeout=600,
            cwd=str(_REPO_ROOT), env=env,
        )
        if proc.returncode != 0:
            pytest.fail(f"route-auth measurement subprocess failed:\n{proc.stderr[-3000:]}")
        return json.loads(Path(out_path).read_text(encoding="utf-8"))
    finally:
        with __import__("contextlib").suppress(OSError):
            os.unlink(out_path)


def _open_writes(measured: dict[str, bool]) -> set[str]:
    return {
        route for route, authed in measured.items()
        if not authed and route.split(" ", 1)[0] in _WRITE_METHODS
    }


def test_measurement_is_not_vacuous():
    """Guard the guard: if the app mounts empty, every other assertion passes for free."""
    measured = _measure()
    assert len(measured) > 50, (
        f"Only {len(measured)} cluster routes measured — the app almost certainly "
        "mounted empty, which would make this ratchet pass vacuously."
    )
    assert any(authed for authed in measured.values()), "No authenticated route found at all."


def test_no_new_unauthenticated_marketplace_write_route():
    """MP-1a ratchet: the set of unauthenticated write routes may only shrink."""
    regressions = sorted(_open_writes(_measure()) - _KNOWN_OPEN)
    assert not regressions, (
        "New unauthenticated marketplace write route(s) detected:\n  "
        + "\n  ".join(regressions)
        + "\n\nEvery write route in the marketplace cluster must depend on "
          "require_api_key (marketplace/CLAUDE.md rule #23). Note that "
          "marketplace_rate_limit is a rate limiter and billing feature_gate is "
          "an entitlement gate — neither authenticates anyone. If a route is "
          "genuinely meant to be public, add it to _KNOWN_OPEN with a reason."
    )


def test_known_open_baseline_has_not_gone_stale():
    """A route that got fixed must be removed from the baseline, so it cannot silently reopen."""
    stale = sorted(_KNOWN_OPEN - _open_writes(_measure()))
    assert not stale, (
        "These routes are listed in _KNOWN_OPEN but are now authenticated (or gone):\n  "
        + "\n  ".join(stale)
        + "\n\nRemove them from the baseline — that is what makes this a ratchet."
    )
