"""
warden/tests/test_marketplace_auth_actually_denies.py — Hook.md H-9.

`test_marketplace_route_auth.py` proves `require_api_key` is **wired** to every
marketplace write route. It inspects dependency callables; it never sends a
request. Wiring and enforcement are different claims, and three of the four
anti-patterns in `Rule.md` §29.1 are precisely a control that is present and
permits everyone.

The gap was wider than that. The documented way to run this suite — in
`warden/marketplace/CLAUDE.md`, in `Hook.md` §5, and in `conftest.py` — sets

    WARDEN_API_KEY=""  ALLOW_UNAUTHENTICATED=true

and `require_api_key` reads module-level `_VALID_KEY` / `_KEYS_PATH`, resolved
at import. With both empty it returns `AuthResult(tenant_id="default")` for
every caller, header or no header. **So the entire marketplace suite runs with
the guard it depends on switched off**, and no test anywhere had ever seen it
refuse anybody.

This file configures a real key and sends three requests. It does not need to
cover every route — it needs to prove the mechanism denies at all, which
nothing did.

Run in a subprocess for the same reason `test_marketplace_route_auth.py` is:
under the polluted pytest env an import-ordering cycle mounts some routers
empty. Here it matters twice over, because `_VALID_KEY` is bound at import and
cannot be changed afterwards by setting an environment variable.
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

#: A protected write route with a body, so the authenticated case is decided by
#: validation rather than by anything that touches a database.
_ROUTE = "/marketplace/action"

_KEY = "h9-configured-key-not-a-real-credential"

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

#: The point of the file: a key is configured and the escape hatch is shut.
_ENFORCING_ENV = {
    "ANTHROPIC_API_KEY": "",
    "WARDEN_API_KEY": _KEY,
    "ALLOW_UNAUTHENTICATED": "false",
    "REDIS_URL": "memory://",
    "SEMANTIC_THRESHOLD": "0.72",
    "IMAGE_GUARD_ENABLED": "false",
    "PROMETHEUS_METRICS_ENABLED": "false",
}

_CHILD = r'''
import json, logging, sys
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

from fastapi.testclient import TestClient
import warden.main as m
import warden.auth_guard as ag

out_path, route, key = sys.argv[1], sys.argv[2], sys.argv[3]

# Fail loudly rather than measuring nothing: if the key did not reach the
# module, every case below would pass for the wrong reason.
if not ag._VALID_KEY:
    json.dump({"error": "WARDEN_API_KEY did not reach auth_guard._VALID_KEY"},
              open(out_path, "w"))
    sys.exit(0)

body = {"action_type": "not-a-valid-action", "payload": {}}
client = TestClient(m.app, raise_server_exceptions=False)

def call(headers):
    r = client.post(route, json=body, headers=headers)
    return r.status_code

json.dump({
    "missing": call({}),
    "wrong":   call({"X-API-Key": "definitely-not-the-key"}),
    "right":   call({"X-API-Key": key}),
}, open(out_path, "w"))
'''


@pytest.fixture(scope="module")
def statuses() -> dict:
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = {k: os.environ[k] for k in _ESSENTIAL_ENV if k in os.environ}
    env.update(_ENFORCING_ENV)
    tmp = Path(tempfile.gettempdir())
    env["MODEL_CACHE_DIR"] = os.environ.get("MODEL_CACHE_DIR", str(tmp / "warden_h9_models"))
    for var in ("LOGS_PATH", "DYNAMIC_RULES_PATH"):
        env[var] = str(tmp / f"warden_h9_{var.lower()}")
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, out_path, _ROUTE, _KEY],
            capture_output=True, text=True, timeout=600,
            cwd=str(_REPO_ROOT), env=env,
        )
        if proc.returncode != 0:
            pytest.fail(f"auth-enforcement subprocess failed:\n{proc.stderr[-3000:]}")
        data = json.loads(Path(out_path).read_text(encoding="utf-8"))
    finally:
        with __import__("contextlib").suppress(OSError):
            os.unlink(out_path)

    if "error" in data:
        pytest.fail(data["error"])
    return data


def test_the_route_under_test_is_really_mounted(statuses: dict):
    """Guards the measurement: a 404 everywhere would make the rest vacuous.

    Existence is read from the responses, not from `app.routes`. That attribute
    does **not** flatten included routers, which is how a shadowed duplicate
    once left `/ws/events` unauthenticated — an introspection that answers
    "absent" for a mounted route is a worse guard than none.
    """
    assert set(statuses.values()) != {404}, f"{_ROUTE} answered 404 to everything"
    assert statuses["missing"] != 404


def test_a_request_with_no_key_is_refused(statuses: dict):
    assert statuses["missing"] == 401, (
        f"A configured key must refuse an anonymous caller; got {statuses['missing']}. "
        "This is the assertion the suite never made: every other marketplace test "
        'runs with WARDEN_API_KEY="", where require_api_key returns a default '
        "AuthResult for everyone."
    )


def test_a_request_with_the_wrong_key_is_refused(statuses: dict):
    assert statuses["wrong"] == 401, (
        f"A wrong key must be refused, not merely absent-checked; got {statuses['wrong']}."
    )


def test_the_configured_key_is_accepted(statuses: dict):
    """The other half. A gate that refuses everyone is not enforcement either —
    it is an outage, and it would pass both assertions above.

    422 is the expected answer: the body is deliberately invalid, so auth ran,
    passed, and validation rejected the payload without touching a database.
    """
    assert statuses["right"] != 401, (
        "The configured key was refused. A gate that denies its own credential "
        "passes the two tests above while protecting nothing anyone can use."
    )
    assert statuses["right"] == 422, (
        f"Expected validation to reject the invalid body once authenticated; "
        f"got {statuses['right']}."
    )
