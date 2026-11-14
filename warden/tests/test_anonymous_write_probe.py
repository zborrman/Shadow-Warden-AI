"""
R0 exit-criterion ratchet: no write route answers an anonymous caller.

The M2M reconstruction's stage R0 ("close what is live") has one falsifiable
exit condition: an anonymous probe over every write route returns only 401/403
or something on an explicitly allowed list. This module *is* that probe, kept
as a test so the condition is re-measured on every push instead of once.

Two things make a naive version of this test pass while measuring nothing, and
both have happened in this repo before:

  * **A 422 is not a refusal.** It proves validation rejected the payload
    before the handler ran. The 2026-07-29 audit took 78 such routes for a
    clean bill of health; re-probed with bodies synthesised from each route's
    own OpenAPI schema, 26 of them executed fully for an anonymous caller. The
    child process therefore builds a minimal valid body per route.
  * **The measurement must not run in the pytest process.** Under the polluted
    test env an import-ordering cycle grabs some routers mid-import and mounts
    them empty, and under starlette>=1.0 ``include_router()`` leaves a
    placeholder in ``app.routes``. Either one silently shrinks the surface
    under test. The child runs in a fresh subprocess with a canonical,
    deploy-like environment - the same construction as
    ``test_marketplace_route_auth.py``.

``ADMIN_KEY`` is set in that environment on purpose: without it the admin
routes answer 503 "not configured", which masks whether they are gated at all.

The baseline carries a reason per entry. Shrinking it is the work; growing it
is the regression. Two entries were removed when this file landed:
``POST /slack/command`` (its signature check returned True whenever
SLACK_SIGNING_SECRET was unset - and that secret reaches no container, so every
anonymous caller verified, including ``/warden approve`` on the MasterAgent
human-in-the-loop gate) and ``POST /compliance/evidence/generate`` (no auth
dependency at all, with ``tenant_id`` a query parameter defaulting to
"default", so any caller exported any tenant's SOC 2 evidence bundle).
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHILD = Path(__file__).with_name("_anonymous_write_probe_child.py")
_BASELINE = Path(__file__).with_name("anonymous_write_baseline.json")

_ESSENTIAL_ENV = (
    "PATH", "PATHEXT", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
    "USER", "USERNAME", "LOGNAME", "LNAME",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "PYTHONHOME", "VIRTUAL_ENV",
    "CONDA_PREFIX", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "pythonLocation", "Python_ROOT_DIR", "Python3_ROOT_DIR",
)

_CANONICAL_ENV = {
    "ANTHROPIC_API_KEY": "",
    "ALLOW_UNAUTHENTICATED": "false",
    "REDIS_URL": "memory://",
    "SEMANTIC_THRESHOLD": "0.72",
    "IMAGE_GUARD_ENABLED": "false",
    "PROMETHEUS_METRICS_ENABLED": "false",
    # Set so admin routes answer 401/403 instead of 503 "not configured",
    # which would hide whether they carry a gate at all.
    "ADMIN_KEY": "r0-probe-admin",
    # VAULT_MASTER_KEY is generated per run in _measure(). A literal Fernet key
    # here is indistinguishable from a real one to a secret scanner, and
    # gitleaks duly failed the build on it.
}

_measured: dict[str, int] | None = None


def _measure() -> dict[str, int]:
    """Return {"<METHOD> <path>": status_code}, measured once per session."""
    global _measured
    if _measured is not None:
        return _measured
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = {k: os.environ[k] for k in _ESSENTIAL_ENV if k in os.environ}
    env.update(_CANONICAL_ENV)
    # A valid Fernet key, generated per run: several routes resolve signing
    # material at call time and answer 503 without it, which would hide whether
    # they are gated at all. Generated rather than written down so no literal
    # that looks like a key lives in the repo.
    env["VAULT_MASTER_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    env["PYTHONPATH"] = str(_REPO_ROOT)
    tmp = Path(tempfile.gettempdir())
    env["WARDEN_DATA_DIR"] = str(tmp / "warden_anon_probe_data")
    env["MODEL_CACHE_DIR"] = os.environ.get(
        "MODEL_CACHE_DIR", str(tmp / "warden_anon_probe_models")
    )
    env["LOGS_PATH"] = str(tmp / "warden_anon_probe_logs.json")
    env["DYNAMIC_RULES_PATH"] = str(tmp / "warden_anon_probe_rules.json")
    try:
        proc = subprocess.run(
            [sys.executable, str(_CHILD), out_path],
            capture_output=True, text=True, timeout=900,
            cwd=str(_REPO_ROOT), env=env,
        )
        if proc.returncode != 0:
            pytest.fail(f"anonymous-write probe subprocess failed:\n{proc.stderr[-3000:]}")
        _measured = json.loads(Path(out_path).read_text(encoding="utf-8"))
        return _measured
    finally:
        with contextlib.suppress(OSError):
            os.unlink(out_path)


def _baseline() -> dict:
    return json.loads(_BASELINE.read_text(encoding="utf-8"))


def _executes(measured: dict[str, int]) -> set[str]:
    return {r for r, st in measured.items() if 200 <= st < 300}


def _inconclusive(measured: dict[str, int]) -> set[str]:
    return {
        r for r, st in measured.items()
        if not (200 <= st < 300) and st not in (401, 403)
    }


def test_measurement_is_not_vacuous():
    """Guard the guard: an app that mounts empty makes every other assertion free."""
    measured = _measure()
    assert len(measured) > 300, (
        f"Only {len(measured)} write routes probed. The app almost certainly mounted "
        "partially, which would make this ratchet pass without measuring anything."
    )
    refused = sum(1 for st in measured.values() if st in (401, 403))
    assert refused > 200, (
        f"Only {refused} write routes refused an anonymous caller. Auth is not actually "
        "enabled in the probe, so a pass here would mean nothing."
    )


def test_no_new_write_route_executes_anonymously():
    """The set of write routes that run for a caller with no credentials may only shrink."""
    baseline = set(_baseline()["executes_anonymously"])
    regressions = sorted(_executes(_measure()) - baseline)
    assert not regressions, (
        "Write route(s) now execute for an anonymous caller:\n  "
        + "\n  ".join(regressions)
        + "\n\nAdd an authentication dependency. If the route is genuinely meant to be "
          "public, add it to warden/tests/anonymous_write_baseline.json with a reason - "
          "and note that a rate limiter or a feature gate authenticates nobody."
    )


def test_no_new_inconclusive_write_route():
    """Routes that neither execute nor refuse may only shrink.

    These answered 4xx/5xx for reasons other than credentials, so the handler
    may well have run. They are not a clean bill of health - see the reason on
    each baseline entry.
    """
    baseline = set(_baseline()["inconclusive"])
    regressions = sorted(_inconclusive(_measure()) - baseline)
    assert not regressions, (
        "Write route(s) answered an anonymous caller with neither 2xx nor 401/403:\n  "
        + "\n  ".join(regressions)
        + "\n\nEach needs a decision: gate it, or record in "
          "warden/tests/anonymous_write_baseline.json why it is reachable."
    )


def test_the_two_routes_this_ratchet_closed_stay_closed():
    """Pin the fixes, so a revert fails here rather than in six months.

    Both were live: /slack/command accepted every anonymous POST because its
    signature check returned True when SLACK_SIGNING_SECRET was unset (and that
    variable is passed to no container), and /compliance/evidence/generate had
    no auth dependency while every sibling in its own router does.
    """
    measured = _measure()
    assert measured.get("POST /slack/command") in (403, 503), (
        "POST /slack/command answered "
        f"{measured.get('POST /slack/command')} anonymously. Its signature check must "
        "fail CLOSED: 503 without a signing secret, 403 on a bad signature."
    )
    assert measured.get("POST /compliance/evidence/generate") == 401, (
        "POST /compliance/evidence/generate answered "
        f"{measured.get('POST /compliance/evidence/generate')} anonymously. It exports a "
        "tenant's SOC 2 evidence bundle and must require a key."
    )


def test_baseline_has_not_gone_stale():
    """An entry that no longer reproduces should be deleted, not left as cover."""
    measured = _measure()
    baseline = _baseline()
    stale_open = sorted(set(baseline["executes_anonymously"]) - _executes(measured))
    stale_inc = sorted(set(baseline["inconclusive"]) - _inconclusive(measured))
    assert not (stale_open or stale_inc), (
        "Baseline entries no longer reproduce - remove them so the file keeps "
        "describing the real surface:\n  executes_anonymously: "
        + ", ".join(stale_open) + "\n  inconclusive: " + ", ".join(stale_inc)
    )
