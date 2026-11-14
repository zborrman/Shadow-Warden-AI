"""
Ratchet: no read route answers an anonymous caller unless it is on the list.

``test_anonymous_write_probe.py`` covers POST/PUT/PATCH/DELETE. Nothing covered
GET, and the first time anyone measured (security audit, 2026-11-14) 67 read
routes answered 2xx with no credentials - the unpatched-CVE feed, open pentest
findings, the healer's state, any tenant's compliance frameworks, any tenant's
subscription plan and the customer-portal URL that manages it. Twenty-five of
those were closed in the change that added this file; the 42 that remain are
public on purpose and each says why in ``anonymous_read_baseline.json``.

The measurement reuses the write probe's child process and environment, for
the reasons that module documents (a same-process run mounts routers empty and
reports a clean bill of health it has not earned). The child gives every
request a deadline, because one streaming route never returns.
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

from warden.tests.test_anonymous_write_probe import (
    _CANONICAL_ENV,
    _CHILD,
    _ESSENTIAL_ENV,
    _REPO_ROOT,
)

_BASELINE = Path(__file__).with_name("anonymous_read_baseline.json")

# Closed on 2026-11-14. Listed so a revert fails here, by name.
_CLOSED = (
    "GET /security/posture", "GET /security/cve-feed", "GET /security/pentest",
    "GET /security/compliance", "GET /soc/healer", "GET /soc/metrics",
    "GET /soc/posture", "GET /community/feed", "GET /community/members",
    "GET /compliance/frameworks/{tenant_id}", "GET /compliance/smb-report",
    "GET /compliance/hipaa", "GET /compliance/nis2", "GET /kya/list",
    "GET /streams/state/{community_id}", "GET /api/stats",
    "GET /sep/model-bundles", "GET /marketplace/escrows",
    "GET /marketplace/autonomy/{agent_id}", "GET /marketplace/maestro/flags",
    "GET /marketplace/agents/{agent_id}/maestro-report",
    "GET /obsidian/feed", "GET /obsidian/reputation",
    "GET /subscription/status", "GET /subscription/portal",
)

_measured: dict[str, int] | None = None


def _measure() -> dict[str, int]:
    global _measured
    if _measured is not None:
        return _measured
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = {k: os.environ[k] for k in _ESSENTIAL_ENV if k in os.environ}
    env.update(_CANONICAL_ENV)
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
            [sys.executable, str(_CHILD), out_path, "read"],
            capture_output=True, text=True, timeout=900,
            cwd=str(_REPO_ROOT), env=env,
        )
        if proc.returncode != 0:
            pytest.fail(f"anonymous-read probe subprocess failed:\n{proc.stderr[-3000:]}")
        _measured = json.loads(Path(out_path).read_text(encoding="utf-8"))
        return _measured
    finally:
        with contextlib.suppress(OSError):
            os.unlink(out_path)


def _baseline() -> dict:
    return json.loads(_BASELINE.read_text(encoding="utf-8"))


def _answers(measured: dict[str, int]) -> set[str]:
    return {r for r, st in measured.items() if 200 <= st < 300}


def _inconclusive(measured: dict[str, int]) -> set[str]:
    return {
        r for r, st in measured.items()
        if not (200 <= st < 300) and st not in (401, 403)
    }


def test_measurement_is_not_vacuous():
    measured = _measure()
    assert len(measured) > 300, (
        f"Only {len(measured)} read routes probed - the app mounted partially, "
        "so a pass here would measure nothing."
    )
    refused = sum(1 for st in measured.values() if st in (401, 403))
    assert refused > 250, (
        f"Only {refused} read routes refused an anonymous caller; auth is not "
        "really enabled in the probe."
    )


def test_no_new_read_route_answers_anonymously():
    baseline = set(_baseline()["answers_anonymously"])
    regressions = sorted(_answers(_measure()) - baseline)
    assert not regressions, (
        "Read route(s) now answer a caller with no credentials:\n  "
        + "\n  ".join(regressions)
        + "\n\nAdd an authentication dependency. If the route is meant to be "
          "public, add it to warden/tests/anonymous_read_baseline.json with the "
          "reason - a rate limiter or a feature gate authenticates nobody."
    )


def test_no_new_inconclusive_read_route():
    baseline = set(_baseline()["inconclusive"])
    regressions = sorted(_inconclusive(_measure()) - baseline)
    assert not regressions, (
        "Read route(s) answered an anonymous caller with neither 2xx nor 401/403, "
        "so the handler may have run:\n  " + "\n  ".join(regressions)
        + "\n\nGate each one, or record in anonymous_read_baseline.json why it "
          "is reachable."
    )


def test_the_reads_closed_on_2026_11_14_stay_closed():
    measured = _measure()
    reopened = sorted(r for r in _CLOSED if measured.get(r) not in (401, 403))
    assert not reopened, (
        "Read route(s) closed by the 2026-11-14 security audit answer an "
        "anonymous caller again (or have vanished from the app):\n  "
        + "\n  ".join(f"{r} -> {measured.get(r)}" for r in reopened)
    )


def test_every_baseline_entry_has_a_reason():
    baseline = _baseline()
    for section in ("answers_anonymously", "inconclusive"):
        missing = sorted(r for r, why in baseline[section].items() if len(str(why)) < 20)
        assert not missing, f"{section}: entries with no real reason: {missing}"


def test_baseline_has_not_gone_stale():
    measured = _measure()
    baseline = _baseline()
    stale_open = sorted(set(baseline["answers_anonymously"]) - _answers(measured))
    stale_inc = sorted(set(baseline["inconclusive"]) - _inconclusive(measured))
    assert not (stale_open or stale_inc), (
        "Baseline entries no longer reproduce - remove them:\n  answers_anonymously: "
        + ", ".join(stale_open) + "\n  inconclusive: " + ", ".join(stale_inc)
    )
