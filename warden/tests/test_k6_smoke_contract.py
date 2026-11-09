"""The post-deploy k6 job must be able to fail, and must test routes that exist.

For weeks this job reported success while 75% of its requests failed: one route
did not exist, a secret was never set, and two separate things hid the result.
"""
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "k6" / "smoke_test.js").read_text(encoding="utf-8")


def _run_step() -> dict:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["k6-smoke"]["steps"]
    return next(s for s in steps if s.get("name") == "Run k6 smoke test")


def test_every_route_in_the_smoke_test_exists():
    inventory = json.loads(
        (ROOT / "warden/tests/fixtures/route_inventory.json").read_text(encoding="utf-8")
    )
    known = {route for routes in inventory.values() for route in routes}
    calls = re.findall(r"http\.(get|post)\(\s*`\$\{BASE_URL\}([^`?]+)", SCRIPT)
    assert calls, "no requests found: the pattern no longer matches the script"
    missing = sorted(
        f"{method.upper()} {path}"
        for method, path in calls
        if f"{method.upper()} {path}" not in known
    )
    assert not missing, f"smoke test calls routes the gateway does not have: {missing}"


def test_a_failed_smoke_run_fails_the_job():
    step = _run_step()
    assert "continue-on-error" not in step
    # The default `bash -e` has no pipefail, so `k6 run ... | tee` would pass.
    assert "| tee" not in step["run"] or step.get("shell") == "bash"


def test_ci_needs_no_production_key():
    step = _run_step()
    assert "WARDEN_API_KEY" not in step.get("env", {})
    assert "WARDEN_API_KEY" not in step["run"]


def test_correctness_checks_are_a_threshold():
    # k6 does not fail a run on a failed check() unless a threshold says so.
    assert re.search(r'"checks\{gate:yes\}":\s*\["rate == 1"\]', SCRIPT)
    assert "canary.missed" in SCRIPT
