"""warden/tests/test_smb_perimeter.py — OB-F22.

This is the enforcement half of `warden/hooks/smb_perimeter.py`. The logic lives
in the hook so pre-commit can run it locally; the gate lives here because CI
does not run pre-commit — `.github/workflows/ci.yml` has no pre-commit step, so
a hook-only guard is advisory, skippable with `--no-verify`, and therefore
exactly the kind of check that reports nothing.

What it protects, and why it is worth a test rather than a code review habit:

  * `docker-compose.smb.yml` published the Streamlit analytics dashboard on
    `8501:8501` — every interface. That dashboard reads the live `/filter`
    event stream, so it shows a customer's real security telemetry.
  * `warden/analytics/auth.py:63` treats an unset `DASHBOARD_PASSWORD_HASH` as
    dev mode and admits everyone, and the variable was named in neither the
    compose file nor `.env.smb.example`. An MSP following the example env file
    got an open panel with no hint a variable was missing.
  * `CONTRIBUTING.md:201` and `Hook.md:263` both described a `check-smb-compose`
    guard covering this file. It did not exist anywhere in the repo.

Our own production was never exposed this way (it runs the enterprise compose,
where the same app is behind `expose:` on 8502; `curl` to the origin on 8501
and 8502 timed out on 2026-09-04). The defect shipped to whoever deploys the
SMB profile, which is worse in one specific sense: we cannot see their host.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from warden.hooks.smb_perimeter import (
    PUBLIC_PORTS,
    REQUIRED_ENV_KEYS,
    check_no_enterprise_services,
    check_ports,
    check_required_env,
    run,
)

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / "docker-compose.smb.yml"


def test_the_smb_profile_perimeter_holds() -> None:
    """The whole guard, as a merge gate."""
    problems = run()
    assert not problems, (
        "The SMB profile ships to MSPs — a port published here is published on "
        "their host, and a variable absent from the example env file is a "
        "control they are never told to turn on:\n  "
        + "\n  ".join(problems)
    )


def test_only_the_gateway_api_is_meant_to_be_public() -> None:
    """Widening PUBLIC_PORTS should be a decision, not a side effect."""
    assert set(PUBLIC_PORTS) == {"8001"}, (
        f"PUBLIC_PORTS is now {sorted(PUBLIC_PORTS)}. 8001 is the gateway API — "
        "the product itself, which a customer's application must reach. Every "
        "other surface is for an operator and belongs behind loopback or a "
        "tunnel. Adding a port here exposes it on every MSP host; say in the PR "
        "which port, and why the operator cannot use a tunnel instead."
    )


def test_the_guard_catches_a_wide_open_port() -> None:
    """Guard the guard: a check that cannot fail is the thing being fixed."""
    assert check_ports('    ports:\n      - "8501:8501"\n'), (
        "check_ports() accepted a port published on every interface. The whole "
        "guard is then decorative."
    )
    assert not check_ports('    ports:\n      - "127.0.0.1:8501:8501"\n')
    assert not check_ports('    ports:\n      - "8001:8001"\n'), (
        "8001 is allow-listed as the gateway API and must not be flagged."
    )


def test_the_guard_catches_a_missing_control_variable() -> None:
    assert check_required_env("REDIS_URL=redis://redis:6379\n"), (
        "check_required_env() passed an env example with no "
        f"{REQUIRED_ENV_KEYS[0]}, which is how the open dashboard shipped."
    )
    assert not check_required_env("DASHBOARD_PASSWORD_HASH=\n")


def test_the_guard_catches_an_enterprise_service_in_the_smb_tier() -> None:
    assert check_no_enterprise_services("  grafana:\n"), (
        "check_no_enterprise_services() missed grafana — this is the one check "
        "the documentation already credited the missing hook with performing."
    )
    assert not check_no_enterprise_services("  redis:\n  warden:\n")


def test_the_documented_hook_now_exists() -> None:
    """CONTRIBUTING.md and Hook.md promised this guard for months."""
    hook = _ROOT / "warden" / "hooks" / "smb_perimeter.py"
    assert hook.exists(), (
        "warden/hooks/smb_perimeter.py is gone. Two documents describe a "
        "check-smb-compose guard over this profile; before OB-F22 they "
        "described something that did not exist, and the profile with the "
        "weakest perimeter had no automated check at all."
    )
    if not _COMPOSE.exists():
        pytest.skip("docker-compose.smb.yml not present in this checkout")
