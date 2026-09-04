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


def test_the_guard_catches_a_wide_open_port_in_every_compose_spelling() -> None:
    """Guard the guard — and the first version could only see one spelling.

    It matched `- "8501:8501"` with a regex requiring double quotes. Unquoted,
    single-quoted and long-form entries were invisible, so three ways of
    writing the same exposure passed a green check. Compose knows what a port
    is; the guard now asks it.
    """
    def doc(ports):
        return {"services": {"dashboard": {"ports": ports}}}

    for spelling in (
        ["8501:8501"],                                        # quoted or not — same YAML
        [8501],                                               # bare container port
        [{"target": 8501, "published": 8501}],                # long form
        [{"target": 8501, "published": "8501", "protocol": "tcp"}],
    ):
        assert check_ports(doc(spelling)), (
            f"check_ports() accepted {spelling!r} — a port published on every "
            "interface. Every spelling Compose accepts has to be visible here, "
            "or the guard is green and blind."
        )

    assert not check_ports(doc(["127.0.0.1:8501:8501"]))
    assert not check_ports(doc([{"target": 8501, "published": 8501,
                                 "host_ip": "127.0.0.1"}]))
    assert not check_ports(doc(["8001:8001"])), (
        "8001 is allow-listed as the gateway API and must not be flagged."
    )


def test_the_guard_does_not_mistake_a_volume_for_a_service() -> None:
    """`volumes:` was being scanned by indentation as though it were services."""
    assert not check_no_enterprise_services({"volumes": {"grafana": None},
                                             "services": {"warden": {}}}), (
        "A volume named `grafana` is not the Grafana service. Scoping by "
        "indentation is what produced that confusion."
    )
    assert check_no_enterprise_services({"services": {"grafana": {}}})


def test_a_variable_named_only_in_a_comment_does_not_count() -> None:
    """Substring matching passed on a mention, including this fix's own comment."""
    assert check_required_env("REDIS_URL=redis://redis:6379\n"), (
        "check_required_env() passed an env example with no "
        f"{REQUIRED_ENV_KEYS[0]}, which is how the open dashboard shipped."
    )
    assert check_required_env("# remember to set DASHBOARD_PASSWORD_HASH\n"), (
        "A commented mention satisfied the check. The operator still has no "
        "line to fill in, which is the entire point of the example file."
    )
    assert not check_required_env("DASHBOARD_PASSWORD_HASH=\n")


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
