"""warden/tests/test_deploy_reports_failure.py — a failed deploy must fail the job.

On 2026-08-19 a deploy left every container in `created` after a stale
container-name conflict, the remote script printed "docker compose up failed"
and exited 1, and the CI job reported **success**. Production was unreachable
(Cloudflare 1033) for about ninety minutes behind a green pipeline.

The cause was one line on the SSH heredoc:

    ssh ... /bin/bash << ENDSSH || { echo "⚠️  Server unreachable"; exit 0; }

Any non-zero exit read as "unreachable" and became `exit 0`. That is also how
the remote script reports `docker compose up` failing, and how the health poll
reports `/health` never returning 200 within five minutes — both `exit 1`. The
verification existed and ran; its verdict was thrown away.

Same defect class as the rest of this suite's guards: a reader reporting success
over a state it did not check. These tests pin the repair — ssh's own 255 is
still treated as unreachable and skipped, anything else fails the job.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_CI = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def deploy_script() -> str:
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if step.get("name") == "Deploy via SSH":
                return str(step["run"])
    # raise, not pytest.fail(): the installed pytest stubs do not mark fail()
    # as NoReturn, so mypy reads this function as able to fall off the end.
    raise AssertionError("no 'Deploy via SSH' step in ci.yml")


def test_ssh_failure_is_not_blanket_converted_to_success(deploy_script: str) -> None:
    """The exact line that hid a ninety-minute outage."""
    assert "ENDSSH || {" not in deploy_script, (
        "The SSH heredoc has a `|| { ... }` guard again. Any non-zero exit — "
        "including `docker compose up failed` and a `/health` timeout — would be "
        "swallowed by it and the job would go green over a dead production."
    )


def test_remote_exit_code_is_captured_and_propagated(deploy_script: str) -> None:
    assert "DEPLOY_RC=$?" in deploy_script, "the remote exit code must be captured"
    assert 'exit "$DEPLOY_RC"' in deploy_script, (
        "a non-zero remote exit must fail the step, not be reported as skipped"
    )


def test_only_ssh_transport_failure_counts_as_unreachable(deploy_script: str) -> None:
    """255 is ssh's own connection failure; everything else is the script's."""
    assert '"$DEPLOY_RC" -eq 255' in deploy_script, (
        "unreachable must be identified by ssh's 255, not by 'any failure'"
    )


def test_the_health_poll_still_fails_the_remote_script(deploy_script: str) -> None:
    """The check whose verdict was being discarded. It must still be there."""
    assert "/health did not return 200 within 5 minutes" in deploy_script
    tail = deploy_script[deploy_script.index("/health did not return 200") :]
    assert "exit 1" in tail, (
        "the post-deploy health poll must exit non-zero on timeout — otherwise "
        "propagating the remote exit code buys nothing"
    )
