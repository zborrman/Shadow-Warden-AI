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


# ── 2026-08-22: the deploy took production down by itself ──────────────────
#
# #359 merged at 06:51 and #355 at 07:01. The test matrix takes ~25 min, so both
# reached "[3/4] Restart services" at 07:18 and drove `docker compose` against
# the same daemon at the same time. The second one's scoped recreate hit
# "removal of container ... is already in progress" — the first one's remove,
# still finishing — and the `||` fallback answered that by running
# `docker compose down` on the whole stack, then lost the same race coming back
# up: "network ... already exists", then `warden-minio` taken by the other run's
# fresh container. `up` aborted two containers in.
#
# Nineteen services destroyed, none running, Cloudflare serving 530/1033. The
# previous guards in this file all held: the step correctly exited 1 and the job
# correctly went red. Reporting the failure honestly was never the problem —
# the deploy caused it.


@pytest.fixture(scope="module")
def deploy_job() -> dict:
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    job = workflow["jobs"].get("deploy")
    if not isinstance(job, dict):
        raise AssertionError("no 'deploy' job in ci.yml")
    return job


def test_only_one_deploy_runs_at_a_time(deploy_job: dict) -> None:
    """There was no concurrency group at all — every merge deployed in parallel."""
    concurrency = deploy_job.get("concurrency")
    assert concurrency, (
        "The deploy job has no `concurrency:` group, so two merges less than a "
        "test-matrix apart both deploy at once and race each other's "
        "`docker compose` against one daemon. That is what destroyed the stack "
        "on 2026-08-22."
    )
    assert concurrency.get("group"), "a concurrency group needs a name"


def test_a_queued_deploy_is_not_cancelled_mid_flight(deploy_job: dict) -> None:
    """
    The dangerous half. `cancel-in-progress: true` would kill a deploy partway
    through `down`/`up` — containers already destroyed, nothing recreated, which
    is precisely the state this incident ended in. A superseded deploy costs a
    few wasted minutes; the newer commit is a descendant and deploys everything
    anyway.
    """
    assert deploy_job["concurrency"].get("cancel-in-progress") is False, (
        "cancel-in-progress must be explicitly false: cancelling a running "
        "deploy leaves a half-recreated stack behind"
    )


def test_a_transient_conflict_does_not_tear_down_the_whole_stack(
    deploy_script: str,
) -> None:
    """
    The fallback exists for a *stale* container left by a prior failed deploy —
    a permanent condition. It fired instead on a transient one that clears in
    seconds, and answered it by destroying thirteen services that were healthy
    and had nothing to do with the deploy. The scoped recreate must be retried
    before `down` is on the table at all.
    """
    assert "retrying scoped in" in deploy_script, (
        "the scoped recreate must be retried once before escalating to a full "
        "`docker compose down` — a transient conflict is not a stale container"
    )
    escalation = deploy_script.index("falling back to full down+up")
    retry = deploy_script.index("retrying scoped in")
    assert retry < escalation, "the retry must come before the escalation"


def test_the_force_remove_can_reach_the_gateway_container(deploy_script: str) -> None:
    """
    The fallback's cleanup filtered on `name=warden-`, which matches
    warden-redis and warden-grafana but NOT shadow-warden-warden-1 or
    shadow-warden-cloudflared-1 — those are named from the compose project, not
    a `container_name:`. So the gateway container, the one most likely to be
    blocking a create, was the one the cleanup could not remove.
    """
    assert "docker compose ps -aq" in deploy_script, (
        "force-remove must enumerate the compose project, not a name prefix, or "
        "it silently skips every container without an explicit container_name"
    )


def test_the_heredoc_does_not_execute_its_own_comments(deploy_script: str) -> None:
    """
    `<< ENDSSH` is unquoted, so the runner expands the body before ssh sends it —
    and that includes backticks inside comments. Thirteen of them ran on the CI
    runner every deploy, among them `docker compose down`, `docker compose up`
    and `git reset --hard`, the last against the runner's own checkout. They
    were no-ops there, and the only visible effect was comments arriving at the
    server with their command text silently replaced by its output. A comment is
    not a place where code should run.
    """
    lines = deploy_script.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.rstrip().endswith("<< ENDSSH"))
    end = next(i for i, ln in enumerate(lines) if i > start and ln.strip() == "ENDSSH")

    offenders = []
    for i in range(start + 1, end):
        stripped = lines[i].replace(r"\`", "")
        if "`" in stripped:
            offenders.append(f"  line {i - start} of the remote script: {lines[i].strip()}")

    assert not offenders, (
        "Unescaped backticks inside the unquoted `<< ENDSSH` heredoc are command "
        "substitutions that execute on the GitHub runner. Escape them as "
        + r"\`" + ":\n"
        + "\n".join(offenders)
    )
