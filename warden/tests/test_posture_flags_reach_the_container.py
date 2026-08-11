"""
warden/tests/test_posture_flags_reach_the_container.py

**A posture flag that is not passed through `docker-compose.yml` is a silent
no-op.** `warden` has no `env_file`, so the container sees only the variables
the compose service lists. Setting one in `/opt/shadow-warden/.env` and
restarting looks like a successful flip and changes nothing.

Measured 2026-08-11 on the production host: seven of the eight documented
enforcement flags were missing from compose, including every money-path gate —
`LEDGER_DUAL_WRITE` (the Track F reconciliation baseline that D-5 is blocked
on), `AUTHORIZE_PAYMENT_ENFORCED` (FT-6's chokepoint), and
`OVERAGE_CHARGE_ENFORCED` (FM-7's collection gate). `MARKETPLACE_REQUIRE_SIGNED_OFFERS`
was the only one present, and its compose comment records that it was added
after somebody hit exactly this.

The failure is worse than "the flag does nothing": an operator who flips
`LEDGER_DUAL_WRITE=true`, waits for a bake period and sees no discrepancies can
reasonably conclude the dual-write reconciled clean, when in fact it never ran.

Both services are checked. `sova_overage_billing` and the other money crons run
in `arq-worker`, so a flag set only on `warden` leaves the scheduled path on its
default.
"""
from __future__ import annotations

import re
from pathlib import Path

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"

#: Flags that change money movement or compliance enforcement. Curated rather
#: than derived: the point is that each is a documented posture decision
#: somebody is expected to flip, and adding one here should be deliberate.
_MONEY_AND_COMPLIANCE = (
    "LEDGER_DUAL_WRITE",
    "AUTHORIZE_PAYMENT_ENFORCED",
    "OVERAGE_CHARGE_ENFORCED",
    "MARKETPLACE_REQUIRE_SIGNED_OFFERS",
    "KYB_ENFORCEMENT_ENABLED",
    "SANCTIONS_SCREENING_ENABLED",
)
#: Flags on the warden request path only.
_WARDEN_ONLY = ("KYA_VERIFIED_ONLY", "X402_GATE_ENABLED")


def _service_env(service: str) -> list[str]:
    """The `environment:` entries of one compose service, as raw strings."""
    text = _COMPOSE.read_text(encoding="utf-8")
    # Service blocks start at two-space indent; take from this service to the next.
    start = re.search(rf"^  {re.escape(service)}:$", text, re.M)
    assert start, f"service {service} not found in docker-compose.yml"
    rest = text[start.end():]
    nxt = re.search(r"^  \w[\w.-]*:$", rest, re.M)
    block = rest[: nxt.start()] if nxt else rest
    env = re.search(r"^    environment:$", block, re.M)
    if not env:
        return []
    tail = block[env.end():]
    end = re.search(r"^    \w", tail, re.M)
    return re.findall(r"^\s*-\s*(\S+)", tail[: end.start()] if end else tail, re.M)


def _names(entries: list[str]) -> set[str]:
    return {e.split("=", 1)[0] for e in entries}


def test_warden_passes_through_every_posture_flag():
    have = _names(_service_env("warden"))
    missing = [f for f in _MONEY_AND_COMPLIANCE + _WARDEN_ONLY if f not in have]
    assert not missing, (
        f"warden does not pass through {missing}. There is no `env_file`, so "
        "setting these in .env is a silent no-op: the flip looks applied and "
        "the code keeps reading its default."
    )


def test_arq_worker_passes_through_the_money_flags():
    """The overage-settlement cron and the nightly money jobs run here."""
    have = _names(_service_env("arq-worker"))
    missing = [f for f in _MONEY_AND_COMPLIANCE if f not in have]
    assert not missing, (
        f"arq-worker does not pass through {missing}. A flag set only on warden "
        "leaves every scheduled money path on its default."
    )


def test_defaults_stay_off():
    """Adding a passthrough must not change behaviour on upgrade.

    Every one of these defaults to false in code; a compose default of `true`
    would flip production the moment this file is deployed.
    """
    for service in ("warden", "arq-worker"):
        for entry in _service_env(service):
            name, _, value = entry.partition("=")
            if name in _MONEY_AND_COMPLIANCE + _WARDEN_ONLY:
                assert value.endswith(":-false}"), (
                    f"{service}.{name} defaults to {value!r}; posture flags must "
                    "default off so deploying this file changes nothing"
                )


def test_the_parser_actually_reads_the_file():
    """A guard whose parser silently returns nothing always passes."""
    env = _service_env("warden")
    assert len(env) > 20, f"only parsed {len(env)} entries — the regex has drifted"
    assert "ARQ_MODE=1" in _service_env("arq-worker")
