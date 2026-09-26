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
    # The on-chain settlement gate: nothing is sent on a chain absent from it
    # (`EscrowService._call_contract`, marketplace rule 31). It was passed
    # through from the start but never pinned here, so a compose edit could drop
    # it silently -- and the first mainnet trade in P1a would then be a no-op
    # that looked configured, which is this file's whole subject.
    "ESCROW_SETTLE_CHAINS",
)
#: Posture flags whose value is a list, whose "off" is therefore empty.
_LIST_FLAGS = frozenset({"ESCROW_SETTLE_CHAINS"})

#: Flags on the warden request path only.
_WARDEN_ONLY = ("KYA_VERIFIED_ONLY", "X402_GATE_ENABLED")

#: Read by code and deliberately NOT passed through. Each defaults to its secure
#: value inside the image, so failing to reach the container fails closed: an
#: operator who sets it to "false" in .env to weaken the check gets no effect.
#: Adding a passthrough would *create* a way to switch the protection off from
#: .env. Listed so that the absence reads as a decision, not as the defect this
#: file exists to catch -- do not "fix" these by adding them to compose.
_SECURE_DEFAULT_NOT_PASSED = {
    # x402_gate.py: os.getenv("X402_REQUIRE_SIGNED_PAYMENT", "true") -- the
    # payer-signature requirement that closed vuln-0004.
    "X402_REQUIRE_SIGNED_PAYMENT": "true",
}


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
            if name in _LIST_FLAGS:
                # A list flag's "off" is the empty list, never a boolean: a
                # boolean would turn settlement on everywhere at once, including
                # chains with no token (marketplace rule 31).
                assert value.endswith(":-}"), (
                    f"{service}.{name} defaults to {value!r}; a list flag must "
                    "default to the empty list so deploying this file sends nothing"
                )
            elif name in _MONEY_AND_COMPLIANCE + _WARDEN_ONLY:
                assert value.endswith(":-false}"), (
                    f"{service}.{name} defaults to {value!r}; posture flags must "
                    "default off so deploying this file changes nothing"
                )


def test_the_parser_actually_reads_the_file():
    """A guard whose parser silently returns nothing always passes."""
    env = _service_env("warden")
    assert len(env) > 20, f"only parsed {len(env)} entries — the regex has drifted"
    assert "ARQ_MODE=1" in _service_env("arq-worker")


def _getenv_defaults(root: Path, flag: str) -> list[str]:
    """Every literal default passed to `os.getenv(flag, ...)` under `warden/`.

    Parsed, not matched. A regex over the source read only double-quoted
    arguments, so `os.getenv('X402_REQUIRE_SIGNED_PAYMENT', 'false')` was
    invisible while the existing secure read kept the result at ["true"] -- the
    test would pass through a fail-open regression on the payment path. Quoting
    style is not a security property; the call is.
    """
    import ast

    out: list[str] = []
    for py in (root / "warden").rglob("*.py"):
        if "tests" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or len(node.args) < 2:
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "getenv":
                continue
            key, default = node.args[0], node.args[1]
            if isinstance(key, ast.Constant) and key.value == flag:
                value = default.value if isinstance(default, ast.Constant) else None
                # A non-string default is not a posture value either -- report it
                # rather than coercing, so the test says what it actually found.
                out.append(value if isinstance(value, str) else "<non-literal>")
    return out


def test_secure_default_flags_stay_out_of_compose_and_default_secure():
    """The other direction. A flag whose default is the secure value must *not*
    gain a passthrough: that would make the protection switchable from .env.
    And its in-code default must still be the secure one, or the exclusion
    above stops being safe."""
    root = Path(__file__).resolve().parents[2]
    compose = _COMPOSE.read_text(encoding="utf-8")
    for flag, secure in _SECURE_DEFAULT_NOT_PASSED.items():
        assert flag not in compose, (
            f"{flag} is now passed through docker-compose.yml. It defaults to "
            f"{secure!r} inside the image; a passthrough lets .env turn the check off."
        )
        hits = _getenv_defaults(root, flag)
        assert hits, f"{flag} is no longer read with a default -- re-check the exclusion"
        assert all(h.lower() == secure for h in hits), (
            f"{flag} now defaults to {hits}, not {secure!r}. The exclusion from "
            "compose was only safe while the default was the secure value."
        )
