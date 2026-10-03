"""
warden/tests/test_phase1_deposit_gate.py

`docs/onchain-settlement-design.md` §7 lets settlement leave Phase 1 only after
five escrows where preflight's verdict was reproduced by a manual deposit. The
section says why the gate is counted rather than timed: the ledger cutover
passed on a shadow period that ended because the clock ran out, with zero
tenants verified.

So the counting is the part worth testing. `scripts/phase1_deposit.py` sends the
transaction; these tests pin what it counts — that five runs against one escrow
are one verified escrow, that a later failure is not hidden by an earlier pass,
and that a refusal reproduced on-chain counts, because a preflight that refuses
everything would otherwise sail through a happy-path-only gate.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "phase1_deposit.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("phase1_deposit", _SCRIPT)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    sys.modules["phase1_deposit"] = m
    spec.loader.exec_module(m)
    return m


def _entry(escrow_id: str, *, preflight_ok: bool = True, sent_ok: bool = True, at: str = "t0") -> dict:
    # A refusal the chain agreed with is one the contract itself rejected.
    rejected = not preflight_ok and not sent_ok
    return {
        "escrow_id": escrow_id, "at": at,
        "preflight_ok": preflight_ok, "sent_ok": sent_ok,
        "chain_rejected": rejected,
        "match": preflight_ok == sent_ok,
    }


def test_five_distinct_escrows_pass_the_gate(mod):
    s = mod.summarise([_entry(f"ESC-{i}") for i in range(5)])
    assert (s["matched"], s["passed"]) == (5, True)


def test_five_runs_against_one_escrow_do_not(mod):
    """The gate counts escrows, not attempts. Retrying one trade until it works
    is exactly the shape of evidence §7 was written to reject."""
    s = mod.summarise([_entry("ESC-1", at=f"t{i}") for i in range(5)])
    assert (s["escrows"], s["matched"], s["passed"]) == (1, 1, False)


def test_a_later_failure_replaces_an_earlier_pass(mod):
    s = mod.summarise([
        _entry("ESC-1", at="t0"),
        _entry("ESC-1", preflight_ok=True, sent_ok=False, at="t1"),
    ])
    assert s["matched"] == 0
    assert [e["escrow_id"] for e in s["mismatched"]] == ["ESC-1"]


def test_a_refusal_the_chain_agreed_with_counts(mod):
    """preflight refuse + deposit reverted is a reproduced verdict. Counting
    only landings would let a preflight that refuses everything pass."""
    s = mod.summarise([_entry(f"ESC-{i}", preflight_ok=False, sent_ok=False) for i in range(5)])
    assert (s["matched"], s["passed"]) == (5, True)


def test_a_refusal_the_chain_ignored_is_a_mismatch(mod):
    """The dangerous direction: preflight refused, yet the deposit landed."""
    s = mod.summarise([_entry("ESC-1", preflight_ok=False, sent_ok=True)])
    assert s["matched"] == 0 and not s["passed"]


def test_four_is_not_five(mod):
    assert not mod.summarise([_entry(f"ESC-{i}") for i in range(4)])["passed"]


def test_the_required_count_is_the_one_the_design_states(mod):
    assert mod.REQUIRED_MATCHES == 5


# ── a refusal is reproduced only by the contract's own "no" ──────────────────
#
# The first live `--force` run (2026-10-03, Base Sepolia) was journalled as a
# MATCH with `failure: MismatchedABI` and no transaction hash: the refused
# Preflight carries no token or amount, the deposit could not be encoded, and
# nothing reached the chain. The gate then read 6/5. These pin that it cannot.

class _Res:
    def __init__(self, ok=False, tx_hash="", error="", simulated=False):
        self.ok, self.tx_hash, self.error, self.simulated = ok, tx_hash, error, simulated


_ABI_ERRORS = {"TransferFailed", "TradeExists", "NotBuyer"}


def test_the_journalled_counterfeit_does_not_count(mod):
    counterfeit = {
        "escrow_id": "ESC-D2B5FE8A7A5A", "at": "2026-10-03T05:58:16+00:00",
        "chain": "base_sepolia", "failure": "MismatchedABI", "forced": True,
        "match": True, "preflight_ok": False,
        "preflight_reason": "insufficient_allowance", "sent_ok": False, "tx_hash": "",
    }
    s = mod.summarise([_entry(f"ESC-{i}") for i in range(4)] + [counterfeit])
    assert (s["matched"], s["passed"]) == (4, False)
    assert [e["escrow_id"] for e in s["unproven"]] == ["ESC-D2B5FE8A7A5A"]


@pytest.mark.parametrize("res", [
    _Res(error="MismatchedABI"),                 # could not encode: nothing sent
    _Res(error="rpc_unreachable"),               # never reached a node
    _Res(error="TimeExhausted", tx_hash="0xab"),  # sent, outcome unknown
    _Res(ok=True, simulated=True),               # nothing configured
    _Res(ok=True, tx_hash="0xab"),               # it landed
])
def test_failures_the_contract_never_judged_are_not_rejections(mod, res):
    assert mod.chain_rejected(res, _ABI_ERRORS) is False


@pytest.mark.parametrize("res", [
    _Res(tx_hash="0xab", error="reverted"),      # mined with status 0
    _Res(error="TransferFailed"),                # the escrow's own custom error
    _Res(error="ContractLogicError"),            # the token's revert, bubbled up
])
def test_the_contracts_own_no_is_a_rejection(mod, res):
    assert mod.chain_rejected(res, _ABI_ERRORS) is True


def test_forced_params_are_a_complete_deposit(mod):
    """What the counterfeit lacked: a token and a non-zero amount, under the
    exact names the ABI's `deposit` declares."""
    import json

    from warden.web3.smart_contract import _abi_path

    p = mod.forced_params("ESC-1", 1.25, "0x" + "1" * 40, "0x" + "2" * 40,
                          "0x036CbD53842c5426634e7929541eC2318f3dCF7e", 6)
    assert p["amount"] == 1_250_000
    assert p["token"] == "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    abi = json.loads(Path(_abi_path()).read_text(encoding="utf-8"))
    deposit = next(f for f in abi if f.get("type") == "function" and f["name"] == "deposit")
    assert set(p) == {i["name"] for i in deposit["inputs"]}


def test_policy_refusals_cannot_be_forced(mod):
    """Forcing past the cap would land and move more than the cap allows."""
    assert "above_trade_cap" not in mod.CHAIN_REPRODUCIBLE_REFUSALS
    assert {"insufficient_allowance", "insufficient_balance"} == mod.CHAIN_REPRODUCIBLE_REFUSALS
