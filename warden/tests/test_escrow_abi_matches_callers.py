"""
warden/tests/test_escrow_abi_matches_callers.py — P1a.

The ABI is hand-written until `scripts/build_escrow.sh` runs solc, so nothing
guarantees it matches either the Solidity source or the calls the gateway makes.
An ABI that disagrees with the contract fails at transaction time, on a mainnet,
with money already pulled from a buyer — which is the worst possible place to
find a typo.

These tests are not a compiler and not an audit. They check the two agreements
that can be checked from here: the ABI covers every function
`warden/marketplace/escrow.py` calls, and it does not claim functions the
Solidity source does not define.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_ABI = _ROOT / "contracts" / "escrow.abi.json"
_SOL = _ROOT / "contracts" / "Escrow.sol"
_CALLER = _ROOT / "warden" / "marketplace" / "escrow.py"

#: Every name passed to `_call_contract()`, which is what reaches `call_escrow`.
_CALL_RE = re.compile(r'_call_contract\(\s*[^,]+,\s*"([A-Za-z_][A-Za-z0-9_]*)"')
_SOL_FN_RE = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)

#: Public state variables are real ABI entries with no `function` keyword in the
#: source — Solidity synthesises a getter for each. Derived rather than listed:
#: the list was `{"arbiter", "trades"}` and went stale the moment `operator` was
#: split out of the arbiter, which is the same second-copy-of-the-vocabulary
#: failure this file exists to catch one layer up.
_SOL_PUBLIC_VAR_RE = re.compile(
    r"^\s*[\w\s\(\)=>\[\]]+?public(?:\s+(?:immutable|constant))?\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.MULTILINE,
)


def _abi() -> list[dict]:
    if not _ABI.exists():
        pytest.skip("no ABI committed yet")
    return json.loads(_ABI.read_text(encoding="utf-8"))


def _abi_functions() -> set[str]:
    return {e["name"] for e in _abi() if e.get("type") == "function"}


def test_abi_covers_every_function_the_gateway_calls() -> None:
    called = set(_CALL_RE.findall(_CALLER.read_text(encoding="utf-8")))
    assert called, "no contract calls found — the regex or the caller moved"
    missing = sorted(called - _abi_functions())
    assert not missing, (
        f"the gateway calls {missing} and the ABI does not define them; the "
        f"transaction would revert with the buyer's funds already escrowed"
    )


def test_the_solidity_source_defines_what_the_abi_claims() -> None:
    if not _SOL.exists():
        pytest.skip("no Solidity source committed")
    source = _SOL.read_text(encoding="utf-8")
    declared = set(_SOL_FN_RE.findall(source))
    declared |= set(_SOL_PUBLIC_VAR_RE.findall(source))
    overclaimed = sorted(_abi_functions() - declared)
    assert not overclaimed, (
        f"the ABI advertises {overclaimed}, which Escrow.sol does not define"
    )


def test_the_contract_states_its_status() -> None:
    """An unaudited escrow that reads as finished is how the money gets lost."""
    src = _SOL.read_text(encoding="utf-8")
    assert "NOT AUDITED" in src and "NOT DEPLOYED" in src, (
        "the contract must keep saying what it has not had"
    )


def test_the_abi_can_decode_this_contract_reverts() -> None:
    """Custom errors must be in the ABI or every revert is opaque.

    The hand-written ABI omitted all six. Nothing in it was wrong — no phantom
    function to revert on — but a failed `confirmReceipt` would have surfaced as
    an unnamed execution error instead of `WrongState(2)`, and the operator
    reading it has money sitting in a contract.
    """
    declared = {e["name"] for e in _abi() if e.get("type") == "error"}
    expected = {"NotArbiter", "NotBuyer", "WrongState", "TradeExists",
                "TransferFailed", "DeadlineNotReached"}
    assert expected <= declared, f"missing from the ABI: {sorted(expected - declared)}"
