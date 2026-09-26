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
    return {
        "escrow_id": escrow_id, "at": at,
        "preflight_ok": preflight_ok, "sent_ok": sent_ok,
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
