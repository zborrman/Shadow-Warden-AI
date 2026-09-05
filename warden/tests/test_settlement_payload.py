"""
warden/tests/test_settlement_payload.py — P1a, Phase 1.

The transport was finished in August and the payload was never written. Twelve
escrow tests passed the whole time, because each of them asserted on state
transitions — which is exactly what a call with no arguments still produces when
the chain is simulated and returns True before looking at them.

So the first test here does not assert on state at all. It drives the lifecycle,
records what the gateway actually put on the wire, and compares each call's
argument names against the deployed contract's own ABI. `deposit({})` fails it,
and so does every future call site that forgets `tradeId` — which was **all six
of them**, since every function in this ABI takes one.

A hand-written list of expected parameters would not have done that job: it is a
second copy of the vocabulary, and this codebase has already shipped a
marketplace enum written out twice where the two copies disagreed. The ABI is
the artifact the chain enforces, so the ABI is what the test reads.
"""
from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from warden.marketplace.escrow import EscrowService
from warden.web3.chains import get_chain
from warden.web3.settlement import (
    Preflight,
    SettlementRefused,
    deposit_params,
    to_minor_units,
    trade_id_for,
)

_ABI = json.loads(
    (Path(__file__).resolve().parents[1] / "web3" / "abi" / "escrow.abi.json")
    .read_text(encoding="utf-8")
)
_INPUTS = {
    f["name"]: [i["name"] for i in f["inputs"]]
    for f in _ABI
    if f.get("type") == "function"
}

_BUYER = "0x24a0d27E8c216b6Ac42A4A7fe7FC9b230Fc1A605"
_SELLER = "0x42Cb99A842a5bb6848Ef96b9f7070E348BD9b913"
# Read from the chain table rather than pasted in, so the fixture cannot drift
# from the address the gateway would actually settle against — and so a public
# contract address is not sitting in a test file looking like a credential.
_USDC_BASE_SEPOLIA = get_chain("base_sepolia")["usdc_address"]


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def wire(monkeypatch):
    """A configured, ready chain that records every call instead of sending it."""
    calls: list[tuple[str, dict]] = []

    def _record(_addr, fn_name, params, _chain):
        calls.append((fn_name, dict(params)))
        return True

    monkeypatch.setattr("warden.web3.smart_contract.call_escrow", _record)
    monkeypatch.setattr(
        "warden.web3.smart_contract.settlement_capability",
        lambda chain="base_sepolia": {
            "can_settle": True, "reason": "", "detail": "", "chain": chain
        },
    )
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(
            ok=True,
            configured=True,
            trade_id=trade_id_for(kw["escrow_id"]),
            amount_minor=1_000_000,
            token_address=_USDC_BASE_SEPOLIA,
            token_decimals=6,
        ),
    )
    return calls


@pytest.fixture()
def escrow(tmp_path, monkeypatch):
    # raising=False so this fixture still builds against an EscrowService that
    # predates the change — which is how these guards get validated against the
    # artifact they were written to catch.
    monkeypatch.setattr(EscrowService, "_payout_address",
                        staticmethod(lambda aid: _BUYER if "buyer" in aid else _SELLER),
                        raising=False)
    db = str(tmp_path / "escrow.db")
    svc = EscrowService()
    esc = svc.create_escrow(
        listing_id="LST-1", buyer_agent_id="did:shadow:buyer",
        seller_agent_id="did:shadow:seller", amount_usd=1.0,
        chain="base_sepolia", db_path=db,
    )
    return svc, esc, db


# ── the conformance test ──────────────────────────────────────────────────────

class TestEveryCallMatchesTheDeployedABI:
    def test_the_happy_path_sends_what_the_contract_declares(self, escrow, wire):
        svc, esc, db = escrow
        assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
        assert svc.deliver_asset(esc.escrow_id, "0x" + "ab" * 32, db_path=db) is True
        assert svc.confirm_receipt(esc.escrow_id, db_path=db) is True

        assert [fn for fn, _ in wire] == ["deposit", "deliverAsset", "confirmReceipt"]
        for fn_name, params in wire:
            assert set(params) == set(_INPUTS[fn_name]), (
                f"{fn_name} was called with {sorted(params)}, "
                f"but the ABI declares {sorted(_INPUTS[fn_name])}"
            )

    def test_the_dispute_path_too(self, escrow, wire):
        svc, esc, db = escrow
        svc.fund_escrow(esc.escrow_id, db_path=db)
        assert svc.raise_dispute(esc.escrow_id, "not delivered", db_path=db) is True
        assert svc.resolve_dispute(esc.escrow_id, True, db_path=db) is True

        assert [fn for fn, _ in wire] == ["deposit", "raiseDispute", "resolveDispute"]
        for fn_name, params in wire:
            assert set(params) == set(_INPUTS[fn_name]), (
                f"{fn_name} was called with {sorted(params)}, "
                f"but the ABI declares {sorted(_INPUTS[fn_name])}"
            )

    def test_every_abi_function_takes_a_trade_id(self):
        """Why the omission mattered six times over, not once.

        `deposit` needing five more arguments is the visible half. The half that
        made the other five calls meaningless is that `tradeId` identifies
        *which* trade — and none of them supplied it.
        """
        for name, inputs in _INPUTS.items():
            # Public getters, not trade operations. `operator` joined them when
            # the hot relay key was split out of the arbiter (2026-09-03).
            if name in ("arbiter", "operator", "trades"):
                continue
            assert "tradeId" in inputs, name

    def test_a_call_without_an_escrow_id_is_refused(self, escrow, monkeypatch):
        """Fail closed: a call that cannot name its trade must not be sent."""
        svc, esc, _db = escrow
        monkeypatch.setattr(
            "warden.web3.settlement.trade_id_for",
            lambda _e: (_ for _ in ()).throw(SettlementRefused("no keccak")),
        )
        assert svc._call_contract(esc.contract_address, "confirmReceipt", {},
                                  esc.escrow_id) is False


# ── amount conversion ─────────────────────────────────────────────────────────

class TestAmountsBecomeIntegers:
    @pytest.mark.parametrize("usd,expected", [
        (1.0, 1_000_000),
        (0.01, 10_000),
        (19.99, 19_990_000),
        (249, 249_000_000),
        (Decimal("0.000001"), 1),
    ])
    def test_usd_to_usdc_minor_units(self, usd, expected):
        assert to_minor_units(usd, 6) == expected

    def test_a_binary_float_artifact_does_not_leak_through(self):
        """0.07 * 3 is 0.21000000000000002 in binary floating point.

        `Decimal(str(x))` reads the decimal the operator wrote; `Decimal(x)`
        inherits the float's error and reintroduces what Decimal is here to
        prevent.
        """
        assert to_minor_units(0.07 * 3, 6) == 210_000

    def test_an_amount_that_rounds_to_zero_refuses(self):
        """The $0.00 clearing defect, one layer down.

        A trade settled for zero tokens and recorded as released would satisfy
        every test that only checks state transitions — which is what the escrow
        suite consisted of.
        """
        with pytest.raises(SettlementRefused, match="rounds to 0"):
            to_minor_units(0.0000001, 6)

    def test_negative_and_zero_refuse(self):
        for bad in (0, -1.0):
            with pytest.raises(SettlementRefused):
                to_minor_units(bad, 6)

    def test_implausible_decimals_refuse(self):
        with pytest.raises(SettlementRefused, match="decimals"):
            to_minor_units(1.0, 99)


# ── trade id ──────────────────────────────────────────────────────────────────

class TestTheTradeIdIsStable:
    def test_it_is_a_bytes32(self):
        tid = trade_id_for("ESC-ABC123")
        assert tid.startswith("0x")
        assert len(bytes.fromhex(tid[2:])) == 32

    def test_the_same_escrow_always_addresses_the_same_trade(self):
        """A retry after a timeout must reach the trade it already opened.

        `Escrow.sol` reverts `TradeExists()` on a second deposit, which the
        caller reads as success. A random id would instead open a second trade
        for the same escrow and fund it twice.
        """
        assert trade_id_for("ESC-1") == trade_id_for("ESC-1")

    def test_different_escrows_do_not_collide(self):
        assert trade_id_for("ESC-1") != trade_id_for("ESC-2")

    def test_an_empty_escrow_id_refuses(self):
        with pytest.raises(SettlementRefused):
            trade_id_for("")


# ── deposit_params ────────────────────────────────────────────────────────────

class TestDepositParams:
    def test_the_keys_are_exactly_the_abi_inputs(self):
        pre = Preflight(ok=True, trade_id=trade_id_for("ESC-1"),
                        amount_minor=1_000_000, token_address=_USDC_BASE_SEPOLIA, token_decimals=6)
        assert set(deposit_params(pre, _BUYER, _SELLER, 3600)) == set(_INPUTS["deposit"])

    def test_a_failed_preflight_produces_no_arguments(self):
        pre = Preflight(ok=False, reason="no_token")
        with pytest.raises(SettlementRefused, match="no_token"):
            deposit_params(pre, _BUYER, _SELLER, 3600)


# ── preflight refusals ────────────────────────────────────────────────────────

class TestPreflightNamesItsReason:
    def test_an_unconfigured_deployment_says_which_piece_is_missing(self):
        """Production today. "Cannot settle" with no cause reads as a blip."""
        from warden.web3.settlement import settlement_preflight
        pre = settlement_preflight(
            escrow_id="ESC-1", amount_usd=1.0,
            buyer_address=_BUYER, seller_address=_SELLER, chain="base_sepolia",
        )
        assert pre.ok is False
        assert pre.reason and pre.detail

    def test_a_chain_with_no_token_is_refused_before_any_transaction(self, monkeypatch):
        """Fact 4: `sepolia` — the chain P1a actually deployed on — has no USDC."""
        from warden.web3 import settlement as st
        monkeypatch.setattr(st, "settlement_capability",
                            lambda chain: {"can_settle": True, "reason": "",
                                           "detail": "", "chain": chain})
        pre = st.settlement_preflight(
            escrow_id="ESC-1", amount_usd=1.0,
            buyer_address=_BUYER, seller_address=_SELLER, chain="sepolia",
        )
        assert pre.ok is False
        assert pre.reason == "no_token"

    def test_a_seller_with_no_payout_address_is_refused(self, monkeypatch):
        from warden.web3 import settlement as st
        monkeypatch.setattr(st, "settlement_capability",
                            lambda chain: {"can_settle": True, "reason": "",
                                           "detail": "", "chain": chain})
        pre = st.settlement_preflight(
            escrow_id="ESC-1", amount_usd=1.0,
            buyer_address=_BUYER, seller_address="", chain="base_sepolia",
        )
        assert pre.ok is False
        assert pre.reason == "no_seller_address"

    def test_a_malformed_address_is_a_config_error_not_a_revert(self, monkeypatch):
        from warden.web3 import settlement as st
        monkeypatch.setattr(st, "settlement_capability",
                            lambda chain: {"can_settle": True, "reason": "",
                                           "detail": "", "chain": chain})
        pre = st.settlement_preflight(
            escrow_id="ESC-1", amount_usd=1.0,
            buyer_address="0xnope", seller_address=_SELLER, chain="base_sepolia",
        )
        assert pre.reason == "bad_buyer_address"


# ── inertness ─────────────────────────────────────────────────────────────────

class TestSimulatedDeploymentsAreUntouched:
    def test_the_state_machine_still_runs_with_nothing_configured(self, escrow):
        """Every deployment today. None of the above may change this."""
        svc, esc, db = escrow
        assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
        assert svc.get_escrow(esc.escrow_id, db_path=db).status == "funded"

    def test_an_unconfigured_deployment_pays_for_no_network_call(self, escrow, monkeypatch):
        """Preflight answers "not configured" from the environment alone.

        Its first check is `settlement_capability`, which reads env vars and a
        packaged file. A deployment that cannot settle must not open an RPC
        connection to be told so.
        """
        import warden.web3.settlement as st
        monkeypatch.setattr(st, "verify_usdc_contract",
                            lambda *a, **kw: pytest.fail("reached the network"))
        svc, esc, db = escrow
        assert svc.fund_escrow(esc.escrow_id, db_path=db) is True

        pre = st.settlement_preflight(
            escrow_id=esc.escrow_id, amount_usd=1.0,
            buyer_address=_BUYER, seller_address=_SELLER, chain="base_sepolia",
        )
        assert pre.configured is False and pre.ok is False
