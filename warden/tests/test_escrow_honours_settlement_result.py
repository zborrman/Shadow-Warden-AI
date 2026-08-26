"""
warden/tests/test_escrow_honours_settlement_result.py — P1a/P3.

What the escrow does when the chain says no.

`call_escrow()` was made to fail CLOSED so that a settlement which never reached
the chain would be distinguishable from one that did. `_call_contract()` then
dropped its return value on the floor and returned None, and every caller
advanced the escrow anyway — so `fund_escrow` marked a deposit `funded`, and
`confirm_receipt` recorded the seller as paid, on the strength of a transaction
that had failed. Fixing the primitive and discarding its answer one layer up
leaves you exactly where you started, with better-looking code.

These tests force the failure. In simulated deployments `call_escrow` returns
True and none of this fires, which is why the whole class went unnoticed: the
suite only ever ran where settlement could not fail.
"""
from __future__ import annotations

import pytest

from warden.marketplace.escrow import EscrowService


@pytest.fixture()
def refusing_chain(monkeypatch):
    """A configured chain that rejects every transaction."""
    monkeypatch.setattr(
        "warden.web3.smart_contract.call_escrow",
        lambda *a, **kw: False,
    )
    # The second path in _call_contract must not rescue it either.
    monkeypatch.setattr(
        "warden.blockchain.chain_connector.ChainConnector",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no node")),
        raising=False,
    )


@pytest.fixture()
def escrow(tmp_path):
    db = str(tmp_path / "escrow.db")
    mgr = EscrowService()
    esc = mgr.create_escrow(
        listing_id="LST-1", buyer_agent_id="did:shadow:buyer",
        seller_agent_id="did:shadow:seller", amount_usd=1.0, db_path=db,
    )
    return mgr, esc.escrow_id, db


class TestARefusedChainDoesNotAdvanceTheDatabase:
    def test_a_failed_deposit_is_not_funded(self, escrow, refusing_chain):
        """The one that matters: money not taken, recorded as taken."""
        mgr, eid, db = escrow
        assert mgr.fund_escrow(eid, db_path=db) is False
        assert mgr.get_escrow(eid, db_path=db).status == "pending_deposit"

    def test_a_failed_release_does_not_record_the_seller_as_paid(
        self, escrow, monkeypatch
    ):
        """Deposit succeeds, release does not — the asymmetry that loses money."""
        mgr, eid, db = escrow
        calls: list[str] = []

        def _selective(_addr, fn, _params, _chain):
            calls.append(fn)
            return fn != "confirmReceipt"

        monkeypatch.setattr("warden.web3.smart_contract.call_escrow", _selective)

        assert mgr.fund_escrow(eid, db_path=db) is True
        assert mgr.deliver_asset(eid, "0x" + "ab" * 32, db_path=db) is True
        assert mgr.confirm_receipt(eid, db_path=db) is False
        assert mgr.get_escrow(eid, db_path=db).status == "delivered", (
            "the escrow advanced to confirmed on a release the chain refused"
        )
        assert "confirmReceipt" in calls


class TestSimulatedDeploymentsAreUnaffected:
    def test_the_state_machine_still_runs_where_nothing_settles(self, escrow):
        """No contract, no ABI, no signer: call_escrow simulates and returns True.

        This is what production runs today, and the guard must be inert there —
        `settlement_mode: simulated` is the field that tells a counterparty which
        of the two they are getting.
        """
        mgr, eid, db = escrow
        assert mgr.fund_escrow(eid, db_path=db) is True
        assert mgr.get_escrow(eid, db_path=db).status == "funded"


class TestTheHelperReturnsAnAnswerAtAll:
    def test_call_contract_is_not_none_returning(self):
        """The defect in one line: a bool-shaped question answered with None."""
        import inspect
        sig = inspect.signature(EscrowService._call_contract)
        # `from __future__ import annotations` keeps annotations as strings.
        assert sig.return_annotation in (bool, "bool"), (
            "the signature must promise an answer"
        )
        assert "return bool(call_escrow" in inspect.getsource(EscrowService._call_contract)
