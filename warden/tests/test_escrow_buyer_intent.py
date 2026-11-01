"""A deposit the gateway relays carries the buyer's signed consent, or is not sent.

`Escrow.deposit` used to accept the operator for any buyer, so the gateway's hot
key alone could open a trade against any standing allowance, to any seller, and
pay it out. The contract now requires the buyer's EIP-712 `DepositIntent`; these
tests pin the gateway half: it never sends a relayed deposit without a signature
that recovers to the escrow's own buyer for the escrow's own arguments.
"""
from __future__ import annotations

import time

import pytest

from warden.marketplace.escrow import EscrowService
from warden.tests.escrow_intent_helpers import BUYER, BUYER_KEY, consent, sign_intent
from warden.web3.settlement import Preflight, trade_id_for

_SELLER = "0x42Cb99A842a5bb6848Ef96b9f7070E348BD9b913"
_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
_OTHER_KEY = "0x" + "c1" * 32
_OPERATOR_KEY = "0x" + "a5" * 32


@pytest.fixture()
def wire(monkeypatch):
    from warden.config import settings
    from warden.web3.smart_contract import EscrowCallResult

    monkeypatch.setattr(settings, "escrow_settle_chains", "base_sepolia")
    monkeypatch.setenv("WEB3_SIGNER_KEY", _OPERATOR_KEY)   # the gateway, not the buyer
    calls: list[tuple[str, dict]] = []

    def _record(_addr, fn_name, params, _chain):
        calls.append((fn_name, dict(params)))
        return EscrowCallResult(ok=True, tx_hash="0x" + f"{len(calls):064x}")

    monkeypatch.setattr("warden.web3.smart_contract.call_escrow_result", _record)
    monkeypatch.setattr(
        "warden.web3.smart_contract.settlement_capability",
        lambda chain="base_sepolia": {"can_settle": True, "reason": "", "detail": "",
                                      "chain": chain},
    )
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(ok=True, configured=True,
                               trade_id=trade_id_for(kw["escrow_id"]),
                               amount_minor=1_000_000, token_address=_USDC,
                               token_decimals=6),
    )
    return calls


@pytest.fixture()
def escrow(tmp_path, monkeypatch):
    monkeypatch.setattr(EscrowService, "_payout_address",
                        staticmethod(lambda aid: BUYER if "buyer" in aid else _SELLER))
    db = str(tmp_path / "escrow.db")
    svc = EscrowService()
    esc = svc.create_escrow(
        listing_id="LST-1", buyer_agent_id="did:shadow:buyer",
        seller_agent_id="did:shadow:seller", amount_usd=1.0,
        chain="base_sepolia", db_path=db,
    )
    return svc, esc, db


def _status(svc, esc, db):
    return svc.get_escrow(esc.escrow_id, db).status


def test_a_relayed_deposit_without_consent_is_not_sent(escrow, wire):
    svc, esc, db = escrow
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is False
    assert wire == []
    assert _status(svc, esc, db) == "pending_deposit"


def test_a_signature_from_anyone_but_the_buyer_is_not_sent(escrow, wire):
    svc, esc, db = escrow
    consent(svc, esc.escrow_id, db, key=_OTHER_KEY)
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is False
    assert wire == []


def test_an_expired_intent_is_not_sent(escrow, wire):
    svc, esc, db = escrow
    deadline = int(time.time()) - 1
    typed = svc.deposit_intent(esc.escrow_id, deadline, db_path=db)
    assert svc.record_deposit_intent(esc.escrow_id, sign_intent(typed), deadline, db_path=db)
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is False
    assert wire == []


def test_a_signature_over_a_different_deadline_is_not_sent(escrow, wire):
    svc, esc, db = escrow
    deadline = int(time.time()) + 900
    typed = svc.deposit_intent(esc.escrow_id, deadline, db_path=db)
    assert svc.record_deposit_intent(esc.escrow_id, sign_intent(typed), deadline + 60,
                                     db_path=db)
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is False
    assert wire == []


def test_the_buyers_own_consent_is_sent_with_the_deposit(escrow, wire):
    svc, esc, db = escrow
    deadline = consent(svc, esc.escrow_id, db)
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    (fn, params), = wire
    assert fn == "deposit"
    assert params["buyer"] == BUYER
    assert params["intentDeadline"] == deadline
    assert len(params["buyerSignature"]) == 65


def test_a_buyer_sending_its_own_deposit_needs_no_signature(escrow, wire, monkeypatch):
    svc, esc, db = escrow
    monkeypatch.setenv("WEB3_SIGNER_KEY", BUYER_KEY)
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    (_fn, params), = wire
    assert params["intentDeadline"] == 0 and params["buyerSignature"] == b""


@pytest.mark.parametrize("bad", ["", "0x1234", "0x" + "zz" * 65, "0x" + "ab" * 64])
def test_a_malformed_signature_is_not_stored(escrow, bad):
    svc, esc, db = escrow
    assert svc.record_deposit_intent(esc.escrow_id, bad, 2**40, db_path=db) is False


def test_an_intent_cannot_be_attached_to_a_funded_escrow(escrow, wire):
    svc, esc, db = escrow
    consent(svc, esc.escrow_id, db)
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    assert svc.record_deposit_intent(esc.escrow_id, "0x" + "ab" * 65, 2**40,
                                     db_path=db) is False


# ── API ──────────────────────────────────────────────────────────────────────

def _client(monkeypatch, db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.api_escrow import router

    monkeypatch.setenv("MARKETPLACE_DB_PATH", db)
    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    return TestClient(app)


def test_the_api_hands_out_typed_data_and_funds_with_the_signature(escrow, wire, monkeypatch):
    svc, esc, db = escrow
    client = _client(monkeypatch, db)
    resp = client.get(f"/marketplace/escrow/{esc.escrow_id}/deposit-intent")
    assert resp.status_code == 200, resp.text
    typed = resp.json()["typed_data"]
    assert typed["primaryType"] == "DepositIntent"
    assert typed["message"]["seller"] == _SELLER

    resp = client.post(f"/marketplace/escrow/{esc.escrow_id}/fund", json={
        "buyer_signature": sign_intent(typed),
        "intent_deadline": typed["message"]["deadline"],
    })
    assert resp.status_code == 200, resp.text
    assert [fn for fn, _ in wire] == ["deposit"]


def test_the_api_refuses_a_signature_without_its_deadline(escrow, wire, monkeypatch):
    svc, esc, db = escrow
    resp = _client(monkeypatch, db).post(
        f"/marketplace/escrow/{esc.escrow_id}/fund",
        json={"buyer_signature": "0x" + "ab" * 65},
    )
    assert resp.status_code == 422
    assert wire == []
