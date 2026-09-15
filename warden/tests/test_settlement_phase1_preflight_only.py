"""
warden/tests/test_settlement_phase1_preflight_only.py — R2, §7 Phase 1.

docs/onchain-settlement-design.md §7: "Preflight runs and logs on every escrow;
nothing is sent." Before this, three things made that impossible:

* Nothing gated sending. The moment an operator configured a signer, ABI and
  contract address — which is what reproducing a verdict by hand needs — the
  gateway itself would start sending, on every chain at once.
* An unconfigured preflight stopped at its first check, so the verdict recorded
  on every production escrow could only ever say "not configured": never that
  the seller had no payout address, or that the chain has no token.
* The verdict was logged on failure and otherwise discarded.
"""
from __future__ import annotations

import json

import pytest

from warden.marketplace.escrow import EscrowService
from warden.web3.settlement import Preflight, trade_id_for
from warden.web3.smart_contract import EscrowCallResult

_BUYER = "0x52908400098527886E0F7030069857D2E4169EE7"
_SELLER = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


@pytest.fixture()
def settle_chains(monkeypatch):
    from warden.config import settings

    def _set(value: str) -> None:
        monkeypatch.setattr(settings, "escrow_settle_chains", value)

    _set("")          # Phase 1 is the default
    return _set


def _escrow(tmp_path, monkeypatch, *, seller=_SELLER, chain="base_sepolia"):
    from warden.marketplace import escrow as escrow_mod

    escrow_mod.reset_escrow_column_memo()
    monkeypatch.setattr(EscrowService, "_payout_address",
                        staticmethod(lambda aid: _BUYER if "buyer" in aid else seller))
    db = str(tmp_path / "escrow.db")
    svc = EscrowService()
    esc = svc.create_escrow(
        listing_id="LST-1", buyer_agent_id="did:shadow:buyer",
        seller_agent_id="did:shadow:seller", amount_usd=1.0, chain=chain, db_path=db,
    )
    return svc, esc, db


@pytest.fixture()
def configured_chain(monkeypatch):
    """Settlement fully configured and preflight passing; records any send."""
    sent: list[str] = []

    def _send(_addr, fn_name, _params, _chain):
        sent.append(fn_name)
        return EscrowCallResult(ok=True, tx_hash="0x" + f"{len(sent):064x}")

    monkeypatch.setattr("warden.web3.smart_contract.call_escrow_result", _send)
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(ok=True, configured=True, trade_id=trade_id_for(kw["escrow_id"]),
                               amount_minor=1_000_000, token_address=_USDC, token_decimals=6),
    )
    return sent


# ── nothing is sent unless the chain is named ───────────────────────────────


def test_phase1_default_sends_nothing_even_when_fully_configured(
        tmp_path, monkeypatch, settle_chains, configured_chain):
    svc, esc, db = _escrow(tmp_path, monkeypatch)

    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    assert svc.deliver_asset(esc.escrow_id, "0x" + "ab" * 32, db_path=db) is True
    assert svc.confirm_receipt(esc.escrow_id, db_path=db) is True

    assert configured_chain == [], f"sent {configured_chain} with no chain enabled"
    stored = svc._get(esc.escrow_id, db)
    assert (stored.fund_tx, stored.deliver_tx, stored.settle_tx) == ("", "", "")
    assert stored.trade_id == "", "no snapshot of a settlement that did not happen"


def test_an_enabled_chain_sends(tmp_path, monkeypatch, settle_chains, configured_chain):
    settle_chains("base_sepolia")
    svc, esc, db = _escrow(tmp_path, monkeypatch)

    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    assert configured_chain == ["deposit"]


def test_enabling_one_chain_enables_no_other(tmp_path, monkeypatch, settle_chains, configured_chain):
    """A list, not a boolean: naming base_sepolia must not turn on sepolia."""
    settle_chains("base_sepolia")
    svc, esc, db = _escrow(tmp_path, monkeypatch, chain="sepolia")

    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    assert configured_chain == []


def test_the_gate_parses_a_messy_list(settle_chains):
    from warden.web3.settlement import sending_enabled

    settle_chains(" base_sepolia , ,polygon_amoy ")
    assert sending_enabled("base_sepolia") and sending_enabled("polygon_amoy")
    assert not sending_enabled("sepolia")
    assert not sending_enabled("")


# ── every verdict is recorded ───────────────────────────────────────────────


def test_a_passing_verdict_is_recorded_whole(tmp_path, monkeypatch, settle_chains, configured_chain):
    svc, esc, db = _escrow(tmp_path, monkeypatch)
    svc.fund_escrow(esc.escrow_id, db_path=db)

    stored = svc._get(esc.escrow_id, db)
    verdict = json.loads(stored.preflight_verdict)
    assert verdict["ok"] is True and verdict["configured"] is True
    assert verdict["amount_minor"] == "1000000"
    assert stored.preflight_at, "when it ran is part of the record"


def test_a_failing_verdict_is_recorded_and_the_escrow_stays_put(tmp_path, monkeypatch, settle_chains):
    settle_chains("base_sepolia")
    sent: list[str] = []
    monkeypatch.setattr("warden.web3.smart_contract.call_escrow_result",
                        lambda *a, **k: sent.append(a[1]) or EscrowCallResult(ok=True))
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(ok=False, configured=True, reason="insufficient_allowance",
                               detail="buyer has approved 0 units"),
    )
    svc, esc, db = _escrow(tmp_path, monkeypatch)

    assert svc.fund_escrow(esc.escrow_id, db_path=db) is False
    stored = svc._get(esc.escrow_id, db)
    assert stored.status == "pending_deposit"
    assert json.loads(stored.preflight_verdict)["reason"] == "insufficient_allowance"
    assert sent == []


def test_an_unconfigured_deployment_still_reports_what_would_block(tmp_path, monkeypatch, settle_chains):
    """The real preflight, no mocks: production today. The verdict must name the
    missing seller address and the chain's token, not only "not configured"."""
    svc, esc, db = _escrow(tmp_path, monkeypatch, seller="", chain="sepolia")

    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True   # simulated, as before
    verdict = json.loads(svc._get(esc.escrow_id, db).preflight_verdict)
    names = {c["name"]: c["ok"] for c in verdict["checks"]}

    assert verdict["ok"] is False and verdict["configured"] is False
    assert names.get("no_seller_address") is False, names
    assert names.get("buyer_address_valid") is True, names
    assert names.get("token_configured") is False, "sepolia has no USDC configured"
