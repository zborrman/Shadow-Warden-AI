"""
warden/tests/test_escrow_remembers_what_it_sent.py — R1-b.

docs/onchain-settlement-design.md specified three things #403 did not land:

* §3 — the escrow snapshots what preflight verified (trade id, token, decimals,
  integer amount) and the hash of each transaction behind a transition.
  `call_escrow` returned a bool and logged 18 characters of the hash, so an
  operator could not look a transition up and a retry could not ask the chain.
* §4 / §8.3 — `deposit` reverting `TradeExists()` means *already funded*. It was
  read as a failure, so one lost receipt left funds held by the contract and the
  gateway record stuck in `pending_deposit`, with every retry refused.
* rule 27 — `ensure_escrow_columns` ran every ALTER on every connection.

The TradeExists tests use a revert produced by the compiled contract on a local
EVM, not a hand-built exception: the first decoder recognised only hex, and a
genuine revert arrives as a bytes-repr. It returned "" until run against one.
"""
from __future__ import annotations

from contextlib import contextmanager

import pytest

from warden.marketplace.escrow import EscrowService
from warden.web3.settlement import Preflight, trade_id_for
from warden.web3.smart_contract import EscrowCallResult, classify_call_failure

_BUYER = "0x52908400098527886E0F7030069857D2E4169EE7"
_SELLER = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


# ── TradeExists, against the compiled contract ─────────────────────────────


@pytest.fixture()
def evm():
    pytest.importorskip("eth_tester", reason="local EVM not installed")
    from eth_tester import EthereumTester, PyEVMBackend
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider

    import warden.tests.test_escrow_contract_on_evm as h

    try:
        abi, code = h._artifacts("escrow")
        token_abi, token_code = h._artifacts("mock_erc20", "test")
    except FileNotFoundError:
        pytest.skip("escrow artifacts not built")

    w3 = Web3(EthereumTesterProvider(EthereumTester(PyEVMBackend())))
    arbiter, buyer, seller, operator = w3.eth.accounts[:4]
    token = h._deploy(w3, token_abi, token_code, arbiter)
    escrow = h._deploy(w3, abi, code, arbiter, arbiter, operator)
    token.functions.mint(buyer, h._AMOUNT * 10).transact({"from": arbiter})
    token.functions.approve(escrow.address, h._AMOUNT * 10).transact({"from": buyer})
    return {"w3": w3, "abi": abi, "escrow": escrow, "token": token, "h": h,
            "arbiter": arbiter, "buyer": buyer, "seller": seller, "operator": operator}


def _revert_of(call):
    try:
        call()
    except Exception as exc:  # the exception IS the fixture
        return exc
    pytest.fail("expected the contract to revert")


def _deposit_fn(evm, trade_id=b"\x01" * 32, amount=None):
    h = evm["h"]
    return evm["escrow"].functions.deposit(
        trade_id, evm["buyer"], evm["seller"], evm["token"].address,
        amount if amount is not None else h._AMOUNT, h._WINDOW,
    )


def test_a_second_deposit_reverting_trade_exists_counts_as_funded(evm):
    _deposit_fn(evm).transact({"from": evm["operator"]})
    exc = _revert_of(lambda: _deposit_fn(evm).build_transaction({"from": evm["operator"]}))

    result = classify_call_failure("deposit", exc, evm["abi"])
    assert result == EscrowCallResult(ok=True, error="TradeExists", already_funded=True)


def test_trade_exists_on_any_other_call_is_still_a_failure(evm):
    """Only `deposit` has TradeExists as its goal state."""
    _deposit_fn(evm).transact({"from": evm["operator"]})
    exc = _revert_of(lambda: _deposit_fn(evm).build_transaction({"from": evm["operator"]}))

    assert classify_call_failure("confirmReceipt", exc, evm["abi"]).ok is False


def test_a_different_deposit_revert_is_never_read_as_funded(evm):
    """The dangerous direction: a deposit that moved nothing recorded as funded.

    An unfunded buyer makes the token transfer fail. That must stay a failure.
    """
    poor_buyer = evm["w3"].eth.accounts[5]
    h = evm["h"]
    fn = evm["escrow"].functions.deposit(
        b"\x09" * 32, poor_buyer, evm["seller"], evm["token"].address, h._AMOUNT, h._WINDOW,
    )
    exc = _revert_of(lambda: fn.build_transaction({"from": evm["operator"]}))

    result = classify_call_failure("deposit", exc, evm["abi"])
    assert result.ok is False
    assert result.already_funded is False


def test_the_decoder_reads_the_hex_form_a_real_node_returns():
    """web3 against a node raises ContractCustomError with the selector as hex."""
    import json
    from pathlib import Path

    abi = json.loads(Path("warden/web3/abi/escrow.abi.json").read_text(encoding="utf-8"))
    abi = abi.get("abi", abi) if isinstance(abi, dict) else abi

    class ContractCustomError(Exception):
        def __init__(self, data):
            super().__init__(data)
            self.data = data

    exc = ContractCustomError("0x822b55c5")
    assert classify_call_failure("deposit", exc, abi).already_funded is True


# ── snapshot + transaction hashes ──────────────────────────────────────────


@pytest.fixture()
def escrow(tmp_path, monkeypatch):
    from warden.marketplace import escrow as escrow_mod

    escrow_mod.reset_escrow_column_memo()
    monkeypatch.setattr(EscrowService, "_payout_address",
                        staticmethod(lambda aid: _BUYER if "buyer" in aid else _SELLER))
    db = str(tmp_path / "escrow.db")
    svc = EscrowService()
    esc = svc.create_escrow(
        listing_id="LST-1", buyer_agent_id="did:shadow:buyer",
        seller_agent_id="did:shadow:seller", amount_usd=1.0,
        chain="base_sepolia", db_path=db,
    )
    yield svc, esc, db
    escrow_mod.reset_escrow_column_memo()


@pytest.fixture()
def ready_chain(monkeypatch):
    """A configured chain that records calls and hands back distinct tx hashes."""
    calls: list[str] = []

    def _send(_addr, fn_name, _params, _chain):
        calls.append(fn_name)
        return EscrowCallResult(ok=True, tx_hash="0x" + f"{len(calls):064x}")

    monkeypatch.setattr("warden.web3.smart_contract.call_escrow_result", _send)
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(
            ok=True, configured=True, trade_id=trade_id_for(kw["escrow_id"]),
            amount_minor=1_000_000, token_address=_USDC, token_decimals=6,
        ),
    )
    return calls


def test_funding_snapshots_what_preflight_verified(escrow, ready_chain):
    svc, esc, db = escrow
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True

    stored = svc._get(esc.escrow_id, db)
    assert stored.trade_id == trade_id_for(esc.escrow_id)
    assert stored.token_address == _USDC
    assert stored.token_decimals == 6
    assert stored.amount_minor == "1000000", "an integer, as TEXT — never a float"


def test_each_transition_records_its_own_transaction(escrow, ready_chain):
    svc, esc, db = escrow
    assert svc.fund_escrow(esc.escrow_id, db_path=db)
    assert svc.deliver_asset(esc.escrow_id, "0x" + "ab" * 32, db_path=db)
    assert svc.confirm_receipt(esc.escrow_id, db_path=db)

    stored = svc._get(esc.escrow_id, db)
    assert stored.fund_tx == "0x" + f"{1:064x}"
    assert stored.deliver_tx == "0x" + f"{2:064x}"
    assert stored.settle_tx == "0x" + f"{3:064x}"


def test_a_recorded_hash_is_never_overwritten(escrow, ready_chain):
    svc, esc, db = escrow
    svc.fund_escrow(esc.escrow_id, db_path=db)
    original = svc._get(esc.escrow_id, db).fund_tx

    svc._record_tx(esc.escrow_id, "deposit", "0x" + "ff" * 32, db)
    assert svc._get(esc.escrow_id, db).fund_tx == original


def test_an_already_funded_deposit_advances_without_a_hash(escrow, monkeypatch):
    """TradeExists after a lost receipt: the escrow must reach `funded`."""
    svc, esc, db = escrow
    monkeypatch.setattr(
        "warden.web3.smart_contract.call_escrow_result",
        lambda *a, **kw: EscrowCallResult(ok=True, error="TradeExists", already_funded=True),
    )
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(ok=True, configured=True, trade_id=trade_id_for(kw["escrow_id"]),
                               amount_minor=1_000_000, token_address=_USDC, token_decimals=6),
    )
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    stored = svc._get(esc.escrow_id, db)
    assert stored.status == "funded"
    assert stored.fund_tx == "", "no hash invented for a transaction this call did not send"


def test_simulated_deployments_record_nothing(escrow):
    """§8.5: with settlement unconfigured the state machine runs, nothing is claimed."""
    svc, esc, db = escrow
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is True
    stored = svc._get(esc.escrow_id, db)
    assert (stored.trade_id, stored.amount_minor, stored.fund_tx) == ("", "", "")


# ── rule 27: no schema work per connection ─────────────────────────────────


class _CountingConnection:
    """Counts ALTER *attempts*, including ones that fail.

    sqlite's trace callback only fires for statements that prepare, and a
    duplicate-column ALTER fails at prepare — so a trace-based count reads zero
    for exactly the defect it is meant to catch. On Turso every attempt is a
    round trip whether or not it succeeds, so attempts are what cost money.
    """

    def __init__(self, con, sink):
        self._con, self._sink = con, sink

    def execute(self, sql, *args):
        if "ALTER TABLE" in sql.upper():
            self._sink.append(sql)
        return self._con.execute(sql, *args)


@contextmanager
def _counting_alters(con, sink):
    yield _CountingConnection(con, sink)


def test_a_complete_table_issues_no_alter(tmp_path):
    import sqlite3

    from warden.marketplace.escrow import _ESCROW_DDL, ensure_escrow_columns

    con = sqlite3.connect(str(tmp_path / "complete.db"))
    con.executescript(_ESCROW_DDL)
    alters: list[str] = []
    with _counting_alters(con, alters) as counted:
        ensure_escrow_columns(counted)
    assert alters == [], f"attempted {len(alters)} ALTERs against a table that needs none"


def test_an_old_table_gets_exactly_its_missing_columns(tmp_path):
    import sqlite3

    from warden.marketplace.escrow import _ADDED_COLUMNS, ensure_escrow_columns

    con = sqlite3.connect(str(tmp_path / "old.db"))
    con.execute(
        "CREATE TABLE marketplace_escrow (escrow_id TEXT PRIMARY KEY, listing_id TEXT, "
        "chain TEXT NOT NULL DEFAULT 'sepolia', created_at TEXT, expires_at TEXT)"
    )
    alters: list[str] = []
    with _counting_alters(con, alters) as counted:
        ensure_escrow_columns(counted)
    assert len(alters) == len(_ADDED_COLUMNS) - 1, "chain already existed; everything else was missing"

    alters.clear()
    with _counting_alters(con, alters) as counted:
        ensure_escrow_columns(counted)
    assert alters == [], "a second pass must be free"


def test_a_real_migration_failure_propagates(tmp_path, monkeypatch):
    """Only duplicate-column is tolerated; the old code swallowed every error."""
    import sqlite3

    from warden.marketplace.escrow import ensure_escrow_columns

    con = sqlite3.connect(str(tmp_path / "missing.db"))
    # No marketplace_escrow table at all: PRAGMA returns nothing, ALTER fails.
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        ensure_escrow_columns(con)


# ── review round 1: selector at offset zero, pending hashes ────────────────


def _escrow_abi():
    import json
    from pathlib import Path

    abi = json.loads(Path("warden/web3/abi/escrow.abi.json").read_text(encoding="utf-8"))
    return abi.get("abi", abi) if isinstance(abi, dict) else abi


_TRADE_EXISTS = bytes.fromhex("822b55c5")
_OTHER_SELECTOR = bytes.fromhex("deadbeef")


@pytest.mark.parametrize("encoding", ["raw_bytes", "hex_data", "bytes_repr"])
def test_trade_exists_bytes_inside_arguments_are_not_trade_exists(encoding):
    """The money-safety bug a substring match had: a token's own error whose
    ARGUMENTS happen to contain 82 2b 55 c5 must not read as an already-funded
    deposit. Only the selector at offset zero names the error."""
    payload = _OTHER_SELECTOR + b"\x00" * 28 + _TRADE_EXISTS + b"\x00" * 28

    class RevertError(Exception):
        pass

    if encoding == "raw_bytes":
        exc = RevertError(payload)
    elif encoding == "hex_data":
        exc = RevertError("reverted")
        exc.data = "0x" + payload.hex()
    else:
        exc = RevertError(f"execution reverted: {payload!r}")

    result = classify_call_failure("deposit", exc, _escrow_abi())
    assert result.ok is False
    assert result.already_funded is False


@pytest.mark.parametrize("encoding", ["raw_bytes", "hex_data", "bytes_repr"])
def test_trade_exists_at_offset_zero_is_recognised_in_every_encoding(encoding):
    class RevertError(Exception):
        pass

    if encoding == "raw_bytes":
        exc = RevertError(_TRADE_EXISTS)
    elif encoding == "hex_data":
        exc = RevertError("reverted")
        exc.data = "0x" + _TRADE_EXISTS.hex()
    else:
        exc = RevertError(f"execution reverted: {_TRADE_EXISTS!r}")

    assert classify_call_failure("deposit", exc, _escrow_abi()).already_funded is True


def test_an_unconfirmed_transaction_is_recorded_as_pending_and_does_not_advance(escrow, monkeypatch):
    svc, esc, db = escrow
    monkeypatch.setattr(
        "warden.web3.smart_contract.call_escrow_result",
        lambda *a, **kw: EscrowCallResult(ok=False, tx_hash="0x" + "aa" * 32, error="TimeExhausted"),
    )
    monkeypatch.setattr(
        "warden.web3.settlement.settlement_preflight",
        lambda **kw: Preflight(ok=True, configured=True, trade_id=trade_id_for(kw["escrow_id"]),
                               amount_minor=1_000_000, token_address=_USDC, token_decimals=6),
    )
    assert svc.fund_escrow(esc.escrow_id, db_path=db) is False
    stored = svc._get(esc.escrow_id, db)
    assert stored.status == "pending_deposit"
    assert stored.fund_tx == "pending:0x" + "aa" * 32


def test_a_confirmed_hash_replaces_a_pending_one_but_nothing_replaces_a_confirmed_one(escrow):
    svc, esc, db = escrow
    svc._record_tx(esc.escrow_id, "deposit", "0x" + "aa" * 32, db, confirmed=False)
    svc._record_tx(esc.escrow_id, "deposit", "0x" + "bb" * 32, db, confirmed=True)
    assert svc._get(esc.escrow_id, db).fund_tx == "0x" + "bb" * 32

    svc._record_tx(esc.escrow_id, "deposit", "0x" + "cc" * 32, db, confirmed=True)
    svc._record_tx(esc.escrow_id, "deposit", "0x" + "dd" * 32, db, confirmed=False)
    assert svc._get(esc.escrow_id, db).fund_tx == "0x" + "bb" * 32
