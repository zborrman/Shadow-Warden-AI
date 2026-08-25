"""
warden/tests/test_escrow_contract_on_evm.py — P1a.

The compiled escrow, executed on a real EVM.

Everything before this proved the contract is *well-formed*: it compiles, and its
ABI matches both the source and the calls the gateway makes. None of that says
the money ends up in the right place. These tests run the lifecycle the gateway
drives — deposit, deliverAsset, confirmReceipt — against py-evm with a mock ERC-20,
and assert on balances rather than on return values.

No chain, no faucet, no key: the whole point is that this can run in CI before
anyone funds a wallet. It is not a substitute for an audit or for one real
testnet trade, both of which come before mainnet.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

import pytest

eth_tester = pytest.importorskip("eth_tester", reason="local EVM not installed")
pytest.importorskip("web3")

from eth_tester import EthereumTester, PyEVMBackend  # noqa: E402
from eth_tester.exceptions import TransactionFailed  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.providers.eth_tester import EthereumTesterProvider  # noqa: E402

_ROOT = Path(__file__).resolve().parents[2]
_C = _ROOT / "contracts"
_AMOUNT = 1_000_000          # 1.00 USDC at 6 decimals
_WINDOW = 48 * 3600          # matches ESCROW_DELIVERY_TIMEOUT_HOURS


def _artifacts(stem: str, subdir: str = "") -> tuple[list, str]:
    base = _C / subdir if subdir else _C
    abi = json.loads((base / f"{stem}.abi.json").read_text(encoding="utf-8"))
    code = (base / f"{stem}.bin").read_text(encoding="utf-8").strip()
    return abi, code


def _deploy(w3, abi, code, sender, *args):
    tx = w3.eth.contract(abi=abi, bytecode=code).constructor(*args).transact({"from": sender})
    addr = w3.eth.wait_for_transaction_receipt(tx)["contractAddress"]
    return w3.eth.contract(address=addr, abi=abi)


@pytest.fixture()
def chain():
    for stem, sub in (("escrow", ""), ("mock_erc20", "test")):
        base = _C / sub if sub else _C
        if not (base / f"{stem}.bin").exists():
            pytest.skip(f"{stem}.bin not built — run scripts/build_escrow.sh")

    w3 = Web3(EthereumTesterProvider(EthereumTester(PyEVMBackend())))
    arbiter, buyer, seller = w3.eth.accounts[0], w3.eth.accounts[1], w3.eth.accounts[2]

    token = _deploy(w3, *_artifacts("mock_erc20", "test"), arbiter)
    escrow = _deploy(w3, *_artifacts("escrow"), arbiter, arbiter)

    token.functions.mint(buyer, _AMOUNT * 10).transact({"from": arbiter})
    token.functions.approve(escrow.address, _AMOUNT * 10).transact({"from": buyer})
    return w3, escrow, token, arbiter, buyer, seller


def _selector(abi: list, error_name: str) -> bytes:
    """4-byte selector of a custom error, from the ABI the gateway will use."""
    entry = next(e for e in abi if e.get("type") == "error" and e["name"] == error_name)
    sig = f"{error_name}({','.join(i['type'] for i in entry['inputs'])})"
    return Web3.keccak(text=sig)[:4]


@contextmanager
def expect_revert(error_name: str):
    """Assert the contract reverted with a specific custom error.

    `pytest.raises(Exception)` passes when the transaction fails for any reason —
    a typo in the ABI, an out-of-gas, a wrong address — so it cannot tell "the
    guard fired" from "the call never worked". The selector says which `revert`
    ran, which is the thing being claimed.
    """
    abi, _ = _artifacts("escrow")
    expected = _selector(abi, error_name)
    with pytest.raises(TransactionFailed) as exc:
        yield
    payload = exc.value.args[0] if exc.value.args else b""
    needle = bytes(expected)
    if isinstance(payload, bytes):
        found = needle in payload
    else:
        # eth-tester stringifies the revert as "execution reverted: b'fìNæ'",
        # so the selector arrives as its own bytes-repr rather than as bytes.
        text = str(payload)
        found = repr(needle)[2:-1] in text or needle.hex() in text.lower()
    assert found, f"expected a {error_name} revert, got {payload!r}"


def _deposit(escrow, token, buyer, seller, sender, trade_id=b"\x01" * 32):
    escrow.functions.deposit(
        trade_id, buyer, seller, token.address, _AMOUNT, _WINDOW
    ).transact({"from": sender})
    return trade_id


class TestHappyPath:
    def test_the_seller_is_paid_only_after_the_buyer_confirms(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)

        assert token.functions.balanceOf(escrow.address).call() == _AMOUNT
        assert token.functions.balanceOf(seller).call() == 0, "paid before delivery"

        escrow.functions.deliverAsset(tid, b"\x02" * 32).transact({"from": seller})
        assert token.functions.balanceOf(seller).call() == 0, (
            "delivery alone must not move funds — only the buyer or the deadline does"
        )

        escrow.functions.confirmReceipt(tid).transact({"from": buyer})
        assert token.functions.balanceOf(seller).call() == _AMOUNT
        assert token.functions.balanceOf(escrow.address).call() == 0
        assert escrow.functions.stateOf(tid).call() == 3, "expected Released"


class TestRefundPath:
    def test_the_buyer_is_refunded_when_delivery_never_happens(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        before = token.functions.balanceOf(buyer).call()
        tid = _deposit(escrow, token, buyer, seller, arbiter)

        # The arbiter may cancel before the deadline; anyone may after it.
        escrow.functions.cancelDeposit(tid).transact({"from": arbiter})

        assert token.functions.balanceOf(buyer).call() == before
        assert escrow.functions.stateOf(tid).call() == 4, "expected Refunded"

    def test_a_stranger_cannot_cancel_before_the_deadline(self, chain):
        """A refund anyone can trigger at will is a way to grief the seller."""
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        with expect_revert("DeadlineNotReached"):
            escrow.functions.cancelDeposit(tid).transact({"from": w3.eth.accounts[4]})


class TestDisputePath:
    def test_the_arbiter_can_return_the_funds_to_the_buyer(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        before = token.functions.balanceOf(buyer).call()
        tid = _deposit(escrow, token, buyer, seller, arbiter)

        escrow.functions.raiseDispute(tid, "asset never arrived").transact({"from": buyer})
        assert escrow.functions.stateOf(tid).call() == 5, "expected Disputed"

        escrow.functions.resolveDispute(tid, True).transact({"from": arbiter})
        assert token.functions.balanceOf(buyer).call() == before
        assert token.functions.balanceOf(seller).call() == 0

    def test_only_the_arbiter_resolves(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        escrow.functions.raiseDispute(tid, "x").transact({"from": buyer})
        with expect_revert("NotArbiter"):
            escrow.functions.resolveDispute(tid, True).transact({"from": buyer})


class TestStateMachineIsEnforcedOnChain:
    def test_confirming_before_delivery_reverts(self, chain):
        """The gateway's state machine is advisory; this one holds the money."""
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        with expect_revert("WrongState"):
            escrow.functions.confirmReceipt(tid).transact({"from": buyer})

    def test_the_same_trade_cannot_be_funded_twice(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        with expect_revert("TradeExists"):
            _deposit(escrow, token, buyer, seller, arbiter, tid)

    def test_a_stranger_cannot_confirm_someone_elses_purchase(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        escrow.functions.deliverAsset(tid, b"\x02" * 32).transact({"from": seller})
        with expect_revert("NotBuyer"):
            escrow.functions.confirmReceipt(tid).transact({"from": w3.eth.accounts[5]})
