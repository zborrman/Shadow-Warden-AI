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
    # A distinct account, not `arbiter` again: the two roles were one address
    # until 2026-09-03, and a fixture that reuses the arbiter as operator cannot
    # tell a working split from no split at all.
    operator = w3.eth.accounts[3]

    token = _deploy(w3, *_artifacts("mock_erc20", "test"), arbiter)
    # _deploy(w3, abi, code, sender, *ctor_args) — `sender` eats the first one.
    escrow = _deploy(w3, *_artifacts("escrow"), arbiter, arbiter, operator)

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


class TestAccessControlAddedAfterSlither:
    """The guards Slither's `arbitrary-send-erc20` pointed at, and two it missed.

    Every test here fails against the contract as first written. That matters:
    the twelve tests above all passed against the vulnerable version, because
    they only ever called each function as the party entitled to call it. A
    guard that no test exercises is indistinguishable from no guard.
    """

    def test_a_stranger_cannot_spend_a_buyers_standing_allowance(self, chain):
        """The high finding, reproduced.

        `deposit` pulls `amount` from a caller-supplied `buyer`. With no check on
        `msg.sender`, anyone could sweep any address that had approved this
        escrow into a trade of their own devising — attacker as seller, deadline
        of their choosing. They could not complete it (`confirmReceipt` checks
        the buyer) but the funds would be locked, and `raiseDispute` would freeze
        them pending the arbiter. Infinite approval is the common integration.
        """
        w3, escrow, token, arbiter, buyer, seller = chain
        attacker = w3.eth.accounts[6]
        before = token.functions.balanceOf(buyer).call()

        with expect_revert("NotBuyer"):
            escrow.functions.deposit(
                b"\x09" * 32, buyer, attacker, token.address, _AMOUNT, _WINDOW
            ).transact({"from": attacker})

        assert token.functions.balanceOf(buyer).call() == before

    def test_the_buyer_may_deposit_for_itself(self, chain):
        """The guard must not break the ordinary direct-buyer integration."""
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = b"\x0a" * 32
        escrow.functions.deposit(
            tid, buyer, seller, token.address, _AMOUNT, _WINDOW
        ).transact({"from": buyer})
        assert escrow.functions.stateOf(tid).call() == 1, "expected Funded"

    def test_a_stranger_cannot_claim_delivery(self, chain):
        """Slither did not flag this; `deliverAsset` had no sender check at all."""
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        with expect_revert("NotSeller"):
            escrow.functions.deliverAsset(tid, b"\x02" * 32).transact(
                {"from": w3.eth.accounts[6]}
            )

    def test_a_stranger_cannot_freeze_a_funded_trade(self, chain):
        """The comment said "either party"; the code accepted anyone.

        A stranger moving a trade to Disputed locks the funds until the arbiter
        rules — a denial of service on every trade in flight, for the price of
        one transaction each.
        """
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        with expect_revert("NotParty"):
            escrow.functions.raiseDispute(tid, "not mine").transact(
                {"from": w3.eth.accounts[6]}
            )
        assert escrow.functions.stateOf(tid).call() == 1, "still Funded"

    def test_both_real_parties_may_still_dispute(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        for party, tid in ((buyer, b"\x0b" * 32), (seller, b"\x0c" * 32)):
            _deposit(escrow, token, buyer, seller, arbiter, tid)
            escrow.functions.raiseDispute(tid, "x").transact({"from": party})
            assert escrow.functions.stateOf(tid).call() == 5

    def test_a_zero_arbiter_deployment_is_refused(self, chain):
        """Unrecoverable: no dispute could resolve, no trade cancel early."""
        w3, escrow, token, arbiter, buyer, seller = chain
        abi, code = _artifacts("escrow")
        with pytest.raises(TransactionFailed):
            w3.eth.contract(abi=abi, bytecode=code).constructor(
                "0x" + "00" * 20, arbiter
            ).transact({"from": arbiter})

    def test_a_zero_operator_deployment_is_refused(self, chain):
        """Merely useless rather than unrecoverable — the parties could still
        call for themselves — but it silently disables every gateway-relayed
        trade, so it is refused at the same gate."""
        w3, escrow, token, arbiter, buyer, seller = chain
        abi, code = _artifacts("escrow")
        with pytest.raises(TransactionFailed):
            w3.eth.contract(abi=abi, bytecode=code).constructor(
                arbiter, "0x" + "00" * 20
            ).transact({"from": arbiter})


class TestTheOperatorRelaysButCannotDecide:
    """The point of splitting `arbiter` in two.

    They were one address, and that made the multisig impossible rather than
    merely absent: `deposit`, `deliverAsset` and `confirmReceipt` accept the
    arbiter so the gateway can act for a counterparty, and those run on every
    trade, unattended. A 2-of-3 multisig in `arbiter` would have needed two
    humans to sign each deposit, so the honest options were a hot multisig —
    which is not a multisig — or no split.

    Now the key that must be hot cannot decide a dispute, and the key that
    decides disputes never has to be hot. These tests pin both halves; a test
    that only checked the operator *can* relay would pass just as well if the
    split had never happened.
    """

    @staticmethod
    def _operator(w3, escrow):
        addr = escrow.functions.operator().call()
        assert addr == w3.eth.accounts[3], "fixture and contract disagree"
        return addr

    def test_the_operator_can_carry_a_trade_end_to_end(self, chain):
        w3, escrow, token, arbiter, buyer, seller = chain
        op = self._operator(w3, escrow)

        tid = _deposit(escrow, token, buyer, seller, op)
        escrow.functions.deliverAsset(tid, b"\xab" * 32).transact({"from": op})
        escrow.functions.confirmReceipt(tid).transact({"from": op})

        assert token.functions.balanceOf(seller).call() == _AMOUNT

    def test_the_operator_may_raise_a_dispute_for_a_party(self, chain):
        """Freezing a trade is a party action the gateway relays. It decides
        nothing — the arbiter still has to resolve it."""
        w3, escrow, token, arbiter, buyer, seller = chain
        op = self._operator(w3, escrow)
        tid = _deposit(escrow, token, buyer, seller, op)
        escrow.functions.raiseDispute(tid, "not delivered").transact({"from": op})
        assert escrow.functions.stateOf(tid).call() == 5   # Disputed

    def test_the_operator_cannot_resolve_a_dispute(self, chain):
        """The whole reason for the split. A compromised VPS must not be able
        to award itself the escrowed funds."""
        w3, escrow, token, arbiter, buyer, seller = chain
        op = self._operator(w3, escrow)
        tid = _deposit(escrow, token, buyer, seller, op)
        escrow.functions.raiseDispute(tid, "stalled").transact({"from": op})

        with pytest.raises(TransactionFailed):
            escrow.functions.resolveDispute(tid, True).transact({"from": op})

        # And the arbiter still can, so the refusal is about who asked.
        escrow.functions.resolveDispute(tid, True).transact({"from": arbiter})
        assert token.functions.balanceOf(buyer).call() >= _AMOUNT

    def test_the_operator_cannot_cancel_before_the_deadline(self, chain):
        """An early cancel refunds the buyer — a decision about who gets the
        money, not a step along the agreed path."""
        w3, escrow, token, arbiter, buyer, seller = chain
        op = self._operator(w3, escrow)
        tid = _deposit(escrow, token, buyer, seller, op)

        with pytest.raises(TransactionFailed):
            escrow.functions.cancelDeposit(tid).transact({"from": op})

        escrow.functions.cancelDeposit(tid).transact({"from": arbiter})
        assert escrow.functions.stateOf(tid).call() == 4   # Refunded

    def test_the_arbiter_keeps_every_power_it_had(self, chain):
        """The split adds a role; it must not quietly remove one, or an existing
        deployment loses the ability to act for a party."""
        w3, escrow, token, arbiter, buyer, seller = chain
        tid = _deposit(escrow, token, buyer, seller, arbiter)
        escrow.functions.deliverAsset(tid, b"\xcd" * 32).transact({"from": arbiter})
        escrow.functions.confirmReceipt(tid).transact({"from": arbiter})
        assert token.functions.balanceOf(seller).call() == _AMOUNT

    def test_a_stranger_is_still_refused_everywhere(self, chain):
        """Adding an allowed sender must not widen the door for anyone else."""
        w3, escrow, token, arbiter, buyer, seller = chain
        stranger = w3.eth.accounts[4]
        with pytest.raises(TransactionFailed):
            _deposit(escrow, token, buyer, seller, stranger, trade_id=b"\x09" * 32)
