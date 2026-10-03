"""
warden/tests/test_deploy_escrow_code_check.py

The first real escrow deployment (2026-10-02, Base Sepolia) succeeded — receipt
status 1, 4277 bytes of runtime code, byte-identical to this repository's build
— and `scripts/deploy_escrow.py` reported it as "the deployment did not take".
The public RPC is load-balanced; `get_code` reached a node that had not seen the
receipt's block yet. A false failure on a deploy tells the operator to deploy
again, which puts a second escrow on chain.

These tests drive `_code_landed` with a fake node instead of reading the script.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "deploy_escrow.py"
_CODE = b"\x60" * 4277
_RCPT = {"status": 1, "contractAddress": "0x899Ff611e4F7A9Ea59d0e86733A4C45445cBDcF8", "blockNumber": 47592002}


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("deploy_escrow", _SCRIPT)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    sys.modules["deploy_escrow"] = m
    spec.loader.exec_module(m)
    return m


class _Node:
    """Answers empty for the first `lag` calls, then the code — a node behind."""

    def __init__(self, lag: int, refuse_block: bool = False):
        self.lag, self.calls, self.refuse_block = lag, 0, refuse_block
        self.eth = self

    def get_code(self, addr, block_identifier="latest"):
        self.calls += 1
        if self.refuse_block and block_identifier != "latest":
            raise ValueError("header not found")
        return b"" if self.calls <= self.lag else _CODE


def test_a_lagging_node_is_not_a_failed_deploy(mod):
    assert mod._code_landed(_Node(lag=3), _RCPT, attempts=4, wait_s=0) is True


def test_a_node_refusing_the_receipt_block_still_gets_asked_latest(mod):
    assert mod._code_landed(_Node(lag=1, refuse_block=True), _RCPT, attempts=3, wait_s=0) is True


def test_code_that_never_appears_is_reported(mod):
    assert mod._code_landed(_Node(lag=10_000), _RCPT, attempts=3, wait_s=0) is False


def test_a_reverted_receipt_fails_immediately(mod):
    node = _Node(lag=0)
    with pytest.raises(SystemExit):
        mod._code_landed(node, {**_RCPT, "status": 0}, attempts=3, wait_s=0)
    assert node.calls == 0, "a reverted deploy was retried as if it might still land"


# ── nonce: the second failure of the same lag ─────────────────────────────────


class _StaleCountNode:
    """Reports the count it had before the last send — a node one tx behind."""

    def __init__(self, start: int):
        self.count = start
        self.eth = self

    def get_transaction_count(self, address, block_identifier="latest"):
        return self.count  # never advances: every answer is stale after a send


def test_a_stale_count_does_not_reuse_a_nonce(mod):
    """The first live --trade died with "replacement transaction underpriced":
    the token deployed with nonce 1, then a lagging node said the count was
    still 1, and the funding transfer reused it."""
    mod._NEXT_NONCE.clear()
    node, sender = _StaleCountNode(start=1), "0xSender"
    first = mod._next_nonce(node, sender)
    mod._NEXT_NONCE[sender] = first + 1          # what _send records after sending
    second = mod._next_nonce(node, sender)
    assert (first, second) == (1, 2), "the second transaction reused the first one's nonce"


def test_the_chain_still_wins_when_it_is_ahead(mod):
    """A transaction sent from elsewhere moves the chain past the local count."""
    mod._NEXT_NONCE.clear()
    mod._NEXT_NONCE["0xSender"] = 3
    assert mod._next_nonce(_StaleCountNode(start=7), "0xSender") == 7


# ── visibility barrier: the third failure of the same lag ─────────────────────


class _BlockNode:
    """Load-balanced: answers from a sequence of nodes at different heights."""

    def __init__(self, heights):
        self.heights, self.i = list(heights), 0
        self.eth = self

    @property
    def block_number(self):
        h = self.heights[min(self.i, len(self.heights) - 1)]
        self.i += 1
        return h


def test_one_fresh_node_is_not_enough(mod):
    """After `approve` landed in block 100, one node answering 101 then a lagging
    one answering 99 must not count as visible — that is the read pattern that
    made the deposit's gas estimate see an allowance of zero."""
    node = _BlockNode([101, 99, 101, 101, 101])
    assert mod._await_visible(node, {"blockNumber": 100}, needed=3, timeout_s=5, wait_s=0) is True
    assert node.i == 5, "the barrier accepted before three consecutive caught-up reads"


def test_the_barrier_gives_up_instead_of_hanging(mod):
    node = _BlockNode([99])
    assert mod._await_visible(node, {"blockNumber": 100}, needed=3, timeout_s=0.05, wait_s=0) is False
