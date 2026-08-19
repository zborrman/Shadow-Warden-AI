"""warden/tests/test_base_chain_registry.py — P1a chain registry invariants.

Two things this pins, both of which fail silently rather than loudly.

**RPC URLs must resolve per call.** The registry used to build its whole table
at module import, so a URL exported after the first import of `chains` was
invisible for the life of the process. That is the same defect the key-hygiene
rule already forbids for signing keys (`resolve_key` per call, never a
module-level snapshot), and on a settlement path it means an operator sets
`BASE_RPC_URL`, restarts nothing, and quietly keeps settling against the old
endpoint — or against none, which reads as "simulated".

**A token address must be checked against the chain.** A wrong but well-formed
USDC address does not raise. The transfer succeeds against whatever contract
lives at it, or against nothing, and the funds are gone with no error anywhere.
`verify_usdc_contract()` asks the contract for `symbol()` and `decimals()` so a
mistake becomes a refusal instead of a loss.

The addresses in the registry were confirmed on 2026-08-19 by querying the live
chains, not copied from documentation:

    base          8453   symbol='USDC' decimals=6
    base_sepolia  84532  symbol='USDC' decimals=6
"""

from __future__ import annotations

from typing import Any

import pytest

from warden.web3 import chains


class _FakeEth:
    def __init__(self, chain_id: int, responses: dict[str, bytes]) -> None:
        self.chain_id = chain_id
        self._responses = responses

    def call(self, tx: dict[str, Any]) -> bytes:
        return self._responses[tx["data"]]


class _FakeW3:
    """Minimal stand-in — the check only needs chain_id, call() and checksum."""

    def __init__(self, chain_id: int, symbol: str = "USDC", decimals: int = 6) -> None:
        encoded = (
            (32).to_bytes(32, "big")
            + len(symbol).to_bytes(32, "big")
            + symbol.encode().ljust(32, b"\x00")
        )
        self.eth = _FakeEth(
            chain_id,
            {
                chains._SELECTOR_SYMBOL: encoded,
                chains._SELECTOR_DECIMALS: decimals.to_bytes(32, "big"),
            },
        )

    @staticmethod
    def to_checksum_address(a: str) -> str:
        return a


# ── registry shape ────────────────────────────────────────────────────────────
def test_base_chains_are_registered() -> None:
    assert {"base", "base_sepolia"} <= chains.VALID_CHAINS


@pytest.mark.parametrize(
    ("chain", "chain_id"), [("base", 8453), ("base_sepolia", 84532)]
)
def test_chain_ids_match_the_public_networks(chain: str, chain_id: int) -> None:
    assert chains.get_chain(chain)["chain_id"] == chain_id


def test_only_base_mainnet_counts_as_real_value() -> None:
    """A testnet trade must never be mistaken for proof the rail works."""
    assert chains.is_mainnet("base") is True
    assert chains.is_mainnet("base_sepolia") is False
    assert chains.is_mainnet("sepolia") is False


def test_unknown_chain_raises() -> None:
    with pytest.raises(ValueError, match="Unknown chain"):
        chains.get_chain("ethereum_classic_but_purple")


# ── the snapshot bug ──────────────────────────────────────────────────────────
def test_rpc_url_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """Change the setting, and the very next get_chain() must see it."""
    before = chains.get_chain("base")["rpc_url"]
    monkeypatch.setattr(
        chains.settings, "base_rpc_url", "https://example.invalid/rpc", raising=False
    )
    after = chains.get_chain("base")["rpc_url"]
    assert after == "https://example.invalid/rpc", (
        "get_chain() snapshotted the RPC URL again — an operator setting "
        f"BASE_RPC_URL would keep settling against {before!r}"
    )


# ── the token check ───────────────────────────────────────────────────────────
def test_verify_accepts_a_real_usdc_contract() -> None:
    result = chains.verify_usdc_contract("base_sepolia", _FakeW3(84532))
    assert result["ok"] is True, result
    assert result["decimals"] == 6


def test_verify_rejects_a_contract_that_is_not_usdc() -> None:
    """The loss case: a plausible address that is some other token."""
    result = chains.verify_usdc_contract("base", _FakeW3(8453, symbol="WETH", decimals=18))
    assert result["ok"] is False
    assert "WETH" in result["reason"]


def test_verify_rejects_an_rpc_pointed_at_the_wrong_network() -> None:
    """Mainnet address, testnet endpoint — nothing about this errors on its own."""
    result = chains.verify_usdc_contract("base", _FakeW3(84532))
    assert result["ok"] is False
    assert "different network" in result["reason"]


def test_verify_reports_rather_than_raises() -> None:
    class _Exploding:
        @property
        def eth(self) -> Any:
            raise RuntimeError("rpc down")

        @staticmethod
        def to_checksum_address(a: str) -> str:
            return a

    result = chains.verify_usdc_contract("base", _Exploding())
    assert result["ok"] is False
    assert "rpc down" in result["reason"]


def test_verify_refuses_a_chain_with_no_usdc_configured() -> None:
    result = chains.verify_usdc_contract("sepolia", _FakeW3(11155111))
    assert result["ok"] is False
    assert "no USDC address" in result["reason"]
