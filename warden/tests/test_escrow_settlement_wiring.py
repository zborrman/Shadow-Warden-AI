"""
warden/tests/test_escrow_settlement_wiring.py — P1a.

`settlement_mode` used to be derived from an RPC URL, which is always present
(`BASE_RPC_URL` defaults to the public Base endpoint) and says nothing about
whether a transaction can be sent. These tests pin the two properties that
replaced it: capability is derived from the whole configuration, and the real
transaction path fails CLOSED.

The second matters more than it looks. The stub returned True on every error, so
an escrow release that never reached the chain was indistinguishable from one
that did — the failure mode that turns a marketplace into a way to lose other
people's money.
"""
from __future__ import annotations

import json
import sys
import types

import pytest

from warden.web3 import smart_contract as sc


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    for var in ("ESCROW_ABI_PATH", "WEB3_SIGNER_KEY", "ESCROW_CONTRACT_BASE"):
        monkeypatch.delenv(var, raising=False)
    sc._load_abi.cache_clear()
    yield
    sc._load_abi.cache_clear()


def _abi_file(tmp_path) -> str:
    p = tmp_path / "escrow.json"
    p.write_text(json.dumps([{"name": "release", "type": "function", "inputs": []}]))
    return str(p)


def _configure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("warden.web3.chains.get_chain",
                        lambda c: {"rpc_url": "https://rpc.example", "chain_id": 8453})
    monkeypatch.setitem(sys.modules, "web3", types.ModuleType("web3"))
    monkeypatch.setenv("ESCROW_ABI_PATH", _abi_file(tmp_path))
    monkeypatch.setenv("ESCROW_CONTRACT_BASE", "0x" + "11" * 20)
    monkeypatch.setenv("WEB3_SIGNER_KEY", "0x" + "22" * 32)


class TestCapabilityIsDerived:
    def test_nothing_configured_cannot_settle(self):
        cap = sc.settlement_capability("base")
        assert cap["can_settle"] is False
        assert cap["reason"], "a refusal with no reason reads as a network blip"

    @pytest.mark.parametrize("missing,reason", [
        ("ESCROW_CONTRACT_BASE", "no_contract"),
        ("WEB3_SIGNER_KEY", "no_signer"),
    ])
    def test_each_missing_piece_names_itself(self, monkeypatch, tmp_path, missing, reason):
        """Two out of three cannot move value, so two out of three must not claim to."""
        _configure(monkeypatch, tmp_path)
        monkeypatch.delenv(missing, raising=False)
        cap = sc.settlement_capability("base")
        assert cap["can_settle"] is False
        assert cap["reason"] == reason

    def test_the_abi_ships_with_the_build(self, monkeypatch, tmp_path):
        """`ESCROW_ABI_PATH` used to be a fourth thing to configure, and there
        was nothing in the image to point it at — `contracts/` is outside the
        warden build context. The ABI is a build artifact of the contract, not
        an operator decision, so it ships beside the module and the variable is
        now only an override."""
        _configure(monkeypatch, tmp_path)
        monkeypatch.delenv("ESCROW_ABI_PATH", raising=False)
        sc._load_abi.cache_clear()
        assert sc._PACKAGED_ABI.exists()
        assert sc.settlement_capability("base")["can_settle"] is True

    def test_an_unreadable_abi_still_refuses(self, monkeypatch, tmp_path):
        """Defaulting the path must not turn a wrong ABI into a silent one."""
        _configure(monkeypatch, tmp_path)
        monkeypatch.setenv("ESCROW_ABI_PATH", str(tmp_path / "nope.json"))
        sc._load_abi.cache_clear()
        cap = sc.settlement_capability("base")
        assert cap["can_settle"] is False
        assert cap["reason"] == "abi_unreadable"

    def test_an_rpc_alone_is_not_capability(self, monkeypatch):
        """The exact shape production shipped: a default RPC and nothing else."""
        monkeypatch.setattr("warden.web3.chains.get_chain",
                            lambda c: {"rpc_url": "https://mainnet.base.org", "chain_id": 8453})
        monkeypatch.setitem(sys.modules, "web3", types.ModuleType("web3"))
        assert sc.settlement_capability("base")["can_settle"] is False

    def test_fully_configured_can_settle(self, monkeypatch, tmp_path):
        _configure(monkeypatch, tmp_path)
        assert sc.settlement_capability("base")["can_settle"] is True


class TestCallEscrowFailsClosed:
    def test_unconfigured_still_simulates(self):
        """The state machine keeps working where no money was ever claimed."""
        assert sc.call_escrow("0xabc", "release", {}, "base") is True

    def test_a_configured_but_broken_chain_returns_false(self, monkeypatch, tmp_path):
        """Real mode: an error is a failure, not a success.

        The stub returned True here, so a release that never happened looked
        exactly like one that did.
        """
        _configure(monkeypatch, tmp_path)

        def _boom(*_a, **_kw):
            raise RuntimeError("node refused the connection")

        web3_mod = types.ModuleType("web3")
        web3_mod.Web3 = _boom  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "web3", web3_mod)

        assert sc.call_escrow("0x" + "11" * 20, "release", {}, "base") is False


class TestDeployUsesTheConfiguredInstance:
    def test_simulated_address_when_unconfigured(self):
        addr = sc.deploy_escrow("b", "s", "l", "n", "base")
        assert addr.endswith(":base")
        assert sc._contract_address("base") == ""

    def test_configured_address_is_returned(self, monkeypatch, tmp_path):
        _configure(monkeypatch, tmp_path)
        assert sc.deploy_escrow("b", "s", "l", "n", "base") == "0x" + "11" * 20 + ":base"
