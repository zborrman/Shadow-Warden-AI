"""
warden/tests/test_deploy_escrow_script.py — P1a.

The deployment script, executed.

`scripts/deploy_escrow.py` is the thing that will run once, against a real chain,
holding a real key, with nobody able to undo it. A script in that position that
has never been executed is a plan, and the failure it hides is not "the escrow is
wrong" — the escrow is tested — but "the script that drives it is". A typo in an
argument order, a missing `build_transaction`, a nonce reused between two senders:
each of those fails after the first transaction lands, leaving a half-deployed
contract and a funded stranger's address.

So the whole flow runs here on py-evm: deploy, fund two derived parties, mint,
approve, deposit, deliver, confirm, and assert on balances. Nothing is stubbed
except the network. What the real run then adds is a gas market and a mempool,
not a first execution.

`--check` is covered too, because it is the command someone runs while deciding
whether they have enough testnet ETH, and a readiness report that lies is worse
than none.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

import pytest

eth_tester = pytest.importorskip("eth_tester", reason="local EVM not installed")
pytest.importorskip("web3")

from eth_tester import EthereumTester, PyEVMBackend  # noqa: E402
from eth_tester.backends.pyevm.main import get_default_account_keys  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.providers.eth_tester import EthereumTesterProvider  # noqa: E402

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "deploy_escrow.py"
_META = {"chain_id": 84532, "block_explorer": "https://sepolia.basescan.org"}


def _load():
    """Import the script by path; it is not a package module."""
    if not _SCRIPT.exists():
        pytest.skip("deploy_escrow.py not present")
    spec = importlib.util.spec_from_file_location("deploy_escrow", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def script():
    return _load()


@pytest.fixture()
def chain(monkeypatch):
    for stem, sub in (("escrow", ""), ("mock_erc20", "test")):
        base = _ROOT / "contracts" / (sub or "")
        if not (base / f"{stem}.bin").exists():
            pytest.skip(f"{stem}.bin not built — run scripts/build_escrow.sh")

    keys = get_default_account_keys()
    w3 = Web3(EthereumTesterProvider(EthereumTester(PyEVMBackend())))
    signer_key = "0x" + keys[0].to_bytes().hex()
    monkeypatch.setenv("WEB3_SIGNER_KEY", signer_key)
    return w3, w3.eth.account.from_key(signer_key)


def _args(**over) -> argparse.Namespace:
    # py-evm prices gas at 1 gwei and fills an unestimated transaction with the
    # 30M block limit, so a sender needs ~0.03 ETH on hand before `estimate_gas`
    # will even run. Base Sepolia charges four orders of magnitude less, which is
    # why the script's own default is 0.0003 and this is not.
    base = {"chain": "base_sepolia", "fund": 50_000_000_000_000_000,
            "rpc": "", "check": False, "deploy": True, "trade": True, "escrow": ""}
    base.update(over)
    return argparse.Namespace(**base)


class TestTheScriptRuns:
    def test_deploy_then_one_full_trade_settles_to_the_seller(self, script, chain, capsys):
        w3, acct = chain
        addr = script.cmd_deploy(w3, _META, _args(), acct)
        assert w3.eth.get_code(addr), "no code at the deployed address"

        script.cmd_trade(w3, _META, _args(), acct, addr)

        out = capsys.readouterr().out
        assert "Settled." in out
        # The assertions that matter are inside cmd_trade: it calls sys.exit(1)
        # through _fail() if the balances disagree, so reaching here is the pass.
        assert "expected 3 = Released" in out

    def test_the_three_parties_are_distinct_addresses(self, script, chain):
        """A trade between one key and itself would satisfy every balance check."""
        w3, acct = chain
        key = script._signer_key()
        buyer = script._derive(w3, key, "buyer")
        seller = script._derive(w3, key, "seller")
        assert len({acct.address, buyer.address, seller.address}) == 3

    def test_the_parties_are_reproducible_from_the_signer(self, script, chain):
        """Re-running must reach the same addresses, or funds strand in old ones."""
        w3, _ = chain
        key = script._signer_key()
        assert script._derive(w3, key, "buyer").address == \
            script._derive(w3, key, "buyer").address
        assert script._derive(w3, key, "buyer").address != \
            script._derive(w3, "0x" + "11" * 32, "buyer").address


class TestItRefusesTheThingsItShould:
    def test_a_mainnet_chain_is_refused(self, script, monkeypatch):
        """Escrow.sol is unaudited with a single-key arbiter."""
        with pytest.raises(SystemExit) as exc:
            script._connect("base")
        assert exc.value.code == 1

    def test_a_node_on_the_wrong_chain_is_refused(self, script, monkeypatch):
        """The flag says base_sepolia; only the node can confirm it.

        A wrong RPC URL in an environment file is the ordinary way a "testnet"
        deployment lands somewhere else, and by then it has already spent gas.
        """
        import web3 as web3_mod

        class _Eth:
            chain_id = 1
            block_number = 0

        class _Onion:
            def inject(self, *a, **k):
                pass

        class _Fake:
            HTTPProvider = staticmethod(lambda *a, **k: None)
            eth = _Eth()
            middleware_onion = _Onion()

            def __init__(self, *a, **k):
                pass

            def is_connected(self):
                return True

        monkeypatch.setattr(web3_mod, "Web3", _Fake)
        with pytest.raises(SystemExit) as exc:
            script._connect("base_sepolia")
        assert exc.value.code == 1

    def test_an_unknown_chain_is_refused(self, script):
        with pytest.raises(SystemExit):
            script._connect("not_a_chain")

    def test_check_without_a_key_reports_and_stops(self, script, chain, monkeypatch, capsys):
        w3, _ = chain
        monkeypatch.delenv("WEB3_SIGNER_KEY", raising=False)
        script.cmd_check(w3, _META, _args(deploy=False, trade=False, check=True))
        out = capsys.readouterr().out
        assert "WEB3_SIGNER_KEY is unset" in out
        assert "faucet" in out

    def test_check_reports_readiness_against_a_real_balance(self, script, chain, capsys):
        w3, acct = chain
        script.cmd_check(w3, _META, _args(deploy=False, trade=False, check=True))
        out = capsys.readouterr().out
        assert acct.address in out
        assert "READY" in out, "the default eth-tester account holds 1M ETH"
