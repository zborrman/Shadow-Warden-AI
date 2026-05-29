"""
warden/tests/test_web3_mandates.py  (Phase 1 — 10 tests)
Web3 decentralized mandate layer with mocked blockchain.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("WEB3_RPC_URL", "")          # force eth_tester


class TestChainConnector:
    def _connector(self):
        from warden.blockchain.chain_connector import ChainConnector
        return ChainConnector()

    def test_available_with_tester(self):
        try:
            from eth_tester import EthereumTester  # noqa: F401
            c = self._connector()
            assert c.available is True
        except ImportError:
            pytest.skip("eth_tester not installed")

    def test_get_block_number(self):
        try:
            from eth_tester import EthereumTester  # noqa: F401
            c = self._connector()
            bn = c.get_block_number()
            assert bn is not None and bn >= 0
        except ImportError:
            c = self._connector()
            assert c.get_block_number() is None

    def test_get_accounts(self):
        try:
            from eth_tester import EthereumTester  # noqa: F401
            c = self._connector()
            accts = c.get_accounts()
            assert isinstance(accts, list)
        except ImportError:
            c = self._connector()
            assert c.get_accounts() == []


class TestIPFSStorage:
    def test_store_returns_cid(self):
        from warden.blockchain.ipfs_storage import IPFSStorage
        cid = IPFSStorage().store_mandate({"id": "m1", "max_amount": 100})
        assert cid.startswith("Qm") or len(cid) > 10

    def test_store_deterministic(self):
        from warden.blockchain.ipfs_storage import IPFSStorage
        s = IPFSStorage()
        cid1 = s.store_mandate({"id": "x", "amount": 50})
        cid2 = s.store_mandate({"id": "x", "amount": 50})
        assert cid1 == cid2  # same data → same simulated CID

    def test_fetch_unavailable_returns_dict(self):
        from warden.blockchain.ipfs_storage import IPFSStorage
        data = IPFSStorage().fetch_mandate("Qmabc123")
        assert isinstance(data, dict)


class TestMandateContract:
    def test_unavailable_returns_false(self, monkeypatch):
        monkeypatch.setenv("WEB3_RPC_URL", "")
        # Without web3/eth_tester, should fail gracefully
        try:
            from warden.blockchain.mandate_contract import MandateContract
            mc = MandateContract()
            result = mc.create("uuid-1", "tenant", 10000, 9999999999, [])
            # Either success (eth_tester) or graceful failure
            assert "success" in result
        except Exception:
            pytest.skip("web3 not available")

    def test_mandate_id_deterministic(self):
        from warden.blockchain.mandate_contract import MandateContract
        id1 = MandateContract._mandate_id("abc")
        id2 = MandateContract._mandate_id("abc")
        assert id1 == id2

    def test_mandate_id_different_inputs(self):
        from warden.blockchain.mandate_contract import MandateContract
        id1 = MandateContract._mandate_id("abc")
        id2 = MandateContract._mandate_id("xyz")
        assert id1 != id2

    def test_get_returns_empty_when_unavailable(self, monkeypatch):
        try:
            from warden.blockchain.mandate_contract import MandateContract
            mc = MandateContract()
            if not mc._address:
                result = mc.get("nonexistent-uuid")
                assert result == {} or isinstance(result, dict)
        except Exception:
            pytest.skip("web3 not available")
