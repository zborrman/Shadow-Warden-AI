"""
warden/tests/test_cross_chain.py
─────────────────────────────────
8 tests for cross-chain escrow (MKT-08).
All Web3 calls are mocked — no real RPC node required.
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("MARKETPLACE_DB_PATH", "/tmp/test_cross_chain.db")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


def _aid() -> str:
    return f"did:shadow:{uuid.uuid4().hex[:32]}"


# ── chains.py ────────────────────────────────────────────────────────────────

class TestChains:
    def test_valid_chains_contains_expected_keys(self):
        from warden.web3.chains import VALID_CHAINS
        assert "sepolia" in VALID_CHAINS
        assert "polygon_amoy" in VALID_CHAINS
        assert "arbitrum_sepolia" in VALID_CHAINS

    def test_get_chain_returns_dict(self):
        from warden.web3.chains import get_chain
        cfg = get_chain("sepolia")
        assert cfg["chain_id"] == 11155111
        assert "rpc_url" in cfg

    def test_get_chain_raises_for_unknown(self):
        from warden.web3.chains import get_chain
        with pytest.raises(ValueError, match="Unknown chain"):
            get_chain("mainnet_does_not_exist")

    def test_chain_label_returns_human_readable(self):
        from warden.web3.chains import chain_label
        assert chain_label("polygon_amoy") == "Polygon Amoy"
        assert chain_label("arbitrum_sepolia") == "Arbitrum Sepolia"


# ── smart_contract.py ────────────────────────────────────────────────────────

class TestSmartContract:
    def test_deploy_escrow_returns_address_with_chain_suffix(self):
        from warden.web3.smart_contract import deploy_escrow
        addr = deploy_escrow("buyer1", "seller1", "list1", "nonce1", "sepolia")
        assert ":" in addr
        assert addr.endswith(":sepolia")
        assert addr.startswith("0x")

    def test_deploy_escrow_different_chains_produce_different_addresses(self):
        from warden.web3.smart_contract import deploy_escrow
        a1 = deploy_escrow("b", "s", "l", "n", "sepolia")
        a2 = deploy_escrow("b", "s", "l", "n", "polygon_amoy")
        assert a1 != a2

    def test_strip_chain_suffix_splits_correctly(self):
        from warden.web3.smart_contract import strip_chain_suffix
        addr, chain = strip_chain_suffix("0xdeadbeef:polygon_amoy")
        assert addr == "0xdeadbeef"
        assert chain == "polygon_amoy"

    def test_strip_chain_suffix_defaults_to_sepolia(self):
        from warden.web3.smart_contract import strip_chain_suffix
        addr, chain = strip_chain_suffix("0xdeadbeef")
        assert addr == "0xdeadbeef"
        assert chain == "sepolia"


# ── Escrow dataclass + create_escrow ─────────────────────────────────────────

class TestEscrowChain:
    def _db(self) -> str:
        return f"/tmp/test_cc_esc_{uuid.uuid4().hex[:8]}.db"

    def test_create_escrow_stores_chain(self):
        from warden.marketplace.escrow import EscrowService
        db = self._db()
        esc = EscrowService().create_escrow(
            listing_id="list-1",
            buyer_agent_id=_aid(),
            seller_agent_id=_aid(),
            amount_usd=10.0,
            chain="polygon_amoy",
            db_path=db,
        )
        assert esc.chain == "polygon_amoy"
        assert esc.contract_address.endswith(":polygon_amoy")

    def test_create_escrow_default_chain_is_sepolia(self):
        from warden.marketplace.escrow import EscrowService
        db = self._db()
        esc = EscrowService().create_escrow(
            listing_id="list-2",
            buyer_agent_id=_aid(),
            seller_agent_id=_aid(),
            amount_usd=5.0,
            db_path=db,
        )
        assert esc.chain == "sepolia"

    def test_get_escrow_roundtrip_preserves_chain(self):
        from warden.marketplace.escrow import EscrowService
        db = self._db()
        svc = EscrowService()
        esc = svc.create_escrow(
            listing_id="list-3",
            buyer_agent_id=_aid(),
            seller_agent_id=_aid(),
            amount_usd=7.5,
            chain="arbitrum_sepolia",
            db_path=db,
        )
        fetched = svc.get_escrow(esc.escrow_id, db_path=db)
        assert fetched is not None
        assert fetched.chain == "arbitrum_sepolia"

    def test_to_dict_includes_chain(self):
        from warden.marketplace.escrow import EscrowService
        db = self._db()
        esc = EscrowService().create_escrow(
            listing_id="list-4",
            buyer_agent_id=_aid(),
            seller_agent_id=_aid(),
            amount_usd=3.0,
            chain="polygon_amoy",
            db_path=db,
        )
        d = esc.to_dict()
        assert d["chain"] == "polygon_amoy"
