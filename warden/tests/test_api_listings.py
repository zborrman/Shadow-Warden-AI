"""
warden/tests/test_api_listings.py
───────────────────────────────────
6 tests for api_listings.py — seller/buyer agents, listing lifecycle,
purchase flow, and budget gate.

Mirrors: warden/marketplace/api_listings.py
"""
from __future__ import annotations

import os
import tempfile
import uuid
from unittest.mock import patch

import pytest

_TMP    = tempfile.gettempdir()
_DB     = os.path.join(_TMP, f"test_api_listings_{uuid.uuid4().hex}.db")
_CMRCDB = os.path.join(_TMP, f"test_commerce_listings_{uuid.uuid4().hex}.db")
_SEPDB  = os.path.join(_TMP, f"test_sep_listings_{uuid.uuid4().hex}.db")

os.environ.setdefault("MARKETPLACE_DB_PATH", _DB)
os.environ.setdefault("COMMERCE_DB_PATH",    _CMRCDB)
os.environ.setdefault("SEP_DB_PATH",         _SEPDB)


def _tid() -> str:
    return f"t-{uuid.uuid4().hex[:8]}"

def _cid() -> str:
    return f"c-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def keypair_a():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"lst-a-{uuid.uuid4().hex[:6]}", kid="v1")


@pytest.fixture(scope="module")
def keypair_b():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"lst-b-{uuid.uuid4().hex[:6]}", kid="v1")


@pytest.fixture(scope="module")
def seller_id(keypair_a) -> str:
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=keypair_a.ed25519_pub_b64,
        capabilities=["marketplace_sell"],
        db_path=_DB,
    )
    return agent.agent_id


@pytest.fixture(scope="module")
def buyer_id(keypair_b) -> str:
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=keypair_b.ed25519_pub_b64,
        capabilities=["marketplace_buy"],
        db_path=_DB,
    )
    return agent.agent_id


# ─────────────────────────────────────────────────────────────────────────────
# 1. SellerAgent evaluates market demand
# ─────────────────────────────────────────────────────────────────────────────

def test_seller_agent_evaluate_demand(seller_id):
    from warden.marketplace.seller_agent import SellerAgent
    result = SellerAgent(seller_id, db_path=_DB).evaluate_market_demand("rule")
    assert "demand_score" in result
    assert 0.0 <= result["demand_score"] <= 1.0
    assert result["recommended_price"] > 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. SellerAgent auto-lists an asset
# ─────────────────────────────────────────────────────────────────────────────

def test_seller_agent_auto_list(seller_id, keypair_a):
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.service import register_asset

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="rule", raw_data={"keyword": "autolist_test"},
        keypair=keypair_a, db_path=_DB,
    )
    listing = SellerAgent(seller_id, keypair=keypair_a, db_path=_DB).auto_list(
        asset_id, asset_type="rule", base_price=8.0, pricing_strategy="dynamic"
    )
    assert listing.listing_id.startswith("LST-")
    assert listing.seller_agent == seller_id
    assert listing.price_usd >= 8.0
    assert listing.status == "active"


# ─────────────────────────────────────────────────────────────────────────────
# 3. BuyerAgent searches listings
# ─────────────────────────────────────────────────────────────────────────────

def test_buyer_agent_search_assets(seller_id, buyer_id, keypair_a):
    from warden.marketplace.buyer_agent import BuyerAgent
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.service import register_asset

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="model",
        raw_data={
            "osi_version": "1.0", "id": "search_test",
            "metrics":    [{"name": "m1", "expression": "count(*)"}],
            "dimensions": [{"name": "d1", "column": "tenant_id"}],
        },
        keypair=keypair_a, db_path=_DB,
    )
    SellerAgent(seller_id, keypair=keypair_a, db_path=_DB).auto_list(
        asset_id, asset_type="model", base_price=5.0, pricing_strategy="fixed"
    )
    results = BuyerAgent(buyer_id, db_path=_DB).search_assets({"asset_type": "model"})
    assert len(results) >= 1
    assert all("seller_rep_score" in r for r in results)


# ─────────────────────────────────────────────────────────────────────────────
# 4. BuyerAgent evaluates seller reputation
# ─────────────────────────────────────────────────────────────────────────────

def test_buyer_agent_evaluate_seller_risk(seller_id, buyer_id):
    from warden.marketplace.buyer_agent import BuyerAgent
    score = BuyerAgent(buyer_id, db_path=_DB).evaluate_seller_risk(seller_id)
    assert 0.0 <= score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Successful purchase when price <= max_price
# ─────────────────────────────────────────────────────────────────────────────

def test_auto_buy_success(seller_id, buyer_id, keypair_a):
    from warden.marketplace.buyer_agent import BuyerAgent
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.service import register_asset

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="rule", raw_data={"keyword": "buy_test"},
        keypair=keypair_a, db_path=_DB,
    )
    listing = SellerAgent(seller_id, keypair=keypair_a, db_path=_DB).auto_list(
        asset_id, asset_type="rule", base_price=10.0, pricing_strategy="fixed"
    )
    result = BuyerAgent(buyer_id, db_path=_DB).auto_buy(
        listing_id=listing.listing_id, max_price=15.0
    )
    assert result["status"] == "purchased"
    assert "purchase_id" in result
    assert "escrow_id" in result


# ─────────────────────────────────────────────────────────────────────────────
# 6. Budget block when commerce budget returns "block"
# ─────────────────────────────────────────────────────────────────────────────

def test_auto_buy_budget_blocked(seller_id, buyer_id, keypair_a):
    from warden.marketplace.buyer_agent import BuyerAgent
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.service import register_asset

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="rule", raw_data={"keyword": "budget_block_test"},
        keypair=keypair_a, db_path=_DB,
    )
    listing = SellerAgent(seller_id, keypair=keypair_a, db_path=_DB).auto_list(
        asset_id, asset_type="rule", base_price=5.0, pricing_strategy="fixed"
    )
    with patch(
        "warden.marketplace.buyer_agent.BuyerAgent._check_budget",
        return_value=False,
    ):
        result = BuyerAgent(buyer_id, db_path=_DB).auto_buy(
            listing_id=listing.listing_id, max_price=50.0
        )
    assert result["status"] == "budget_blocked"
