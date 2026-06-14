"""
warden/tests/test_api_negotiations.py
──────────────────────────────────────
4 tests for api_negotiations.py — start negotiation, counter-offer,
accept, and rejection.

Mirrors: warden/marketplace/api_negotiations.py
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

_TMP    = tempfile.gettempdir()
_DB     = os.path.join(_TMP, f"test_api_negotiations_{uuid.uuid4().hex}.db")
_CMRCDB = os.path.join(_TMP, f"test_commerce_neg_{uuid.uuid4().hex}.db")
_SEPDB  = os.path.join(_TMP, f"test_sep_neg_{uuid.uuid4().hex}.db")

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
    return generate_community_keypair(f"neg-a-{uuid.uuid4().hex[:6]}", kid="v1")


@pytest.fixture(scope="module")
def keypair_b():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"neg-b-{uuid.uuid4().hex[:6]}", kid="v1")


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
# 1. Buyer opens negotiation when price exceeds max_price (within stretch)
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_opens_when_price_too_high(seller_id, buyer_id, keypair_a, keypair_b):
    from warden.marketplace.buyer_agent import BuyerAgent
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.service import register_asset

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="rule", raw_data={"keyword": "neg_test"},
        keypair=keypair_a, db_path=_DB,
    )
    listing = SellerAgent(seller_id, keypair=keypair_a, db_path=_DB).auto_list(
        asset_id, asset_type="rule", base_price=16.0, pricing_strategy="fixed"
    )
    # max_price=15.0, listing=16.0, stretch=15.0×1.10=16.5 → within stretch → negotiating
    result = BuyerAgent(buyer_id, keypair=keypair_b, db_path=_DB).auto_buy(
        listing_id=listing.listing_id, max_price=15.0
    )
    assert result["status"] == "negotiating"
    assert "negotiation_id" in result
    assert result["offered_price"] == 15.0


# ─────────────────────────────────────────────────────────────────────────────
# 2. Counter-offer round
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_counter_offer(seller_id, buyer_id, keypair_a, keypair_b):
    from warden.marketplace.listing import publish_listing
    from warden.marketplace.negotiation import NegotiationEngine

    listing = publish_listing(
        asset_id="SEP-countertest", seller_agent=seller_id,
        community_id=_cid(), tenant_id=_tid(), asset_type="rule",
        price_usd=30.0, db_path=_DB,
    )
    engine = NegotiationEngine()
    neg    = engine.start_negotiation(
        buyer_agent_id=buyer_id, seller_agent_id=seller_id,
        listing_id=listing.listing_id, initial_price=30.0,
        db_path=_DB,
    )
    offer1 = engine.send_offer(neg.negotiation_id, buyer_id, 22.0, keypair=keypair_b, db_path=_DB)
    offer2 = engine.send_offer(neg.negotiation_id, seller_id, 26.0, keypair=keypair_a, db_path=_DB)

    assert offer1.offer_type == "offer"
    assert offer2.price == 26.0
    assert offer2.round == 2


# ─────────────────────────────────────────────────────────────────────────────
# 3. Accept closes at agreed price
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_accept(seller_id, buyer_id, keypair_a, keypair_b):
    from warden.marketplace.listing import publish_listing
    from warden.marketplace.negotiation import NegotiationEngine

    listing = publish_listing(
        asset_id="SEP-accepttest", seller_agent=seller_id,
        community_id=_cid(), tenant_id=_tid(), asset_type="rule",
        price_usd=25.0, db_path=_DB,
    )
    engine = NegotiationEngine()
    neg    = engine.start_negotiation(
        buyer_agent_id=buyer_id, seller_agent_id=seller_id,
        listing_id=listing.listing_id, initial_price=25.0,
        db_path=_DB,
    )
    engine.send_offer(neg.negotiation_id, buyer_id, 20.0, keypair=keypair_b, db_path=_DB)
    accept = engine.accept_offer(neg.negotiation_id, seller_id, keypair=keypair_a, db_path=_DB)

    assert accept.offer_type == "accept"
    status = engine.get_negotiation_status(neg.negotiation_id, db_path=_DB)
    assert status["status"] == "accepted"
    assert len(status["offers"]) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 4. Rejection marks negotiation as rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_rejection(seller_id, buyer_id):
    from warden.marketplace.listing import publish_listing
    from warden.marketplace.negotiation import NegotiationEngine

    listing = publish_listing(
        asset_id="SEP-rejecttest", seller_agent=seller_id,
        community_id=_cid(), tenant_id=_tid(), asset_type="rule",
        price_usd=50.0, db_path=_DB,
    )
    engine = NegotiationEngine()
    neg    = engine.start_negotiation(
        buyer_agent_id=buyer_id, seller_agent_id=seller_id,
        listing_id=listing.listing_id, initial_price=50.0,
        db_path=_DB,
    )
    rejected = engine.reject_offer(neg.negotiation_id, seller_id, "Price too low", db_path=_DB)
    assert rejected is True
    status = engine.get_negotiation_status(neg.negotiation_id, db_path=_DB)
    assert status["status"] == "rejected"
