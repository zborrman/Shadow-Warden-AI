"""
warden/tests/test_marketplace_trading.py
─────────────────────────────────────────
15 tests for Community M2M Agentic Marketplace — Phase 2: Autonomous Trading.

Covers:
  1–2   SellerAgent: market demand + auto-list
  3–4   BuyerAgent: search + seller reputation
  5–6   Purchase flow (price ≤ max_price, budget block)
  7–9   Negotiation: offer → counter-offer → accept
  10    Negotiation: rejection
  11–13 Escrow: deploy → fund → deliver → confirm
  14    Escrow: dispute and resolution by arbitrator
  15    Escrow: cancel after timeout
"""
from __future__ import annotations

import os
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

# ── DB isolation ──────────────────────────────────────────────────────────────
_TMP = tempfile.gettempdir()
_DB  = os.path.join(_TMP, f"test_trading_{uuid.uuid4().hex}.db")
os.environ.setdefault("MARKETPLACE_DB_PATH",  _DB)
os.environ.setdefault("COMMERCE_DB_PATH",     os.path.join(_TMP, f"test_commerce_trd_{uuid.uuid4().hex}.db"))
os.environ.setdefault("SEP_DB_PATH",          os.path.join(_TMP, f"test_sep_trd_{uuid.uuid4().hex}.db"))
os.environ.setdefault("ANTHROPIC_API_KEY",    "")
os.environ.setdefault("WARDEN_API_KEY",       "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED","true")
os.environ.setdefault("REDIS_URL",            "memory://")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tid() -> str:
    return f"t-{uuid.uuid4().hex[:8]}"

def _cid() -> str:
    return f"c-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def keypair_a():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"comm-a-{uuid.uuid4().hex[:6]}", kid="v1")


@pytest.fixture(scope="module")
def keypair_b():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"comm-b-{uuid.uuid4().hex[:6]}", kid="v1")


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


@pytest.fixture(scope="module")
def sample_asset_id(seller_id, keypair_a) -> str:
    from warden.marketplace.service import register_asset
    return register_asset(
        tenant_id=_tid(),
        seller_agent_id=seller_id,
        asset_type="rule",
        raw_data={"keyword": "test_trading_rule"},
        keypair=keypair_a,
        db_path=_DB,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. SellerAgent evaluates market demand
# ─────────────────────────────────────────────────────────────────────────────

def test_seller_agent_evaluate_demand(seller_id):
    from warden.marketplace.seller_agent import SellerAgent
    result = SellerAgent(seller_id, db_path=_DB).evaluate_market_demand("rule")
    assert "demand_score" in result
    assert 0.0 <= result["demand_score"] <= 1.0
    assert "recommended_price" in result
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
    seller = SellerAgent(seller_id, keypair=keypair_a, db_path=_DB)
    listing = seller.auto_list(asset_id, asset_type="rule", base_price=8.0, pricing_strategy="dynamic")

    assert listing.listing_id.startswith("LST-")
    assert listing.seller_agent == seller_id
    assert listing.price_usd >= 8.0   # dynamic >= base
    assert listing.status == "active"


# ─────────────────────────────────────────────────────────────────────────────
# 3. BuyerAgent searches listings
# ─────────────────────────────────────────────────────────────────────────────

def test_buyer_agent_search_assets(seller_id, buyer_id, keypair_a):
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.service import register_asset
    from warden.marketplace.buyer_agent import BuyerAgent

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="model",
        raw_data={
            "osi_version": "1.0", "id": "search_test",
            "metrics": [{"name": "m1", "expression": "count(*)"}],
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
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.buyer_agent import BuyerAgent
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
# 6. Budget block when semantic_budget returns "block"
# ─────────────────────────────────────────────────────────────────────────────

def test_auto_buy_budget_blocked(seller_id, buyer_id, keypair_a):
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.buyer_agent import BuyerAgent
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


# ─────────────────────────────────────────────────────────────────────────────
# 7. Negotiation: buyer opens negotiation (price > max_price)
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_opens_when_price_too_high(seller_id, buyer_id, keypair_a, keypair_b):
    from warden.marketplace.seller_agent import SellerAgent
    from warden.marketplace.buyer_agent import BuyerAgent
    from warden.marketplace.service import register_asset

    asset_id = register_asset(
        tenant_id=_tid(), seller_agent_id=seller_id,
        asset_type="rule", raw_data={"keyword": "neg_test"},
        keypair=keypair_a, db_path=_DB,
    )
    listing = SellerAgent(seller_id, keypair=keypair_a, db_path=_DB).auto_list(
        asset_id, asset_type="rule", base_price=16.0, pricing_strategy="fixed"
    )

    # max_price=15.0, listing=16.0, stretch_limit=15.0*1.10=16.5 → within stretch → negotiating
    result = BuyerAgent(buyer_id, keypair=keypair_b, db_path=_DB).auto_buy(
        listing_id=listing.listing_id, max_price=15.0
    )
    assert result["status"] == "negotiating"
    assert "negotiation_id" in result
    assert result["offered_price"] == 15.0


# ─────────────────────────────────────────────────────────────────────────────
# 8. Negotiation: counter-offer round
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_counter_offer(seller_id, buyer_id, keypair_a, keypair_b):
    from warden.marketplace.negotiation import NegotiationEngine
    from warden.marketplace.listing import publish_listing

    listing = publish_listing(
        asset_id="SEP-countertest", seller_agent=seller_id,
        community_id=_cid(), tenant_id=_tid(), asset_type="rule",
        price_usd=30.0, db_path=_DB,
    )
    engine = NegotiationEngine()
    neg = engine.start_negotiation(
        buyer_agent_id=buyer_id, seller_agent_id=seller_id,
        listing_id=listing.listing_id, initial_price=30.0,
        db_path=_DB,
    )
    # Buyer offers lower price
    offer1 = engine.send_offer(neg.negotiation_id, buyer_id, 22.0, keypair=keypair_b, db_path=_DB)
    # Seller counter-offers
    offer2 = engine.send_offer(neg.negotiation_id, seller_id, 26.0, keypair=keypair_a, db_path=_DB)

    assert offer1.offer_type == "offer"
    assert offer2.price == 26.0
    assert offer2.round == 2


# ─────────────────────────────────────────────────────────────────────────────
# 9. Negotiation: accept closes at agreed price
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_accept(seller_id, buyer_id, keypair_a, keypair_b):
    from warden.marketplace.negotiation import NegotiationEngine
    from warden.marketplace.listing import publish_listing

    listing = publish_listing(
        asset_id="SEP-accepttest", seller_agent=seller_id,
        community_id=_cid(), tenant_id=_tid(), asset_type="rule",
        price_usd=25.0, db_path=_DB,
    )
    engine = NegotiationEngine()
    neg = engine.start_negotiation(
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
# 10. Negotiation: rejection
# ─────────────────────────────────────────────────────────────────────────────

def test_negotiation_rejection(seller_id, buyer_id):
    from warden.marketplace.negotiation import NegotiationEngine
    from warden.marketplace.listing import publish_listing

    listing = publish_listing(
        asset_id="SEP-rejecttest", seller_agent=seller_id,
        community_id=_cid(), tenant_id=_tid(), asset_type="rule",
        price_usd=50.0, db_path=_DB,
    )
    engine = NegotiationEngine()
    neg = engine.start_negotiation(
        buyer_agent_id=buyer_id, seller_agent_id=seller_id,
        listing_id=listing.listing_id, initial_price=50.0,
        db_path=_DB,
    )
    rejected = engine.reject_offer(neg.negotiation_id, seller_id, "Price too low", db_path=_DB)
    assert rejected is True
    status = engine.get_negotiation_status(neg.negotiation_id, db_path=_DB)
    assert status["status"] == "rejected"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Escrow: create returns simulated contract address
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_create(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService

    escrow = EscrowService().create_escrow(
        listing_id="LST-TEST01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=10.0, db_path=_DB,
    )
    assert escrow.escrow_id.startswith("ESC-")
    assert escrow.status == "pending_deposit"
    assert escrow.contract_address.startswith("0x")
    assert len(escrow.contract_address) == 42


# ─────────────────────────────────────────────────────────────────────────────
# 12. Escrow: fund → deliver → confirm completes lifecycle
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_full_lifecycle(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()

    escrow = svc.create_escrow(
        listing_id="LST-FULL01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=15.0, db_path=_DB,
    )
    assert svc.fund_escrow(escrow.escrow_id, db_path=_DB) is True

    funded = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert funded.status == "funded"

    import hashlib
    asset_hash = "0x" + hashlib.sha256(b"test_asset_payload").hexdigest()
    assert svc.deliver_asset(escrow.escrow_id, asset_hash, db_path=_DB) is True

    delivered = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert delivered.status == "delivered"
    assert delivered.asset_hash == asset_hash

    assert svc.confirm_receipt(escrow.escrow_id, db_path=_DB) is True

    confirmed = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert confirmed.status == "confirmed"


# ─────────────────────────────────────────────────────────────────────────────
# 13. Escrow: fund then deliver cannot be skipped (wrong status guards)
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_status_guards(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()

    escrow = svc.create_escrow(
        listing_id="LST-GUARD01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=5.0, db_path=_DB,
    )
    # Cannot deliver before funding
    assert svc.deliver_asset(escrow.escrow_id, "0xabcd", db_path=_DB) is False
    # Cannot confirm before delivering
    assert svc.confirm_receipt(escrow.escrow_id, db_path=_DB) is False


# ─────────────────────────────────────────────────────────────────────────────
# 14. Escrow: dispute raised and resolved by arbitrator
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_dispute_and_resolution(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()

    escrow = svc.create_escrow(
        listing_id="LST-DISP01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=20.0, db_path=_DB,
    )
    svc.fund_escrow(escrow.escrow_id, db_path=_DB)
    svc.raise_dispute(escrow.escrow_id, "Asset hash mismatch", db_path=_DB)

    disputed = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert disputed.status == "disputed"
    assert "mismatch" in disputed.dispute_reason

    svc.resolve_dispute(escrow.escrow_id, release_to_buyer=True, db_path=_DB)
    resolved = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert resolved.status == "resolved_buyer"


# ─────────────────────────────────────────────────────────────────────────────
# 15. Escrow: cancel after timeout refunds buyer
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_cancel_after_timeout(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService, _conn, _ensure_schema
    svc = EscrowService()

    escrow = svc.create_escrow(
        listing_id="LST-TMOUT01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=8.0, db_path=_DB,
    )
    svc.fund_escrow(escrow.escrow_id, db_path=_DB)

    # Manually expire the escrow by back-dating expires_at
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    import sqlite3
    con = sqlite3.connect(_DB)
    con.execute(
        "UPDATE marketplace_escrow SET expires_at=? WHERE escrow_id=?",
        (past, escrow.escrow_id),
    )
    con.commit()
    con.close()

    ok = svc.cancel_escrow(escrow.escrow_id, db_path=_DB)
    assert ok is True

    cancelled = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert cancelled.status == "cancelled"
