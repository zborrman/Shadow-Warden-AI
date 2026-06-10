"""
warden/marketplace/buyer_agent.py
───────────────────────────────────
BuyerAgent — autonomous buyer that searches listings, evaluates seller
reputation, checks budget, and purchases or initiates negotiation.

Budget check
────────────
  Calls semantic_budget.check_budget() (fail-open: allows purchase if unavailable).
  Only hard-blocks when status == "block" (budget exceeded).

Negotiation strategy
─────────────────────
  When listing.price_usd > max_price:
    1. Open a negotiation session.
    2. Send initial offer at max_price.
    3. If counter-offer ≤ threshold (max_price * BUYER_STRETCH_FACTOR), auto-accept.
    4. Otherwise leave negotiation open for seller to respond.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("warden.marketplace.buyer_agent")

_DB_PATH       = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_STRETCH_FACTOR = float(os.getenv("MARKETPLACE_BUYER_STRETCH", "1.10"))
_MIN_REP_SCORE  = float(os.getenv("MARKETPLACE_MIN_SELLER_REP", "0.0"))


class BuyerAgent:
    """
    Autonomous buyer on behalf of a registered marketplace agent.
    """

    def __init__(self, agent_id: str, keypair=None, db_path: str = _DB_PATH) -> None:
        self.agent_id = agent_id
        self.keypair  = keypair
        self.db_path  = db_path

    # ── Public API ────────────────────────────────────────────────────────────

    def search_assets(
        self,
        criteria: dict,
    ) -> list[dict]:
        """
        Search active listings matching *criteria*.

        Supported keys: asset_type, community_id, max_price, min_rep_score, limit.
        Results are enriched with seller reputation band.
        """
        from warden.marketplace.listing import get_listings
        from warden.marketplace.reputation import ReputationEngine

        rep_engine = ReputationEngine()
        listings = get_listings(
            community_id=criteria.get("community_id"),
            asset_type=criteria.get("asset_type"),
            max_price=criteria.get("max_price"),
            limit=int(criteria.get("limit", 20)),
            db_path=self.db_path,
        )

        min_rep = float(criteria.get("min_rep_score", _MIN_REP_SCORE))
        results = []
        for lst in listings:
            if lst.seller_agent == self.agent_id:
                continue   # don't buy own listings
            rep = rep_engine.get_score(lst.seller_agent, db_path=self.db_path)
            if rep.score < min_rep:
                continue
            row = lst.to_dict()
            row["seller_rep_score"] = rep.score
            row["seller_rep_band"]  = rep.band
            results.append(row)
        return results

    def evaluate_seller_risk(self, seller_agent_id: str) -> float:
        """Return the seller's composite reputation score (0.0–1.0)."""
        from warden.marketplace.reputation import ReputationEngine
        return ReputationEngine().get_score(seller_agent_id, db_path=self.db_path).score

    def auto_buy(
        self,
        listing_id: str,
        max_price: float,
        mandate_id: str = "",
        tenant_id: str = "",
    ) -> dict:
        """
        Attempt to purchase *listing_id* at or below *max_price*.

        Returns:
          {"status": "purchased"|"negotiating"|"budget_blocked"|"price_rejected",
           "purchase_id": str, "negotiation_id": str, ...}
        """
        from warden.marketplace.listing import get_listing, create_purchase, finalize_purchase
        from warden.marketplace.escrow import EscrowService
        from warden.marketplace.negotiation import NegotiationEngine

        listing = get_listing(listing_id, db_path=self.db_path)
        if listing is None:
            return {"status": "not_found", "listing_id": listing_id}
        if listing.status != "active":
            return {"status": "listing_unavailable", "listing_id": listing_id}

        # Budget check (fail-open)
        if not self._check_budget(listing.price_usd, tenant_id):
            return {"status": "budget_blocked", "listing_id": listing_id}

        # Reputation gate
        rep = self.evaluate_seller_risk(listing.seller_agent)
        if rep < _MIN_REP_SCORE and rep > 0:
            return {"status": "seller_rep_too_low", "seller_rep": rep}

        # Straight purchase if price acceptable
        if listing.price_usd <= max_price:
            purchase = create_purchase(
                listing_id=listing.listing_id,
                asset_id=listing.asset_id,
                buyer_agent=self.agent_id,
                seller_agent=listing.seller_agent,
                price_paid=listing.price_usd,
                db_path=self.db_path,
            )
            escrow = EscrowService().create_escrow(
                listing_id=listing.listing_id,
                buyer_agent_id=self.agent_id,
                seller_agent_id=listing.seller_agent,
                amount_usd=listing.price_usd,
                purchase_id=purchase.purchase_id,
                db_path=self.db_path,
            )
            log.info(
                "BuyerAgent %s purchased listing %s price=%.2f escrow=%s",
                self.agent_id, listing_id, listing.price_usd, escrow.escrow_id,
            )
            return {
                "status":      "purchased",
                "purchase_id": purchase.purchase_id,
                "escrow_id":   escrow.escrow_id,
                "price_paid":  listing.price_usd,
            }

        # Price too high — try negotiation if within stretch tolerance
        stretch_limit = max_price * _STRETCH_FACTOR
        if listing.price_usd <= stretch_limit:
            engine = NegotiationEngine()
            neg = engine.start_negotiation(
                buyer_agent_id=self.agent_id,
                seller_agent_id=listing.seller_agent,
                listing_id=listing.listing_id,
                initial_price=listing.price_usd,
                asset_ueciid=listing.asset_id,
                db_path=self.db_path,
            )
            offer = engine.send_offer(
                negotiation_id=neg.negotiation_id,
                from_agent_id=self.agent_id,
                price=max_price,
                message=f"Offering {max_price:.2f} for {listing.asset_id}",
                keypair=self.keypair,
                db_path=self.db_path,
            )
            log.info(
                "BuyerAgent %s opened negotiation %s for listing %s",
                self.agent_id, neg.negotiation_id, listing_id,
            )
            return {
                "status":         "negotiating",
                "negotiation_id": neg.negotiation_id,
                "offer_id":       offer.offer_id,
                "offered_price":  max_price,
            }

        return {
            "status":        "price_rejected",
            "listing_price": listing.price_usd,
            "max_price":     max_price,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _check_budget(self, amount: float, tenant_id: str) -> bool:
        """Returns True if purchase is within budget. Fail-open on any error."""
        try:
            from warden.business_community.agentic_commerce.semantic_budget import check_budget
            result = check_budget(tenant_id or "default", amount)
            return result.get("status") != "block"
        except Exception:
            return True
