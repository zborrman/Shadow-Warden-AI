"""
warden/marketplace/seller_agent.py
────────────────────────────────────
SellerAgent — autonomous agent that evaluates market demand, lists assets at
dynamic prices, and dereferences stale signal bundles.

Dynamic pricing
───────────────
  price = base_price * (1 + demand_factor * demand_score)
  demand_factor defaults to 0.5 (configurable via MARKETPLACE_DEMAND_FACTOR env var).

Usage
─────
  seller = SellerAgent(agent_id="did:shadow:...", keypair=kp, db_path=...)
  listing = seller.auto_list(asset_id="SEP-...", base_price=10.0)
  seller.delist_if_stale(listing.listing_id)
"""
from __future__ import annotations

import logging
import os

from warden.config import data_path
from warden.db.connect import open_db_readonly

log = logging.getLogger("warden.marketplace.seller_agent")

_DEMAND_FACTOR = float(os.getenv("MARKETPLACE_DEMAND_FACTOR", "0.5"))
_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_DB_PATH_AT_IMPORT = _DB_PATH   # pristine; never monkeypatched

def _db_path() -> str:
    """Resolve the DB path on every call.

    DE-6 P2: this used to be read once into a module-level ``_DB_PATH`` and then
    used as a *parameter default* (``db_path: str | None = None``). Defaults bind at
    def-time, so the first value seen by the process was frozen into ~79
    signatures — no later ``MARKETPLACE_DB_PATH`` change, and no monkeypatch,
    could move them. That is the repo's own documented trap (Track F: use
    ``= None`` and resolve dynamically), and it is why test files that set the
    env at import fought over one another's databases.

    ``_DB_PATH`` is kept for callers that still reference it directly.
    """
    # An explicit override wins. Tests across this repo use
    # `monkeypatch.setattr(module, "_DB_PATH", ...)`, and callers may assign
    # it directly; re-reading the env unconditionally would silently ignore
    # both. Only when _DB_PATH is still the pristine import-time value do we
    # resolve fresh -- which is what unfreezes the parameter defaults.
    if _DB_PATH != _DB_PATH_AT_IMPORT:
        return _DB_PATH
    return data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")



class SellerAgent:
    """
    Autonomous seller that evaluates demand and manages listings on behalf of
    a registered marketplace agent.
    """

    def __init__(self, agent_id: str, keypair=None, db_path: str | None = None) -> None:
        self.agent_id = agent_id
        self.keypair  = keypair
        self.db_path  = db_path

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate_market_demand(self, asset_type: str) -> dict:
        """
        Analyse current active listings to estimate demand for *asset_type*.

        Returns:
          {
            "asset_type":      str,
            "active_listings": int,
            "avg_price":       float,
            "demand_score":    float,   # 0.0–1.0
            "recommended_price": float,
          }
        """
        stats = self._listing_stats(asset_type)
        active = stats["active"]
        avg_p  = stats["avg_price"]

        # Simple demand heuristic: more active listings → higher demand signal
        demand_score = min(active / 10.0, 1.0)

        # Recommended price: avg market price boosted by demand
        recommended = avg_p * (1.0 + _DEMAND_FACTOR * demand_score) if avg_p > 0 else 5.0

        return {
            "asset_type":       asset_type,
            "active_listings":  active,
            "avg_price":        round(avg_p, 2),
            "demand_score":     round(demand_score, 4),
            "recommended_price": round(recommended, 2),
        }

    def auto_list(
        self,
        asset_id: str,
        asset_type: str = "rule",
        base_price: float = 10.0,
        pricing_strategy: str = "dynamic",
        community_id: str = "",
        tenant_id: str = "",
        expires_hours: int | None = None,
    ):
        """
        Tokenize demand, compute price, publish listing. Returns Listing.

        Raises ValueError if agent_id not found in registry.
        """
        from warden.marketplace.agent import get_agent
        from warden.marketplace.listing import publish_listing

        agent = get_agent(self.agent_id, db_path=self.db_path)
        if agent is None:
            raise ValueError(f"SellerAgent '{self.agent_id}' not registered.")

        _community_id = community_id or agent.community_id
        _tenant_id    = tenant_id    or agent.tenant_id

        if pricing_strategy == "dynamic":
            demand = self.evaluate_market_demand(asset_type)
            price  = base_price * (1.0 + _DEMAND_FACTOR * demand["demand_score"])
            demand_score = demand["demand_score"]
        else:
            price        = base_price
            demand_score = 0.5

        listing = publish_listing(
            asset_id=asset_id,
            seller_agent=self.agent_id,
            community_id=_community_id,
            tenant_id=_tenant_id,
            asset_type=asset_type,
            price_usd=round(price, 2),
            pricing_strategy=pricing_strategy,
            demand_score=demand_score,
            expires_hours=expires_hours,
            db_path=self.db_path,
        )
        log.info(
            "SellerAgent %s listed %s as %s price=%.2f",
            self.agent_id, asset_id, listing.listing_id, listing.price_usd,
        )
        return listing

    def delist_if_stale(self, listing_id: str) -> bool:
        """
        Delist a specific listing if it is a 'signals' asset older than the
        stale threshold. Returns True if delisted.
        """
        from warden.marketplace.listing import get_listing, update_listing_status
        listing = get_listing(listing_id, db_path=self.db_path)
        if listing is None:
            return False
        if listing.asset_type != "signals" or listing.status != "active":
            return False

        import os as _os
        from datetime import UTC, datetime, timedelta
        stale_h = int(_os.getenv("MARKETPLACE_SIGNAL_STALE_HOURS", "48"))
        listed  = datetime.fromisoformat(listing.listed_at)
        if datetime.now(UTC) - listed > timedelta(hours=stale_h):
            update_listing_status(listing_id, "stale", db_path=self.db_path)
            log.info("SellerAgent delisted stale signals listing %s", listing_id)
            return True
        return False

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _listing_stats(self, asset_type: str) -> dict:
        try:
            con = open_db_readonly(self.db_path)
            row = con.execute(
                """SELECT COUNT(*) AS active, COALESCE(AVG(price_usd), 0) AS avg_price
                   FROM marketplace_listings
                   WHERE asset_type=? AND status='active'""",
                (asset_type,),
            ).fetchone()
            con.close()
            return {"active": int(row["active"] or 0), "avg_price": float(row["avg_price"] or 0)}
        except Exception:
            return {"active": 0, "avg_price": 0.0}
