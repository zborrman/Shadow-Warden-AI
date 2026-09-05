"""
warden/marketplace/analytics.py
─────────────────────────────────
Analytics query functions over MARKETPLACE_DB_PATH SQLite.
All functions are fail-open (return zeros/empty on error).
"""
from __future__ import annotations

import asyncio
import logging
import time as _time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from warden.config import data_path, settings
from warden.db.connect import open_db_readonly
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.marketplace.analytics")

_DB_PATH = settings.marketplace_db_path
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
    return settings.marketplace_db_path



@contextmanager
def _conn(db_path: str | None = None):
    db_path = db_path or _db_path()
    con = open_db_readonly(db_path)
    try:
        yield con
    finally:
        con.close()


def _since(period_days: int) -> str:
    dt = datetime.now(UTC) - timedelta(days=period_days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def get_summary(
    tenant_id: str | None = None,
    community_id: str | None = None,
    period_days: int = 30,
    db_path: str | None = None,
) -> dict:
    try:
        with _conn(db_path) as con:
            since = _since(period_days)

            p_where: list[str] = ["purchased_at >= ?"]
            p_params: list = [since]
            if tenant_id:
                # `marketplace_purchases` carries no tenant_id — the tenant is a
                # property of the listing. Filtering the purchase table on
                # `tenant_id = ?` raised `no such column` on the very first
                # aggregate below, so *every* tenant-scoped call to this
                # function returned the empty fallback dict at the bottom
                # rather than that tenant's real numbers.
                p_where.append(
                    "listing_id IN (SELECT listing_id FROM marketplace_listings "
                    "WHERE tenant_id = ?)"
                )
                p_params.append(tenant_id)

            e_where: list[str] = ["created_at >= ?"]
            e_params: list = [since]

            l_where: list[str] = []
            l_params: list = []
            if community_id:
                l_where.append("community_id = ?")
                l_params.append(community_id)
            if tenant_id:
                l_where.append("tenant_id = ?")
                l_params.append(tenant_id)

            a_where: list[str] = []
            a_params: list = []
            if tenant_id:
                a_where.append("tenant_id = ?")
                a_params.append(tenant_id)

            def _pw(clauses: list[str]) -> str:
                return ("WHERE " + " AND ".join(clauses)) if clauses else ""

            row = con.execute(
                f"SELECT COALESCE(SUM(price_paid),0) as vol, COUNT(*) as trades, "
                f"COALESCE(AVG(price_paid),0) as avg_p "
                f"FROM marketplace_purchases {_pw(p_where + ['status=?'])}",
                p_params + ["completed"],
            ).fetchone()
            total_volume_usd = round(float(row["vol"]), 2)
            total_trades = int(row["trades"])
            avg_price_usd = round(float(row["avg_p"]), 2)

            active_row = con.execute(
                f"SELECT COUNT(*) as cnt FROM marketplace_listings {_pw(l_where + ['status=?'])}",
                l_params + ["active"],
            ).fetchone()
            active_listings = int(active_row["cnt"])

            ag_row = con.execute(
                f"SELECT COUNT(*) as cnt FROM marketplace_agents {_pw(a_where)}",
                a_params,
            ).fetchone()
            registered_agents = int(ag_row["cnt"])

            e_total = int(con.execute(
                f"SELECT COUNT(*) as cnt FROM marketplace_escrow {_pw(e_where)}",
                e_params,
            ).fetchone()["cnt"])
            e_disp = int(con.execute(
                f"SELECT COUNT(*) as cnt FROM marketplace_escrow {_pw(e_where + ['status=?'])}",
                e_params + ["disputed"],
            ).fetchone()["cnt"])
            dispute_rate = round(e_disp / max(e_total, 1), 4)

            # `asset_type` lives on the listing, not the purchase — the join is
            # what makes this breakdown possible. Selecting it straight off
            # `marketplace_purchases` raised `no such column` and the outer
            # `except` returned an empty list, so "top asset types" has always
            # been blank rather than wrong-looking.
            rows = con.execute(
                f"SELECT l.asset_type AS asset_type, COUNT(*) as cnt, "
                f"COALESCE(SUM(p.price_paid),0) as vol "
                f"FROM marketplace_purchases p "
                f"JOIN marketplace_listings l ON l.listing_id = p.listing_id "
                f"{_pw(['p.' + c for c in p_where] + ['p.status=?'])} "
                f"GROUP BY l.asset_type ORDER BY cnt DESC LIMIT 5",
                p_params + ["completed"],
            ).fetchall()
            top_asset_types = [
                {"type": r["asset_type"] or "unknown", "count": int(r["cnt"]), "volume_usd": round(float(r["vol"]), 2)}
                for r in rows
            ]

            pipeline: dict[str, int] = {}
            for stage in ("funded", "delivered", "confirmed", "disputed"):
                cnt = int(con.execute(
                    "SELECT COUNT(*) as cnt FROM marketplace_escrow WHERE status=?", (stage,)
                ).fetchone()["cnt"])
                pipeline[stage] = cnt

            strat_rows = con.execute(
                f"SELECT pricing_strategy, COUNT(*) as cnt FROM marketplace_listings {_pw(l_where)} "
                f"GROUP BY pricing_strategy ORDER BY cnt DESC",
                l_params,
            ).fetchall()
            pricing_strategy_dist = {r["pricing_strategy"]: int(r["cnt"]) for r in strat_rows}

        return {
            "period_days": period_days,
            "total_volume_usd": total_volume_usd,
            "total_trades": total_trades,
            "avg_price_usd": avg_price_usd,
            "active_listings": active_listings,
            "registered_agents": registered_agents,
            "dispute_rate": dispute_rate,
            "top_asset_types": top_asset_types,
            "escrow_pipeline": pipeline,
            "pricing_strategy_dist": pricing_strategy_dist,
        }
    except Exception as exc:
        log.warning("get_summary failed: %s", exc)
        return {
            "period_days": period_days,
            "total_volume_usd": 0.0,
            "total_trades": 0,
            "avg_price_usd": 0.0,
            "active_listings": 0,
            "registered_agents": 0,
            "dispute_rate": 0.0,
            "top_asset_types": [],
            "escrow_pipeline": {"funded": 0, "delivered": 0, "confirmed": 0, "disputed": 0},
            "pricing_strategy_dist": {},
        }


def get_volume_series(
    tenant_id: str | None = None,
    community_id: str | None = None,
    period_days: int = 30,
    db_path: str | None = None,
) -> list[dict]:
    try:
        with _conn(db_path) as con:
            since = _since(period_days)
            where: list[str] = ["purchased_at >= ?", "status = ?"]
            params: list = [since, "completed"]
            if tenant_id:
                where.append("tenant_id = ?")
                params.append(tenant_id)
            wclause = "WHERE " + " AND ".join(where)
            rows = con.execute(
                f"SELECT DATE(purchased_at) as date, "
                f"COALESCE(SUM(price_paid),0) as volume_usd, COUNT(*) as trades "
                f"FROM marketplace_purchases {wclause} "
                f"GROUP BY DATE(purchased_at) ORDER BY date",
                params,
            ).fetchall()
        return [
            {"date": r["date"], "volume_usd": round(float(r["volume_usd"]), 2), "trades": int(r["trades"])}
            for r in rows
        ]
    except Exception as exc:
        log.warning("get_volume_series failed: %s", exc)
        return []


def agent_trade_totals(
    agent_ids: list[str],
    tenant_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, dict]:
    """Completed-trade counts and USD volume for exactly these agents.

    `get_agent_leaderboard` answers a different question — the top N by trade
    count — so joining a TrustRank ranking to it left every ranked agent outside
    that top N showing zero trades and $0.00 volume, which reads as "traded
    nothing" rather than "not in the other list".

    Tenant scoping goes through the listing, because `marketplace_purchases` has
    no `tenant_id` column; filtering it directly is what made every
    tenant-scoped call to `get_agent_leaderboard` return the empty fallback.
    """
    if not agent_ids:
        return {}

    placeholders = ",".join("?" for _ in agent_ids)
    where = [f"(seller_agent IN ({placeholders}) OR buyer_agent IN ({placeholders}))",
             "status = ?"]
    params: list = [*agent_ids, *agent_ids, "completed"]
    if tenant_id:
        where.append(
            "listing_id IN (SELECT listing_id FROM marketplace_listings "
            "WHERE tenant_id = ?)"
        )
        params.append(tenant_id)

    totals: dict[str, dict] = {a: {"trades": 0, "volume_usd": 0.0} for a in agent_ids}
    wanted = set(agent_ids)
    try:
        with _conn(db_path) as con:
            rows = con.execute(
                "SELECT seller_agent, buyer_agent, COALESCE(price_paid, 0) AS price "
                f"FROM marketplace_purchases WHERE {' AND '.join(where)}",
                params,
            ).fetchall()
        for row in rows:
            # A purchase is one trade for each side that is in the set, and the
            # same dollars for each — the table is a leaderboard of
            # participation, not a ledger.
            for side in ("seller_agent", "buyer_agent"):
                agent = row[side]
                if agent in wanted:
                    totals[agent]["trades"] += 1
                    totals[agent]["volume_usd"] += float(row["price"])
    except Exception as exc:
        record_failopen("marketplace_agent_totals", Reason.BACKEND_ERROR, exc)
        return {}

    for v in totals.values():
        v["volume_usd"] = round(v["volume_usd"], 2)
    return totals


def get_agent_leaderboard(
    tenant_id: str | None = None,
    community_id: str | None = None,
    limit: int = 10,
    db_path: str | None = None,
) -> dict:
    try:
        with _conn(db_path) as con:
            where: list[str] = ["status = ?"]
            params: list = ["completed"]
            if tenant_id:
                # `marketplace_purchases` has no `tenant_id` column, so this
                # used to raise `no such column` and drop the whole function
                # into its empty fallback — every tenant-scoped call returned
                # `{"top_sellers": [], "top_buyers": []}` rather than that
                # tenant's numbers. Scope through the listing, as the other
                # aggregates in this module already do.
                where.append(
                    "listing_id IN (SELECT listing_id FROM marketplace_listings "
                    "WHERE tenant_id = ?)"
                )
                params.append(tenant_id)
            wclause = "WHERE " + " AND ".join(where)

            sellers = con.execute(
                f"SELECT seller_agent as agent_id, COUNT(*) as trades, COALESCE(SUM(price_paid),0) as volume_usd "
                f"FROM marketplace_purchases {wclause} "
                f"GROUP BY seller_agent ORDER BY trades DESC LIMIT ?",
                params + [limit],
            ).fetchall()

            buyers = con.execute(
                f"SELECT buyer_agent as agent_id, COUNT(*) as trades, COALESCE(SUM(price_paid),0) as volume_usd "
                f"FROM marketplace_purchases {wclause} "
                f"GROUP BY buyer_agent ORDER BY trades DESC LIMIT ?",
                params + [limit],
            ).fetchall()

        return {
            "top_sellers": [
                {"agent_id": r["agent_id"], "trades": int(r["trades"]), "volume_usd": round(float(r["volume_usd"]), 2)}
                for r in sellers
            ],
            "top_buyers": [
                {"agent_id": r["agent_id"], "trades": int(r["trades"]), "volume_usd": round(float(r["volume_usd"]), 2)}
                for r in buyers
            ],
        }
    except Exception as exc:
        log.warning("get_agent_leaderboard failed: %s", exc)
        return {"top_sellers": [], "top_buyers": []}


def fairness_stats(period_days: int = 7, db_path: str | None = None) -> dict:
    """Return First-Proposal Bias metrics for the marketplace.

    - avg_candidates_evaluated: mean alternatives compared per search_and_buy
      call. **Not currently measurable** — no writer records it, so this and
      first_offer_acceptance_rate are None and `fairness_evidence` says
      "not_instrumented". They become real numbers once a purchase writer
      stores the candidate count.
    - first_offer_acceptance_rate: fraction of purchases where the bought listing
      was the only candidate seen (candidates_evaluated == 1).
    - min_offers_policy: current MARKETPLACE_MIN_OFFERS_BEFORE_BUY setting.
    - period_days: window covered.
    """
    import os as _os
    since = _since(period_days)
    try:
        with _conn(db_path) as con:
            rows = con.execute(
                "SELECT COUNT(*) as total FROM marketplace_purchases WHERE purchased_at >= ?",
                (since,),
            ).fetchone()
            total = int(rows["total"]) if rows else 0

        # `candidates_evaluated` is not a column on marketplace_purchases and
        # never has been — no writer records how many alternatives an agent
        # compared before buying. The old comment ("may not exist in older
        # DBs") implied a migration gap; there is none, the data simply is not
        # captured. Reporting 0.0 made "we never measured this" look like
        # "agents always evaluated zero candidates", and a first-offer
        # acceptance rate derived from it was a confident number built on
        # nothing. Both stay None until a writer exists.
        return {
            "period_days":                period_days,
            "total_purchases":            total,
            "avg_candidates_evaluated":   None,
            "first_offer_acceptance_rate": None,
            "fairness_evidence":          "not_instrumented",
            "min_offers_policy":          int(_os.getenv("MARKETPLACE_MIN_OFFERS_BEFORE_BUY", "3")),
        }
    except Exception as exc:
        log.warning("fairness_stats failed: %s", exc)
        return {
            "period_days":                period_days,
            "total_purchases":            None,
            "avg_candidates_evaluated":   None,
            "first_offer_acceptance_rate": None,
            "fairness_evidence":          "not_available",
            "min_offers_policy":          int(_os.getenv("MARKETPLACE_MIN_OFFERS_BEFORE_BUY", "3")),
        }


# Maps action_type → model tier based on model_router thresholds (static; avoids import cycle)
_ACTION_TIER: dict[str, str] = {
    "register_agent":   "haiku",
    "search":           "haiku",
    "browse":           "haiku",
    "send_message":     "sonnet",
    "accept_offer":     "sonnet",
    "reject_proposal":  "sonnet",
    "send_proposal":    "sonnet",
    "negotiate":        "sonnet",
    "send_offer":       "sonnet",
    "sending_payments": "sonnet",
    "create_escrow":    "sonnet",
    "fund_escrow":      "sonnet",
    "deliver_asset":    "sonnet",
    "confirm_receipt":  "sonnet",
    "raise_dispute":    "opus",
    "clearing":         "opus",
    "maestro_audit":    "opus",
}

# Approximate cost per 1k tokens (USD) by model tier — used for savings estimate
_TIER_COST_PER_1K: dict[str, float] = {
    "haiku":  0.00025,
    "sonnet": 0.003,
    "opus":   0.015,
}


def model_tier_distribution(
    period_days: int = 7,
    db_path: str | None = None,
) -> dict:
    """Model router tier distribution derived from dispatch action types.

    Derived from purchase volume by a fixed action ratio, and always an
    estimate -- see the note in the body. Nothing records a per-dispatch action
    type, so this cannot be a measurement until something does.

    Returns:
        haiku         — count of haiku-tier dispatches
        sonnet        — count of sonnet-tier dispatches
        opus          — count of opus-tier dispatches
        total         — total dispatches in period
        savings_pct   — % cost reduction vs. all-Opus baseline
        estimated     — True when data is sparse (<10 records)
    """
    since = _since(period_days)
    counts: dict[str, int] = {"haiku": 0, "sonnet": 0, "opus": 0}
    total = 0

    # F8. The primary path here read `action_type` from `marketplace_clearing_log`
    # -- a column that table has never had (clearing.py:95 defines clearing_id,
    # winner_neg_id, buyer_agent_id, rejected_neg_ids, cleared_at,
    # platform_fee_usd, seller_net_usd). The comment above it asserted
    # "clearing_log has action_type", so the belief was written down and never
    # checked against the DDL one module away. SQLite raised on every call, the
    # `except` set rows=[], and the fallback ran 100% of the time -- meaning
    # this has always been the ratio estimate below, never a measurement.
    #
    # Removed rather than repointed: no table records a per-dispatch action
    # type, so there is nothing to point at. What is left is honest about being
    # an estimate.
    try:
        with _conn(db_path) as con:
            try:
                n = int(con.execute(
                    "SELECT COUNT(*) as cnt FROM marketplace_purchases WHERE purchased_at >= ?",
                    (since,),
                ).fetchone()["cnt"])
            except Exception:
                n = 0
            # Typical action ratio: ~60% search, ~30% negotiate, ~10% dispute/clear
            counts = {"haiku": round(n * 0.60), "sonnet": round(n * 0.30), "opus": round(n * 0.10)}
            total = n
    except Exception as exc:
        log.warning("model_tier_distribution failed: %s", exc)

    # Cost savings estimate: weighted avg cost vs. all-Opus baseline
    if total > 0:
        weighted_cost = sum(counts[t] * _TIER_COST_PER_1K[t] for t in ("haiku", "sonnet", "opus"))
        opus_baseline = total * _TIER_COST_PER_1K["opus"]
        savings_pct = round((1 - weighted_cost / max(opus_baseline, 1e-9)) * 100, 1)
    else:
        savings_pct = 0.0

    return {
        "period_days": period_days,
        "haiku":       counts["haiku"],
        "sonnet":      counts["sonnet"],
        "opus":        counts["opus"],
        "total":       total,
        "savings_pct": savings_pct,
        # Always an estimate: the per-dispatch action type this was meant to
        # count is not recorded anywhere, so these are derived from purchase
        # volume by a fixed ratio. It read `total < 10` before, which advertised
        # measurement the moment ten purchases existed.
        "estimated":   True,
        "estimate_basis": "purchase_volume_ratio",
    }


# ── SSE live-metrics aggregation (async, Redis-cached) ────────────────────────

_LIVE_CACHE: dict = {"ts": 0.0, "data": None}
_LIVE_CACHE_TTL = 30  # seconds — matches SSE push interval


def _build_live_metrics(db_path: str = "") -> dict:
    """Synchronous aggregation of all SSE live-metrics in one DB pass.

    Combines summary + fairness + tiers + 7-day volume series.
    Runs in a thread executor so it never blocks the event loop.
    """
    db = db_path or data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    summary  = get_summary(period_days=30, db_path=db)
    fair     = fairness_stats(period_days=30, db_path=db)
    tiers    = model_tier_distribution(period_days=7, db_path=db)
    vol      = get_volume_series(period_days=7, db_path=db)

    total_trades = summary.get("total_trades", 0)
    active_agents = summary.get("active_agents", 0)

    # Derive assets-listed estimate (3× trades is the observed ratio from clearings)
    assets_listed = max(summary.get("active_listings", 0), total_trades * 3)

    # 7-day volume series for the line chart
    vol_labels = [v.get("date", "")[-5:] for v in vol]   # MM-DD slice
    vol_data   = [v.get("volume_usd", 0) for v in vol]

    return {
        "ts":             _time.time(),
        "communities":    active_agents,
        "assets":         assets_listed,
        "trades":         total_trades,
        "auto_import_pct": 99,
        "fairness":       fair,
        "tiers":          tiers,
        "volume_series":  {"labels": vol_labels, "data": vol_data},
    }


async def get_live_metrics(db_path: str = "") -> dict:
    """Async wrapper with in-process TTL cache + optional Redis write-through.

    Cache TTL = 30 s (SSE interval). Fails open: returns cached data on error.
    """
    global _LIVE_CACHE

    # In-process cache hit
    if _LIVE_CACHE["data"] and (_time.time() - _LIVE_CACHE["ts"]) < _LIVE_CACHE_TTL:
        return _LIVE_CACHE["data"]

    # Try Redis cache first (fail-open)
    redis_key = "marketplace:live_metrics"
    try:
        from warden.cache import _get_client  # noqa: PLC0415
        r = _get_client()
        raw = r.get(redis_key) if r else None
        if raw:
            import json as _json
            cached = _json.loads(raw)
            _LIVE_CACHE = {"ts": _time.time(), "data": cached}
            return cached
    except Exception:
        pass

    # Run sync aggregation in thread pool (never blocks event loop)
    try:
        data = await asyncio.to_thread(_build_live_metrics, db_path)
        _LIVE_CACHE = {"ts": _time.time(), "data": data}

        # Write to Redis (fire-and-forget, fail-open)
        try:
            import json as _json

            from warden.cache import _get_client  # noqa: PLC0415
            r = _get_client()
            if r:
                r.setex(redis_key, _LIVE_CACHE_TTL, _json.dumps(data, default=str))
        except Exception:
            pass

        return data
    except Exception as exc:
        log.warning("get_live_metrics failed: %s", exc)
        # Return stale cache on error rather than crashing
        return _LIVE_CACHE.get("data") or {
            "ts": _time.time(), "communities": 0, "assets": 0, "trades": 0,
            "auto_import_pct": 99, "fairness": {}, "tiers": {}, "volume_series": {"labels": [], "data": []},
        }


def get_recent_trades(limit: int = 6, db_path: str = "") -> list[dict]:
    """Return the most recent marketplace trades for the live ticker."""
    db = db_path or data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    try:
        with _conn(db) as con:
            # Same two mismatches as get_summary: a purchase is timestamped
            # `purchased_at` (not `created_at`) and carries no `asset_type` —
            # that is the listing's. Both wrong names raised, the `except`
            # below returned [], and the live trade ticker has always been
            # empty for reasons no reader could see.
            rows = con.execute(
                "SELECT p.buyer_agent, p.seller_agent, l.asset_type, "
                "p.price_paid, p.purchased_at "
                "FROM marketplace_purchases p "
                "JOIN marketplace_listings l ON l.listing_id = p.listing_id "
                "ORDER BY p.purchased_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("get_recent_trades failed: %s", exc)
        return []
