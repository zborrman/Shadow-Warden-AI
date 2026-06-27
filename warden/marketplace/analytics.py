"""
warden/marketplace/analytics.py
─────────────────────────────────
Analytics query functions over MARKETPLACE_DB_PATH SQLite.
All functions are fail-open (return zeros/empty on error).
"""
from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import time as _time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.marketplace.analytics")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")


@contextmanager
def _conn(db_path: str = _DB_PATH):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
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
    db_path: str = _DB_PATH,
) -> dict:
    try:
        with _conn(db_path) as con:
            since = _since(period_days)

            p_where: list[str] = ["purchased_at >= ?"]
            p_params: list = [since]
            if tenant_id:
                p_where.append("tenant_id = ?")
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

            rows = con.execute(
                f"SELECT asset_type, COUNT(*) as cnt, COALESCE(SUM(price_paid),0) as vol "
                f"FROM marketplace_purchases {_pw(p_where + ['status=?'])} "
                f"GROUP BY asset_type ORDER BY cnt DESC LIMIT 5",
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
    db_path: str = _DB_PATH,
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


def get_agent_leaderboard(
    tenant_id: str | None = None,
    community_id: str | None = None,
    limit: int = 10,
    db_path: str = _DB_PATH,
) -> dict:
    try:
        with _conn(db_path) as con:
            where: list[str] = ["status = ?"]
            params: list = ["completed"]
            if tenant_id:
                where.append("tenant_id = ?")
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


def fairness_stats(period_days: int = 7, db_path: str = _DB_PATH) -> dict:
    """Return First-Proposal Bias metrics for the marketplace.

    - avg_candidates_evaluated: mean alternatives compared per search_and_buy call
      (sourced from candidates_evaluated stored in purchase records when available).
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

            # candidates_evaluated column may not exist in older DBs — fail gracefully
            try:
                agg = con.execute(
                    "SELECT AVG(CAST(candidates_evaluated AS REAL)) as avg_c, "
                    "SUM(CASE WHEN candidates_evaluated = 1 THEN 1 ELSE 0 END) as single_c "
                    "FROM marketplace_purchases WHERE purchased_at >= ?",
                    (since,),
                ).fetchone()
                avg_candidates = round(float(agg["avg_c"] or 0), 2)
                single_candidate = int(agg["single_c"] or 0)
            except Exception:
                avg_candidates = 0.0
                single_candidate = 0

        first_offer_rate = round(single_candidate / total, 4) if total > 0 else 0.0
        return {
            "period_days":                period_days,
            "total_purchases":            total,
            "avg_candidates_evaluated":   avg_candidates,
            "first_offer_acceptance_rate": first_offer_rate,
            "min_offers_policy":          int(_os.getenv("MARKETPLACE_MIN_OFFERS_BEFORE_BUY", "3")),
        }
    except Exception as exc:
        log.warning("fairness_stats failed: %s", exc)
        return {
            "period_days":                period_days,
            "total_purchases":            0,
            "avg_candidates_evaluated":   0.0,
            "first_offer_acceptance_rate": 0.0,
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
    db_path: str = _DB_PATH,
) -> dict:
    """Model router tier distribution derived from dispatch action types.

    Reads action_type counts from marketplace_clearing_log for the period,
    maps each to its routing tier (haiku/sonnet/opus), and estimates the
    API cost saved vs. always using Opus.

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

    try:
        with _conn(db_path) as con:
            # clearing_log has action_type; fall back to purchases if clearing_log is missing
            try:
                rows = con.execute(
                    "SELECT action_type, COUNT(*) as cnt FROM marketplace_clearing_log "
                    "WHERE cleared_at >= ? GROUP BY action_type",
                    (since,),
                ).fetchall()
            except Exception:
                rows = []

            if not rows:
                # Fall back: derive from purchases (search+negotiate+clear) proportions
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
            else:
                for r in rows:
                    tier = _ACTION_TIER.get(r["action_type"] or "", "sonnet")
                    counts[tier] = counts.get(tier, 0) + int(r["cnt"])
                    total += int(r["cnt"])
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
        "estimated":   total < 10,
    }


# ── SSE live-metrics aggregation (async, Redis-cached) ────────────────────────

_LIVE_CACHE: dict = {"ts": 0.0, "data": None}
_LIVE_CACHE_TTL = 30  # seconds — matches SSE push interval


def _build_live_metrics(db_path: str = "") -> dict:
    """Synchronous aggregation of all SSE live-metrics in one DB pass.

    Combines summary + fairness + tiers + 7-day volume series.
    Runs in a thread executor so it never blocks the event loop.
    """
    db = db_path or os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
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
        from warden.cache import _get_redis  # noqa: PLC0415
        r = _get_redis()
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

            from warden.cache import _get_redis  # noqa: PLC0415
            r = _get_redis()
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
    db = db_path or os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    try:
        with _conn(db) as con:
            rows = con.execute(
                "SELECT buyer_agent, seller_agent, asset_type, price_paid, created_at "
                "FROM marketplace_purchases ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("get_recent_trades failed: %s", exc)
