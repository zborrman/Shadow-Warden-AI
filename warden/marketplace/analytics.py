"""
warden/marketplace/analytics.py
─────────────────────────────────
Analytics query functions over MARKETPLACE_DB_PATH SQLite.
All functions are fail-open (return zeros/empty on error).
"""
from __future__ import annotations

import logging
import os
import sqlite3
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
