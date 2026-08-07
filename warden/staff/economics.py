"""
Unit Economics — token cost tracker for Digital Staff agents.

Tracks LLM spend per agent action so operators can see the true margin of each
autonomous operation (e.g. cost-per-SAR-draft, cost-per-SEO-text) and fire
budget alerts before Opus (L3) loops overspend.

SQLite at STAFF_ECONOMICS_DB_PATH (default /tmp/warden_staff_economics.db).
Fail-open: all methods return gracefully on any DB or import error.
"""
from __future__ import annotations

import contextlib
import logging
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.finops.rating import DEFAULT_RATES as _DEFAULT_RATES
from warden.finops.rating import PRICE_BOOK as _COST_PER_MTOK
from warden.finops.rating import rate_usage
from warden.observability import Reason, record_failopen

log = logging.getLogger(__name__)

# Pricing is owned by warden.finops.rating (the single source of truth); the two
# aliases below preserve this module's historical import surface. Listed in
# __all__ so they read as intentional re-exports, not dead imports.
__all__ = [
    "ActionCost",
    "TokenCostTracker",
    "_COST_PER_MTOK",
    "_DEFAULT_RATES",
    "compute_cost_usd",
    "get_tracker",
]

_DB_PATH: str = data_path("warden_staff_economics.db", "STAFF_ECONOMICS_DB_PATH")


def compute_cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
) -> float:
    """USD cost of one call. `cached_tokens` (prompt-cache reads) bill at a
    fraction of the input rate — see warden.finops.rating. Backward compatible:
    2-positional-arg callers get the old fresh-input-only behaviour."""
    return rate_usage(model, input_tokens, output_tokens, cached_tokens).total_usd


@dataclass
class ActionCost:
    tenant_id: str
    agent_id: str
    action: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    cached_tokens: int = 0
    ts: int = field(default_factory=lambda: int(time.time()))


_STAFF_DDL = """
    CREATE TABLE IF NOT EXISTS staff_action_costs (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id     TEXT    NOT NULL,
        agent_id      TEXT    NOT NULL,
        action        TEXT    NOT NULL,
        model         TEXT    NOT NULL,
        input_tokens  INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        cost_usd      REAL    NOT NULL,
        ts            INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sac_tenant ON staff_action_costs(tenant_id, ts);
"""

register("staff_economics", "staff_economics", _STAFF_DDL)


def _ensure_columns(con: sqlite3.Connection) -> None:
    """
    Add columns that post-date the original table.

    `ALTER TABLE … ADD COLUMN` is not idempotent — it errors when the column is
    already there — so it cannot live in the registered DDL, which is replayed
    whenever its checksum changes. Same suppress-per-connect pattern as
    `marketplace/agent.py`.

    `cached_tokens` is what makes prompt-cache savings *reportable*: the rate
    already discounts them to 10% of the input rate, but without the count
    stored we can apply the saving and never show it.
    """
    for col, defn in [("cached_tokens", "INTEGER NOT NULL DEFAULT 0")]:
        try:
            con.execute(f"ALTER TABLE staff_action_costs ADD COLUMN {col} {defn}")
            con.commit()
        except Exception:   # the column is already there
            pass


@contextmanager
def _conn(path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Yield a SQLite or Turso connection for the staff economics database."""
    with open_db(
        "staff_economics", path, turso_name="staff", module_default_path=_DB_PATH
    ) as con:
        _ensure_columns(con)
        yield con


class TokenCostTracker:
    """SQLite-backed per-action cost recorder for Digital Staff agents."""

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path

    def record(
        self,
        tenant_id: str,
        agent_id: str,
        action: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
    ) -> ActionCost:
        """
        Record one LLM call's cost against a tenant.

        `cached_tokens` are prompt-cache reads, billed at 10% of the input rate
        (see warden.finops.rating). Callers that have the usage object should
        pass it — omitting it overstates cost on cache-heavy paths like SOVA,
        which caches its whole tool schema block.
        """
        cost = compute_cost_usd(model, input_tokens, output_tokens, cached_tokens)
        entry = ActionCost(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=action,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            cached_tokens=cached_tokens,
        )
        try:
            with _conn(self._db_path) as conn:
                conn.execute(
                    "INSERT INTO staff_action_costs "
                    "(tenant_id,agent_id,action,model,input_tokens,output_tokens,"
                    " cached_tokens,cost_usd,ts) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (tenant_id, agent_id, action, model,
                     input_tokens, output_tokens, cached_tokens, cost, entry.ts),
                )
            log.debug(
                "ECONOMICS: tenant=%s agent=%s action=%s model=%s cost=$%.6f",
                tenant_id, agent_id, action, model, cost,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("ECONOMICS record failed (fail-open): %s", exc)

        # Prometheus COGS counter — metrics must never block a recorded cost
        with contextlib.suppress(Exception):
            from warden.metrics import LLM_COST_USD_TOTAL
            LLM_COST_USD_TOTAL.labels(agent=agent_id, model=model).inc(cost)

        # Billing audit chain — fail-open, never blocks
        try:
            from warden.billing.audit_chain import STAFF_CALL, append_billing_event  # noqa: PLC0415
            append_billing_event(
                tenant_id=tenant_id,
                event_type=STAFF_CALL,
                cost_usd=cost,
                agent_id=agent_id,
                tool_name=action,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("billing_audit hook failed (fail-open): %s", exc)

        return entry

    def get_report(self, tenant_id: str, days: int = 30) -> dict:
        """Per-action cost breakdown for the last N days."""
        since = int(time.time()) - days * 86400
        try:
            with _conn(self._db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT agent_id, action, model,
                           COUNT(*) as calls,
                           SUM(input_tokens) as total_input,
                           SUM(output_tokens) as total_output,
                           SUM(cost_usd) as total_cost,
                           AVG(cost_usd) as avg_cost
                    FROM staff_action_costs
                    WHERE tenant_id = ? AND ts >= ?
                    GROUP BY agent_id, action, model
                    ORDER BY total_cost DESC
                    """,
                    (tenant_id, since),
                ).fetchall()
            actions = [
                {
                    "agent_id": r["agent_id"],
                    "action": r["action"],
                    "model": r["model"],
                    "calls": r["calls"],
                    "total_input_tokens": r["total_input"],
                    "total_output_tokens": r["total_output"],
                    "total_cost_usd": round(r["total_cost"], 6),
                    "avg_cost_usd": round(r["avg_cost"], 6),
                    "cost_per_call_usd": round(r["total_cost"] / r["calls"], 6),
                }
                for r in rows
            ]
            total = sum(a["total_cost_usd"] for a in actions)
            return {
                "tenant_id": tenant_id,
                "period_days": days,
                "total_cost_usd": round(total, 6),
                "actions": actions,
                "model_breakdown": _model_breakdown(actions),
            }
        except Exception as exc:  # noqa: BLE001
            log.warning("ECONOMICS get_report failed (fail-open): %s", exc)
            return {"tenant_id": tenant_id, "period_days": days, "total_cost_usd": 0.0, "actions": []}

    def get_margin_alerts(self, tenant_id: str, threshold_usd: float = 0.50) -> list[dict]:
        """Return actions where avg cost-per-call exceeds threshold_usd."""
        report = self.get_report(tenant_id)
        return [
            {**a, "alert": "avg_cost_exceeds_threshold", "threshold_usd": threshold_usd}
            for a in report.get("actions", [])
            if a["avg_cost_usd"] > threshold_usd
        ]

    def get_total_cost(self, tenant_id: str, days: int = 30) -> float:
        return self.get_report(tenant_id, days).get("total_cost_usd", 0.0)

    def get_turns_since(
        self, tenant_id: str, since_ts: int, agent_prefix: str = "master"
    ) -> int:
        """
        Count agent turns for a tenant since a timestamp.

        One row = one model call = one billable turn. `agent_prefix` selects the
        sold surface — MasterAgent records itself as `master:<sub_agent>`, so the
        default counts exactly what "MasterAgent included in Pro" covers and
        leaves platform-internal spend (evolution, healer) out of the customer's
        allowance. Fail-open: an unreadable DB counts as zero turns used, which
        never over-bills.
        """
        try:
            with _conn(self._db_path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM staff_action_costs "
                    "WHERE tenant_id = ? AND ts >= ? AND agent_id LIKE ?",
                    (tenant_id, int(since_ts), f"{agent_prefix}%"),
                ).fetchone()
            return int(row["n"] if row else 0)
        except Exception as exc:
            record_failopen("staff_economics", Reason.BACKEND_ERROR, exc)
            return 0

    def get_cache_savings_since(self, tenant_id: str, since_ts: int) -> float:
        """
        USD saved by prompt-cache reads since a timestamp.

        Cached input tokens bill at `CACHE_READ_DISCOUNT` of the fresh input
        rate; the saving is the difference, rated per row against that row's own
        model. Rows written before `cached_tokens` existed default to 0 and
        contribute nothing — they under-report the saving rather than invent it.
        """
        try:
            with _conn(self._db_path) as conn:
                rows = conn.execute(
                    "SELECT model, SUM(cached_tokens) AS cached FROM staff_action_costs "
                    "WHERE tenant_id = ? AND ts >= ? GROUP BY model",
                    (tenant_id, int(since_ts)),
                ).fetchall()
            return round(
                sum(
                    rate_usage(r["model"], 0, 0, int(r["cached"] or 0)).cache_savings_usd
                    for r in rows
                ),
                6,
            )
        except Exception as exc:
            record_failopen("staff_economics", Reason.BACKEND_ERROR, exc)
            return 0.0

    def get_cost_since(self, tenant_id: str, since_ts: int) -> float:
        """
        Total USD spent by *tenant_id* since a unix timestamp.

        A single SUM, not a grouped report — this is on the hot path of every
        budget check (warden.finops.llm_budget), so it must stay cheap.
        Fail-open: an unreadable DB reads as $0 spent, which keeps agents
        answering rather than degrading them on an infrastructure fault.
        """
        try:
            with _conn(self._db_path) as conn:
                row = conn.execute(
                    "SELECT COALESCE(SUM(cost_usd), 0.0) AS total "
                    "FROM staff_action_costs WHERE tenant_id = ? AND ts >= ?",
                    (tenant_id, int(since_ts)),
                ).fetchone()
            return float(row["total"] if row else 0.0)
        except Exception as exc:
            record_failopen("staff_economics", Reason.BACKEND_ERROR, exc)
            return 0.0


def _model_breakdown(actions: list[dict]) -> list[dict]:
    totals: dict[str, dict] = {}
    for a in actions:
        m = a["model"]
        if m not in totals:
            totals[m] = {"model": m, "calls": 0, "cost_usd": 0.0}
        totals[m]["calls"] += a["calls"]
        totals[m]["cost_usd"] += a["total_cost_usd"]
    return sorted(totals.values(), key=lambda x: x["cost_usd"], reverse=True)


_tracker_instance: TokenCostTracker | None = None


def get_tracker() -> TokenCostTracker:
    global _tracker_instance  # noqa: PLW0603
    if _tracker_instance is None:
        _tracker_instance = TokenCostTracker()
    return _tracker_instance
