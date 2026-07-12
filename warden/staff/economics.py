"""
Unit Economics — token cost tracker for Digital Staff agents.

Tracks LLM spend per agent action so operators can see the true margin of each
autonomous operation (e.g. cost-per-SAR-draft, cost-per-SEO-text) and fire
budget alerts before Opus (L3) loops overspend.

SQLite at STAFF_ECONOMICS_DB_PATH (default /tmp/warden_staff_economics.db).
Fail-open: all methods return gracefully on any DB or import error.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

from warden.config import data_path  # noqa: E402

_DB_PATH: str = data_path("warden_staff_economics.db", "STAFF_ECONOMICS_DB_PATH")

# Pricing as of 2026-06 (USD per million tokens)
_COST_PER_MTOK: dict[str, dict[str, float]] = {
    "claude-haiku-4-5-20251001": {"input": 0.80,  "output": 4.00},
    "claude-sonnet-4-6":         {"input": 3.00,  "output": 15.00},
    "claude-opus-4-8":           {"input": 15.00, "output": 75.00},
}
_DEFAULT_RATES = {"input": 3.00, "output": 15.00}


def compute_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = _COST_PER_MTOK.get(model, _DEFAULT_RATES)
    return (input_tokens * rates["input"] + output_tokens * rates["output"]) / 1_000_000


@dataclass
class ActionCost:
    tenant_id: str
    agent_id: str
    action: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
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


def _db(path: str = _DB_PATH) -> sqlite3.Connection:
    """Return a SQLite or Turso connection for the staff economics database."""
    try:
        from contextlib import suppress  # noqa: PLC0415

        from warden.db.turso import get_connection, is_turso_enabled  # noqa: PLC0415
        if is_turso_enabled("staff") and path == _DB_PATH:
            # Return a proxy that mimics sqlite3.Connection commit/close lifecycle
            class _TursoProxy:
                def __init__(self, inner):
                    self._c = inner
                def execute(self, sql, params=()):
                    return self._c.execute(sql, params)
                def commit(self):
                    pass
                def close(self):
                    pass
                row_factory = None
            ctx = get_connection("staff", fallback_path=_DB_PATH)
            con = ctx.__enter__()
            with suppress(Exception):
                con.executescript(_STAFF_DDL)
            return _TursoProxy(con)  # type: ignore[return-value]
    except (ImportError, Exception):
        pass
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_STAFF_DDL)
    conn.commit()
    return conn


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
    ) -> ActionCost:
        cost = compute_cost_usd(model, input_tokens, output_tokens)
        entry = ActionCost(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=action,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
        )
        try:
            conn = _db(self._db_path)
            conn.execute(
                "INSERT INTO staff_action_costs "
                "(tenant_id,agent_id,action,model,input_tokens,output_tokens,cost_usd,ts) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (tenant_id, agent_id, action, model,
                 input_tokens, output_tokens, cost, entry.ts),
            )
            conn.commit()
            conn.close()
            log.debug(
                "ECONOMICS: tenant=%s agent=%s action=%s model=%s cost=$%.6f",
                tenant_id, agent_id, action, model, cost,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("ECONOMICS record failed (fail-open): %s", exc)

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
            conn = _db(self._db_path)
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
            conn.close()
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
