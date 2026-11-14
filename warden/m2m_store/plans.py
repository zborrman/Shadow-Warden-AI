"""
warden/m2m_store/plans.py
──────────────────────────
Which store plan a seller is on, and what that plan may hold.

The entitlement is a row in this database, not a call to a payment provider.
Whoever sells the plan only *writes* that row - the operator today, a verified
subscription webhook once a payment rail exists - and every read is local. A
provider outage can therefore delay an upgrade; it cannot lock a paying seller
out of their own shop, and it cannot be used to mint a plan.

Three properties this module exists to keep:

  * **The tenant is never named by the caller.** Every function takes the
    tenant the route resolved from its own credentials. Only the operator
    (admin key) may act on a named tenant.
  * **Limits are enforced where the row is written**, in one conditional
    INSERT (see ``storefront.create_store`` and ``inventory.add_product``).
    Production runs four workers; a count-then-insert in Python lets two of
    them both see room for the last slot.
  * **A lower plan never destroys anything.** Going over a limit - by a
    downgrade or an expired trial - blocks *new* stores and products. What
    exists stays, stays published, and stays exportable.

A trial is single-use per tenant for the life of the tenant: the marker row is
a PRIMARY KEY insert, so a second attempt loses the race in the database and
not in a Python ``if``.
"""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from warden.billing import pricing
from warden.db.ddl_registry import register

from .inventory import _conn, _db_lock, _now_iso

_PLANS_DDL = """
    CREATE TABLE IF NOT EXISTS m2m_store_plans (
        tenant_id TEXT PRIMARY KEY,
        plan TEXT NOT NULL,
        source TEXT NOT NULL,
        granted_by TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        expires_at TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS m2m_store_plan_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        event TEXT NOT NULL,
        plan TEXT NOT NULL,
        source TEXT NOT NULL,
        actor TEXT NOT NULL,
        expires_at TEXT NOT NULL DEFAULT '',
        at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_plan_events_tenant
        ON m2m_store_plan_events(tenant_id, at);
    CREATE TABLE IF NOT EXISTS m2m_store_trials (
        tenant_id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL
    );
"""

register("m2m_store", "plans", _PLANS_DDL)

# Read at call time, so a test can pin a different default without reloading.
DEFAULT_PLAN: str = pricing.STORE_DEFAULT_PLAN

# Who may put a row here. "subscription" is reserved for the payment webhook:
# nothing writes it yet, and no route accepts it from a caller.
GRANTABLE_SOURCES = frozenset({"admin", "founding", "fixture"})
_ALL_SOURCES = GRANTABLE_SOURCES | {"trial", "subscription"}

_MAX_GRANT_DAYS = 3660


class PlanLimitError(Exception):
    """A write would take the tenant past what its plan holds."""

    def __init__(self, limit: str, maximum: int, plan: str) -> None:
        super().__init__(f"plan {plan} allows at most {maximum} {limit}")
        self.limit = limit
        self.maximum = maximum
        self.plan = plan


class PlanInvalidError(ValueError):
    """An unknown plan, an unknown source, or a nonsensical duration."""


class PlanConflictError(Exception):
    """The trial was already used, or the tenant is already on a plan."""


@dataclass(frozen=True)
class PlanState:
    plan: str
    source: str
    expires_at: str = ""
    limits: dict[str, int] = field(default_factory=dict)

    def limit(self, name: str) -> int:
        return self.limits[name]

    def as_dict(self) -> dict[str, Any]:
        return {"plan": self.plan, "source": self.source,
                "expires_at": self.expires_at, "limits": dict(self.limits)}


def _default_state() -> PlanState:
    return PlanState(DEFAULT_PLAN, "default", "", pricing.store_plan_limits(DEFAULT_PLAN))


def get_plan(tenant_id: str) -> PlanState:
    """The plan in force for *tenant_id* right now.

    No row, an expired row, or a row naming a plan that no longer exists all
    resolve to the default plan - never to an error and never to "unlimited".
    """
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT plan, source, expires_at FROM m2m_store_plans WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    if row is None or row["plan"] not in pricing.STORE_PLAN_LIMITS:
        return _default_state()
    if row["expires_at"] and row["expires_at"] <= _now_iso():
        return _default_state()
    return PlanState(row["plan"], row["source"], row["expires_at"],
                     pricing.store_plan_limits(row["plan"]))


def _event(con: sqlite3.Connection, tenant_id: str, event: str, plan: str,
           source: str, actor: str, expires_at: str = "") -> None:
    con.execute(
        "INSERT INTO m2m_store_plan_events(id, tenant_id, event, plan, source, actor,"
        " expires_at, at) VALUES(?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), tenant_id, event, plan, source, actor, expires_at, _now_iso()),
    )


def _expiry(days: int | None) -> str:
    if days is None:
        return ""
    if not 1 <= days <= _MAX_GRANT_DAYS:
        raise PlanInvalidError(f"days must be between 1 and {_MAX_GRANT_DAYS}")
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def grant_plan(tenant_id: str, plan: str, *, source: str, actor: str,
               days: int | None = None) -> PlanState:
    """Put *tenant_id* on *plan*. Operator-only; the route enforces that.

    Replaces whatever the tenant was on and records who did it. ``days=None``
    is an open-ended grant.
    """
    if not tenant_id or not tenant_id.strip():
        raise PlanInvalidError("tenant_id is required")
    if plan not in pricing.STORE_PLAN_LIMITS:
        raise PlanInvalidError(f"unknown plan {plan!r}")
    if source not in GRANTABLE_SOURCES:
        raise PlanInvalidError(f"source must be one of {sorted(GRANTABLE_SOURCES)}")
    if not actor:
        raise PlanInvalidError("actor is required")
    expires_at = _expiry(days)
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO m2m_store_plans(tenant_id, plan, source, granted_by, granted_at,"
            " expires_at) VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(tenant_id) DO UPDATE SET plan=excluded.plan, source=excluded.source,"
            " granted_by=excluded.granted_by, granted_at=excluded.granted_at,"
            " expires_at=excluded.expires_at",
            (tenant_id, plan, source, actor, _now_iso(), expires_at),
        )
        _event(con, tenant_id, "granted", plan, source, actor, expires_at)
    return get_plan(tenant_id)


def revoke_plan(tenant_id: str, *, actor: str) -> None:
    """Return *tenant_id* to the default plan. Nothing the tenant owns is touched."""
    with _db_lock, _conn() as con:
        cur = con.execute("DELETE FROM m2m_store_plans WHERE tenant_id=?", (tenant_id,))
        if cur.rowcount:
            _event(con, tenant_id, "revoked", DEFAULT_PLAN, "admin", actor)


def trial_available(tenant_id: str) -> bool:
    with _db_lock, _conn() as con:
        used = con.execute(
            "SELECT 1 FROM m2m_store_trials WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    return used is None and get_plan(tenant_id).source == "default"


def start_trial(tenant_id: str) -> PlanState:
    """Start the tenant's one trial of the paid plan.

    Two refusals, both decided by the database rather than by a check made
    before it: a tenant that has ever started a trial (the marker is a PRIMARY
    KEY), and a tenant that holds an unexpired plan (the upsert only replaces an
    expired row). A refused attempt does not burn the trial - the marker and the
    plan are written in one transaction.
    """
    plan = pricing.STORE_TRIAL_PLAN
    now = _now_iso()
    expires_at = _expiry(pricing.STORE_TRIAL_DAYS)
    with _db_lock, _conn() as con:
        try:
            con.execute(
                "INSERT INTO m2m_store_trials(tenant_id, started_at) VALUES(?,?)",
                (tenant_id, now),
            )
        except sqlite3.IntegrityError as exc:
            raise PlanConflictError("the trial has already been used") from exc
        cur = con.execute(
            "INSERT INTO m2m_store_plans(tenant_id, plan, source, granted_by, granted_at,"
            " expires_at) VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(tenant_id) DO UPDATE SET plan=excluded.plan, source=excluded.source,"
            " granted_by=excluded.granted_by, granted_at=excluded.granted_at,"
            " expires_at=excluded.expires_at"
            " WHERE m2m_store_plans.expires_at != '' AND m2m_store_plans.expires_at <= ?",
            (tenant_id, plan, "trial", tenant_id, now, expires_at, now),
        )
        if cur.rowcount != 1:
            # Raising inside the block rolls the marker back with it.
            raise PlanConflictError("already on a plan")
        _event(con, tenant_id, "trial_started", plan, "trial", tenant_id, expires_at)
    return get_plan(tenant_id)


def usage(tenant_id: str) -> dict[str, int]:
    """What the tenant currently holds against its limits."""
    with _db_lock, _conn() as con:
        stores = con.execute(
            "SELECT COUNT(*) FROM m2m_stores WHERE tenant_id=? AND deleted_at=''",
            (tenant_id,),
        ).fetchone()[0]
        products = con.execute(
            "SELECT COUNT(*) FROM m2m_products WHERE json_extract(data_json,'$.tenant_id')=?"
            " AND COALESCE(json_extract(data_json,'$.deleted_at'),'')=''",
            (tenant_id,),
        ).fetchone()[0]
    return {"stores": int(stores), "products": int(products)}


def history(tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Plan changes for *tenant_id*, newest first. The audit trail of every grant."""
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT event, plan, source, actor, expires_at, at FROM m2m_store_plan_events"
            " WHERE tenant_id=? ORDER BY at DESC LIMIT ?",
            (tenant_id, max(1, min(limit, 200))),
        ).fetchall()
    return [dict(r) for r in rows]
