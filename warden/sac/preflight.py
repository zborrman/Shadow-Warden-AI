"""
SAC two-phase preflight billing — reserve → commit / release.

Guards against a runaway ReAct loop draining a tenant's balance ("wallet run"):
before an expensive agent run the estimated cost is *reserved* (held); after the
run the *actual* cost (from token usage / GSAM economics) is *committed* and the
unused remainder released.

Ledger model (integer **micro-USD** to preserve sub-cent nanopayment precision):

    net = balance − hold                      # spendable right now
    reserve(est):  require net ≥ est; hold += est
    commit(actual): balance −= min(actual, balance); hold −= held      (hold cleared)
    release():      hold −= held                                       (nothing spent)

Every reserve/commit/release is appended to the tenant's billing audit chain.
Storage is Turso-or-SQLite (db name ``sac_wallet``); all writes hold a lock.
"""
from __future__ import annotations

import logging
import secrets
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime

from warden.config import settings

log = logging.getLogger("warden.sac.preflight")

_db_lock = threading.RLock()
_MICROS = 1_000_000  # micro-USD per USD

_WALLET_DDL = """
    CREATE TABLE IF NOT EXISTS sac_wallets (
        tenant_id     TEXT PRIMARY KEY,
        balance_micros INTEGER NOT NULL DEFAULT 0,
        hold_micros    INTEGER NOT NULL DEFAULT 0,
        updated_at    TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS sac_holds (
        hold_id      TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL,
        amount_micros INTEGER NOT NULL,
        status       TEXT NOT NULL DEFAULT 'HELD',
        reason       TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL,
        resolved_at  TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_sac_holds_tenant ON sac_holds(tenant_id, status);
"""


class InsufficientFundsError(RuntimeError):
    """Raised by :func:`reserve` when net balance cannot cover the estimate."""


class HoldError(RuntimeError):
    """Raised when a hold is missing or already resolved."""


def _to_micros(usd: float) -> int:
    return int(round(max(0.0, float(usd)) * _MICROS))


def _to_usd(micros: int) -> float:
    return round(micros / _MICROS, 6)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with suppress(ImportError):
        from warden.db.turso import get_connection, is_turso_enabled
        if is_turso_enabled("sac_wallet"):
            with get_connection("sac_wallet", fallback_path=settings.sac_wallet_db_path) as con:
                with suppress(Exception):
                    con.executescript(_WALLET_DDL)
                yield con  # type: ignore[misc]
            return
    con = sqlite3.connect(settings.sac_wallet_db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_WALLET_DDL)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _audit(tenant_id: str, event: str, amount_usd: float, agent_id: str = "") -> None:
    with suppress(Exception):
        from warden.billing.audit_chain import append_billing_event
        append_billing_event(tenant_id, event, amount_usd=amount_usd, agent_id=agent_id)


def _row(con: sqlite3.Connection, tenant_id: str) -> tuple[int, int]:
    r = con.execute(
        "SELECT balance_micros, hold_micros FROM sac_wallets WHERE tenant_id=?", (tenant_id,)
    ).fetchone()
    return (int(r["balance_micros"]), int(r["hold_micros"])) if r else (0, 0)


def _upsert(con: sqlite3.Connection, tenant_id: str, balance: int, hold: int) -> None:
    con.execute(
        "INSERT INTO sac_wallets (tenant_id,balance_micros,hold_micros,updated_at) VALUES(?,?,?,?) "
        "ON CONFLICT(tenant_id) DO UPDATE SET balance_micros=excluded.balance_micros, "
        "hold_micros=excluded.hold_micros, updated_at=excluded.updated_at",
        (tenant_id, max(0, balance), max(0, hold), datetime.now(UTC).isoformat()),
    )


def get_wallet(tenant_id: str) -> dict:
    """Return the tenant wallet with net (spendable) balance in USD."""
    with _db_lock, _conn() as con:
        balance, hold = _row(con, tenant_id)
    return {
        "tenant_id": tenant_id,
        "balance_usd": _to_usd(balance),
        "hold_usd": _to_usd(hold),
        "net_usd": _to_usd(max(0, balance - hold)),
    }


def deposit(tenant_id: str, amount_usd: float) -> dict:
    """Fund a wallet (privileged operation). Returns the updated wallet."""
    micros = _to_micros(amount_usd)
    if micros <= 0:
        raise ValueError("amount_usd must be positive")
    with _db_lock, _conn() as con:
        balance, hold = _row(con, tenant_id)
        _upsert(con, tenant_id, balance + micros, hold)
    _audit(tenant_id, "wallet_deposit", amount_usd)
    return get_wallet(tenant_id)


def reserve(tenant_id: str, est_cost_usd: float, reason: str = "", agent_id: str = "") -> str:
    """Reserve (hold) the estimated cost. Returns a hold_id.

    Raises :class:`InsufficientFundsError` if net balance < estimate.
    """
    est = _to_micros(est_cost_usd)
    hold_id = f"sac_hold_{secrets.token_hex(12)}"
    with _db_lock, _conn() as con:
        balance, hold = _row(con, tenant_id)
        if balance - hold < est:
            raise InsufficientFundsError(
                f"net {_to_usd(balance - hold)} USD < estimate {_to_usd(est)} USD"
            )
        _upsert(con, tenant_id, balance, hold + est)
        con.execute(
            "INSERT INTO sac_holds (hold_id,tenant_id,amount_micros,status,reason,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (hold_id, tenant_id, est, "HELD", reason, datetime.now(UTC).isoformat()),
        )
    _audit(tenant_id, "preflight_reserve", _to_usd(est), agent_id)
    return hold_id


def _resolve_hold(
    con: sqlite3.Connection, hold_id: str, expected_tenant_id: str | None = None
) -> tuple[str, int]:
    r = con.execute(
        "SELECT tenant_id, amount_micros, status FROM sac_holds WHERE hold_id=?", (hold_id,)
    ).fetchone()
    # A tenant mismatch reads identically to "not found" — never confirm to a
    # caller that a hold belonging to another tenant exists (IDOR prevention).
    if not r or (expected_tenant_id is not None and r["tenant_id"] != expected_tenant_id):
        raise HoldError("hold not found")
    if r["status"] != "HELD":
        raise HoldError(f"hold already {r['status'].lower()}")
    return r["tenant_id"], int(r["amount_micros"])


def commit(
    hold_id: str, actual_cost_usd: float, agent_id: str = "", expected_tenant_id: str | None = None
) -> dict:
    """Commit the actual cost against a hold and release the remainder.

    ``actual`` is charged to the balance (never below 0); the full held amount is
    released from ``hold``. Returns {committed_usd, released_usd, wallet}.

    ``expected_tenant_id``, when given, must match the hold's owning tenant or a
    :class:`HoldError` is raised — prevents one tenant from settling another
    tenant's hold via a guessed/observed hold_id.
    """
    actual = _to_micros(actual_cost_usd)
    with _db_lock, _conn() as con:
        tenant_id, held = _resolve_hold(con, hold_id, expected_tenant_id)
        balance, hold = _row(con, tenant_id)
        charge = min(actual, balance)  # never overdraw
        _upsert(con, tenant_id, balance - charge, hold - held)
        con.execute(
            "UPDATE sac_holds SET status='COMMITTED', resolved_at=? WHERE hold_id=?",
            (datetime.now(UTC).isoformat(), hold_id),
        )
    _audit(tenant_id, "preflight_commit", _to_usd(charge), agent_id)
    return {
        "hold_id": hold_id, "committed_usd": _to_usd(charge),
        "released_usd": _to_usd(max(0, held - charge)), "wallet": get_wallet(tenant_id),
    }


def release(
    hold_id: str, reason: str = "", agent_id: str = "", expected_tenant_id: str | None = None
) -> dict:
    """Release a hold without charging (run failed / aborted).

    ``expected_tenant_id`` behaves as in :func:`commit` — an ownership check to
    prevent cross-tenant hold manipulation.
    """
    with _db_lock, _conn() as con:
        tenant_id, held = _resolve_hold(con, hold_id, expected_tenant_id)
        balance, hold = _row(con, tenant_id)
        _upsert(con, tenant_id, balance, hold - held)
        con.execute(
            "UPDATE sac_holds SET status='RELEASED', resolved_at=? WHERE hold_id=?",
            (datetime.now(UTC).isoformat(), hold_id),
        )
    _audit(tenant_id, "preflight_release", _to_usd(held), agent_id)
    return {"hold_id": hold_id, "released_usd": _to_usd(held), "wallet": get_wallet(tenant_id)}


def recent_agent_cost_usd(agent_id: str, hours: int = 1) -> float:
    """Rate-phase helper: actual cost for an agent from the GSAM rollup."""
    with suppress(Exception):
        from warden.gsam.rollup import read_agent_stats
        stats = read_agent_stats(agent_id, hours=hours)
        return round(sum(h["cost_usd"] for h in stats["hours"]), 6)
    return 0.0
