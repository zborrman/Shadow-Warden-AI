"""
warden/marketplace/credits.py
──────────────────────────────
Flex Credits — prepaid balance system for marketplace search and actions.

1 credit = $0.001. 1 search call = 1 credit.
Credits take priority over x402 USDC signatures — enterprise buyers get
budget-predictable access without needing a crypto wallet.

Credit packages map to billing/addons.py SKUs:
  agent_credits_starter     100 credits  $0.10
  agent_credits_builder     500 credits  $0.45
  agent_credits_pro        1000 credits  $0.85
  agent_credits_enterprise 5000 credits  $4.00

Storage
───────
  SQLite `marketplace_credits` in MARKETPLACE_DB_PATH (shared with listing.py)
  Redis  `marketplace:credits:{tenant_id}` integer DECRBY (atomic, fast-path)
  Falls back to SQLite-only when Redis unavailable.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager

from warden.config import data_path
from warden.db.sqlite_pragmas import init_pragmas
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.marketplace.credits")

_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock = threading.RLock()

CREDIT_PACKAGES: dict[str, dict] = {
    "credits_100": {
        "display_name": "Starter Credits",
        "credits":      100,
        "price_usd":    0.10,
        "addon_key":    "agent_credits_starter",
    },
    "credits_500": {
        "display_name": "Builder Credits",
        "credits":      500,
        "price_usd":    0.45,
        "addon_key":    "agent_credits_builder",
    },
    "credits_1000": {
        "display_name": "Pro Credits",
        "credits":      1000,
        "price_usd":    0.85,
        "addon_key":    "agent_credits_pro",
    },
    "credits_5000": {
        "display_name": "Enterprise Credits",
        "credits":      5000,
        "price_usd":    4.00,
        "addon_key":    "agent_credits_enterprise",
    },
}


# ── Schema ─────────────────────────────────────────────────────────────────────

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_credits (
            tenant_id        TEXT PRIMARY KEY,
            balance_credits  INTEGER NOT NULL DEFAULT 0,
            reserved_credits INTEGER NOT NULL DEFAULT 0,
            updated_at       TEXT    NOT NULL
        );
    """)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    init_pragmas(con)
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True, socket_connect_timeout=5, socket_timeout=3)
    except Exception:
        return None


def _redis_key(tenant_id: str) -> str:
    return f"marketplace:credits:{tenant_id}"


def _redis_get_balance(tenant_id: str) -> int | None:
    try:
        r = _redis()
        if r:
            val = r.get(_redis_key(tenant_id))
            return int(val) if val is not None else None
    except Exception as exc:
        log.debug("credits redis get error: %s", exc)
    return None


def _redis_sync(tenant_id: str, balance: int) -> None:
    """Write authoritative balance from SQLite into Redis."""
    try:
        r = _redis()
        if r:
            r.set(_redis_key(tenant_id), balance)
    except Exception as exc:
        log.debug("credits redis sync error: %s", exc)


# ── SQLite helpers ─────────────────────────────────────────────────────────────

def _db_get_balance(tenant_id: str) -> int:
    with _conn() as con:
        row = con.execute(
            "SELECT balance_credits FROM marketplace_credits WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    return int(row["balance_credits"]) if row else 0


def _db_add_credits(tenant_id: str, amount: int) -> int:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _db_lock, _conn() as con:
        con.execute(
            """INSERT INTO marketplace_credits (tenant_id, balance_credits, reserved_credits, updated_at)
               VALUES (?, ?, 0, ?)
               ON CONFLICT(tenant_id) DO UPDATE SET
                 balance_credits = balance_credits + excluded.balance_credits,
                 updated_at = excluded.updated_at""",
            (tenant_id, amount, now),
        )
        row = con.execute(
            "SELECT balance_credits FROM marketplace_credits WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
    return int(row["balance_credits"]) if row else amount


def _db_deduct_credits(tenant_id: str, amount: int) -> bool:
    """Deduct credits if sufficient balance exists. Returns True on success."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT balance_credits FROM marketplace_credits WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        balance = int(row["balance_credits"]) if row else 0
        if balance < amount:
            return False
        con.execute(
            "UPDATE marketplace_credits SET balance_credits = balance_credits - ?, updated_at = ? "
            "WHERE tenant_id = ? AND balance_credits >= ?",
            (amount, now, tenant_id, amount),
        )
        # Verify update actually happened (race guard)
        row2 = con.execute(
            "SELECT changes() as c",
        ).fetchone()
        if row2 and int(row2["c"]) == 0:
            return False
    return True


# ── Public API ─────────────────────────────────────────────────────────────────

_CREDIT_MICROS = 1_000  # 1 credit = $0.001 = 1000 µUSD


def _mirror_credit_grant(tenant_id: str, credits: int) -> None:
    """FT-2 dual-run: mirror a credit grant into the ledger. Fully guarded —
    neither the import nor the mirror may ever break the live credit path."""
    try:
        from warden.ledger import dual_write, operations
        from warden.ledger.money import Money
        dual_write.mirror(
            "credits.grant", operations.grant_credits, tenant_id,
            Money.from_micros(credits * _CREDIT_MICROS),
            idempotency_key=f"credits-grant-{tenant_id}-{uuid.uuid4().hex}",
        )
    except Exception as exc:  # shadow ledger (or its import) must never break credits
        record_failopen("credits_ledger_mirror", Reason.BACKEND_ERROR, exc)


def _mirror_credit_spend(tenant_id: str, credits: int) -> None:
    """FT-2 dual-run: mirror a credit deduction into the ledger. Fully guarded."""
    try:
        from warden.ledger import dual_write, operations
        from warden.ledger.money import Money
        dual_write.mirror(
            "credits.spend", operations.spend_credits, tenant_id,
            Money.from_micros(credits * _CREDIT_MICROS),
            idempotency_key=f"credits-spend-{tenant_id}-{uuid.uuid4().hex}",
        )
    except Exception as exc:  # shadow ledger (or its import) must never break credits
        record_failopen("credits_ledger_mirror", Reason.BACKEND_ERROR, exc)


def purchase_credits(tenant_id: str, package_id: str) -> int:
    """Add credits for *package_id* to *tenant_id*. Returns new balance.

    In production this is called from the Lemon Squeezy webhook handler after
    payment confirmation — not directly from the API (which should redirect to
    checkout). Tests can call it directly to seed balances.
    """
    package = CREDIT_PACKAGES.get(package_id)
    if not package:
        raise ValueError(f"Unknown credit package: {package_id!r}. "
                         f"Valid: {list(CREDIT_PACKAGES)}")
    amount = package["credits"]
    new_balance = _db_add_credits(tenant_id, amount)
    _redis_sync(tenant_id, new_balance)
    _mirror_credit_grant(tenant_id, amount)
    log.info("credits: purchased package=%s credits=%d tenant=%s new_balance=%d",
             package_id, amount, tenant_id, new_balance)
    return new_balance


def deduct_credits(tenant_id: str, amount: int = 1) -> bool:
    """Deduct *amount* credits from *tenant_id*. Returns False (not exception) on insufficient balance.

    Fast-path: Redis DECRBY with optimistic check.
    Fallback: SQLite when Redis unavailable.
    """
    if amount <= 0:
        return True

    # Redis fast-path — optimistic deduct then verify
    try:
        r = _redis()
        if r:
            key = _redis_key(tenant_id)
            new_val = r.decrby(key, amount)
            if new_val >= 0:
                # Deduction succeeded in Redis; sync to SQLite asynchronously on next purchase
                import contextlib
                with contextlib.suppress(Exception):
                    _db_deduct_credits(tenant_id, amount)
                _mirror_credit_spend(tenant_id, amount)
                return True
            else:
                # Restore Redis (went negative — insufficient balance)
                r.incrby(key, amount)
                return False
    except Exception as exc:
        log.debug("credits redis deduct error, falling back to SQLite: %s", exc)

    # SQLite fallback
    result = _db_deduct_credits(tenant_id, amount)
    if result:
        balance = _db_get_balance(tenant_id)
        _redis_sync(tenant_id, balance)
        _mirror_credit_spend(tenant_id, amount)
    return result


def get_balance(tenant_id: str) -> int:
    """Return current credit balance. Redis fast-path, SQLite fallback."""
    cached = _redis_get_balance(tenant_id)
    if cached is not None:
        return cached
    balance = _db_get_balance(tenant_id)
    _redis_sync(tenant_id, balance)
    return balance


def all_balances() -> dict[str, int]:
    """Every tenant's credit balance from SQLite (the durable source of truth).

    Used by the FT-2 ledger reconciliation job. Reads SQLite, not Redis — Redis is
    a fast-path cache and may lag; the SQLite table is authoritative.
    """
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT tenant_id, balance_credits FROM marketplace_credits"
        ).fetchall()
    return {r["tenant_id"]: int(r["balance_credits"]) for r in rows}
