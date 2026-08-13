"""
warden/tests/marketplace_schema.py

Build a marketplace test database from the **real** registered DDL.

Every clearing/escrow test used to hand-roll its own `CREATE TABLE`, and each
one invented columns the product does not have — `marketplace_negotiations`
with `agreed_price` and `buyer_agent_id`, an escrow table spelled
`marketplace_escrows`. Those fixtures did not merely fail to catch the
name mismatches in `clearing.py`, `data_lifecycle.py`, `auto_responder.py`
and `scheduler.py`: they **agreed with them**, so a suite that was green end
to end was pinning a schema that has never existed in production.

Fixtures that build from the module DDL cannot drift from it. A column rename
in `negotiation.py` now breaks the tests that depend on it, which is the whole
point of having them.

Not named `test_*` so pytest does not try to collect it as a test module.
"""
from __future__ import annotations

import sqlite3

from warden.marketplace.agent import _AGENTS_DDL
from warden.marketplace.clearing import _CLEARING_DDL
from warden.marketplace.escrow import _ESCROW_DDL
from warden.marketplace.listing import _LISTING_DDL
from warden.marketplace.negotiation import _NEGOTIATION_DDL

#: Every marketplace table a test is likely to touch, in dependency order.
MARKETPLACE_DDL = (
    _AGENTS_DDL,
    _LISTING_DDL,
    _NEGOTIATION_DDL,
    _ESCROW_DDL,
    _CLEARING_DDL,
)


def create_marketplace_schema(db_path: str) -> None:
    """Apply the product's own marketplace DDL to ``db_path``."""
    con = sqlite3.connect(db_path)
    try:
        for ddl in MARKETPLACE_DDL:
            con.executescript(ddl)
        con.commit()
    finally:
        con.close()


def seed_negotiation(
    db_path: str,
    negotiation_id: str,
    *,
    buyer_agent: str = "buyer-1",
    seller_agent: str = "seller-1",
    listing_id: str = "lst-1",
    status: str = "active",
    price: float = 100.0,
) -> None:
    """Insert one negotiation using the real column names."""
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """INSERT OR IGNORE INTO marketplace_negotiations
                   (negotiation_id, listing_id, buyer_agent, seller_agent,
                    asset_ueciid, status, current_price, round_count,
                    created_at, updated_at)
               VALUES (?,?,?,?,'',?,?,0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')""",
            (negotiation_id, listing_id, buyer_agent, seller_agent, status, price),
        )
        con.commit()
    finally:
        con.close()
