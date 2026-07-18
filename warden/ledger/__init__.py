"""
warden/ledger/ — the money core (Track F, FT-0).

The single home for money *semantics*: integer micro-USD arithmetic (`money.py`)
today; double-entry journal, accounts, holds, and derived-balance rollups
(FT-1+) next. Storage rides Track B's `open_db()` / `ddl_registry` substrate.

Hard rule (ratchet-enforced): **no float on any money path.** `Money` is an
integer value type; Decimal appears only at the API boundary via
`Money.from_usd()` / `Money.to_usd()`; `float` is rejected with `TypeError`.
"""
from __future__ import annotations

from warden.ledger.money import MICROS_PER_USD, Money

__all__ = ["MICROS_PER_USD", "Money"]
