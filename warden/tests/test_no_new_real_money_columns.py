"""
FT-0 — float-money ratchet.

Counts `REAL`-typed money columns in SQLite DDL across warden/ and enforces a
committed baseline that may only DROP. Float money loses cents at scale and
cannot be reconciled to zero; the ledger core (`warden/ledger/money.py`) is
integer micro-USD. New money state must be integer (`INTEGER … µUSD`, the
`sac_wallets` pattern) or route through `Money` — never a new `REAL` column.

Why a ratchet and not a ban: 40+ legacy `REAL` money columns remain across the
three commerce stacks (see `docs/money-mutation-inventory.md`); they are frozen
read-only and migrated to journal accounts under FT-2, not rewritten in place.
Freezing the count blocks *new* float money while the existing surface drains.

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_REAL_MONEY_BASELINE=1 pytest warden/tests/test_no_new_real_money_columns.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent
_BASELINE = Path(__file__).parent / "real_money_columns_baseline.json"

# A money-ish column name immediately followed by the REAL SQLite type.
# Matches e.g. `amount_usd REAL`, `price REAL`, `balance_credits  REAL NOT NULL`.
_MONEY = r"(usd|cents|credits|price|amount|budget|spend|balance|fee|revenue|payout|cost)"
_PAT = re.compile(rf"\w*{_MONEY}\w*\s+REAL", re.IGNORECASE)


def count_real_money_columns() -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for py in sorted(_WARDEN.rglob("*.py")):
        rel = py.relative_to(_WARDEN)
        if rel.parts[0] == "tests":
            continue
        try:
            src = py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        n = len(_PAT.findall(src))
        if n:
            per_file[str(rel).replace("\\", "/")] = n
        total += n
    return total, per_file


def test_no_new_real_money_columns():
    total, per_file = count_real_money_columns()
    current = {"total": total, "per_file": dict(sorted(per_file.items()))}

    if os.getenv("UPDATE_REAL_MONEY_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_REAL_MONEY_BASELINE") == "1":
            import pytest
            pytest.skip(f"real-money-column baseline regenerated: total={total}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"REAL money columns rose: {total} > baseline {base['total']}. "
        "New money state must be integer micro-USD (see warden/ledger/money.py) "
        "or go through Money — not a REAL column. "
        "Regenerate only after a genuine reduction: "
        "UPDATE_REAL_MONEY_BASELINE=1 pytest warden/tests/test_no_new_real_money_columns.py"
    )
