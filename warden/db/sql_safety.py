"""
warden/db/sql_safety.py
────────────────────────
Allowlisted SET-clause builder for the few dynamic UPDATE statements.

Several endpoints build `SET col=:col, ...` from whichever fields the caller supplied.
The column names there are code literals (not request strings) and the *values* are
bound parameters, so the statements were never injectable — but that safety was
incidental: it held only because nobody had yet built the update dict from user keys.
semgrep's avoid-sqlalchemy-text rule flags exactly this shape, and it is right to.

`safe_set_clause()` makes the property structural instead: a column that is not in the
caller's explicit allowlist raises, so the f-string can only ever interpolate names the
developer named. Values are still bound (`:col`) and never interpolated.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping


class UnsafeColumnError(ValueError):
    """Raised when an update targets a column outside the allowlist."""


def safe_set_clause(
    updates: Mapping[str, object],
    allowed: Iterable[str],
    *,
    sep: str = ", ",
    assign: str = "{col} = :{col}",
) -> str:
    """
    Build `col = :col, other = :other` from ``updates``, restricted to ``allowed``.

    Raises UnsafeColumnError on any column outside the allowlist — so the resulting
    string is composed exclusively of developer-declared identifiers.
    """
    allowed_set = frozenset(allowed)
    if not updates:
        raise UnsafeColumnError("no columns to update")
    bad = [c for c in updates if c not in allowed_set]
    if bad:
        raise UnsafeColumnError(f"column(s) not allowed in UPDATE: {sorted(bad)}")
    return sep.join(assign.format(col=c) for c in updates)
