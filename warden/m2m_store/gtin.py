"""
warden/m2m_store/gtin.py
────────────────────────
Plan stage R8.3: a product's GS1 Global Trade Item Number.

A GTIN is 8, 12, 13 or 14 digits (GTIN-8 / UPC-A / EAN-13 / GTIN-14) whose
last digit is a mod-10 check over the others (GS1 General Specifications,
section 7.9). We check the shape and the check digit only: whether the number
was licensed to this seller is GS1's register to answer, not ours, and nothing
here claims it was.
"""
from __future__ import annotations

import re

LENGTHS = (8, 12, 13, 14)
_SEPARATORS = re.compile(r"[\s-]")


class GtinError(ValueError):
    pass


def check_digit(body: str) -> int:
    """The check digit for the digits before it (weights 3,1,3,1... from the right)."""
    total = sum(int(d) * (3 if i % 2 == 0 else 1) for i, d in enumerate(reversed(body)))
    return (10 - total % 10) % 10


def normalize(raw: str) -> str:
    """Digits only, validated. Empty input means "no GTIN" and returns ""."""
    s = _SEPARATORS.sub("", raw or "")
    if not s:
        return ""
    if not s.isascii() or not s.isdigit():
        raise GtinError("a GTIN has digits only")
    if len(s) not in LENGTHS:
        raise GtinError("a GTIN has 8, 12, 13 or 14 digits")
    if set(s) == {"0"}:
        raise GtinError("a GTIN cannot be all zeros")
    if check_digit(s[:-1]) != int(s[-1]):
        raise GtinError("the GTIN check digit does not match; check the number")
    return s


def kind(gtin: str) -> str:
    """The symbology a label prints it with."""
    return {8: "EAN-8", 12: "UPC-A", 13: "EAN-13", 14: "ITF-14"}.get(len(gtin), "")


def taken_by(tenant_id: str, gtin: str, product_id: str = "") -> str:
    """Another live product of the same seller with this GTIN, or ""."""
    if not gtin:
        return ""
    from .inventory import _conn, _db_lock
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT id FROM m2m_products WHERE json_extract(data_json,'$.tenant_id')=?"
            " AND json_extract(data_json,'$.gtin')=? AND id<>?"
            " AND COALESCE(json_extract(data_json,'$.deleted_at'),'')=''",
            (tenant_id, gtin, product_id or ""),
        ).fetchone()
    return row["id"] if row else ""
