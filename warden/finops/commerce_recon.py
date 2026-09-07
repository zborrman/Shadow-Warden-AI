"""
warden/finops/commerce_recon.py — mandate ↔ order ↔ receipt reconciliation.

`order_recon.py` answers "did the order mirror receive what the source wrote".
This module answers a different question one layer down: **does the money inside
`agentic_commerce` add up at all**.

It exists because production currently says it does not. `get_mandate_usage()`
on live data reports four mandates, $4 000 authorised and `total_spent` of
**$0.00**, while paid orders reference those same mandates. That is the same
class of defect as the clearing bug that settled every trade at $0.00 for
months: a field nothing writes reads back as a confident zero, and every
dashboard above it agrees.

Four independent checks, counted separately because they have different causes:

    cap_breach      a mandate whose recorded spend exceeds its own max_amount —
                    the spending cap did not hold
    expired_active  a mandate past valid_until still marked ACTIVE — it will
                    still authorise a payment
    spend_drift     paid orders reference a mandate but `spent_so_far` does not
                    match their total. The $0.00 case is called out separately
                    because "never written" and "written slightly wrong" have
                    different root causes
    receipt_gap     an order marked PAID with no receipt row, or a receipt whose
                    amount disagrees with the order total

Evidence follows the `observability` labels: a check that could not read the
tables reports ``not_available``, never a clean ``ok``. A reconciliation that
cannot run must not look like a reconciliation that passed.

Pure computation — no LLM, no network. Scheduling lives in
`warden/agent/scheduler.py::sova_commerce_watchdog`; the same function backs the
`reconcile_orders` agent tool.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from warden.observability import COUNTED, NOT_AVAILABLE, NOTHING_TO_CHECK, Reason, record_failopen

log = logging.getLogger("warden.finops.commerce_recon")

# Money is compared in whole cents — a float round-trip through JSON must not
# be reported as a finding.
_CENT = 0.005


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_ts(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _load(tenant_id: str) -> tuple[list, list[dict], dict[str, dict], str]:
    """Read mandates, orders and receipts for *tenant_id*.

    Returns ``(mandates, orders, receipts_by_order_id, evidence)``. Any read
    failure yields ``not_available`` rather than an empty-but-clean result.
    """
    try:
        from warden.business_community.agentic_commerce.ap2 import AP2Processor, _conn, _db_lock
    except Exception as exc:
        record_failopen("commerce_recon", Reason.IMPORT_MISSING, exc)
        return [], [], {}, NOT_AVAILABLE

    try:
        ap2 = AP2Processor()
        mandates = ap2.list_mandates(tenant_id)
    except Exception as exc:
        record_failopen("commerce_recon", Reason.BACKEND_ERROR, exc)
        return [], [], {}, NOT_AVAILABLE

    orders: list[dict] = []
    receipts: dict[str, dict] = {}
    try:
        with _db_lock, _conn() as con:
            for row in con.execute(
                "SELECT data_json FROM commerce_orders WHERE tenant_id=?", (tenant_id,)
            ).fetchall():
                try:
                    orders.append(json.loads(row["data_json"]))
                except (ValueError, TypeError):
                    continue
            # commerce_receipts has no tenant_id column — it is keyed by
            # order_id. Scope the read to this tenant's orders rather than
            # reading the whole table, which would be a cross-tenant read.
            # json_each keeps this a constant SQL string with a single bound
            # parameter, so no id is ever interpolated into the statement.
            order_ids = [str(o.get("id", "")) for o in orders if o.get("id")]
            if order_ids:
                for row in con.execute(
                    "SELECT order_id, data_json FROM commerce_receipts "
                    "WHERE order_id IN (SELECT value FROM json_each(?))",
                    (json.dumps(order_ids),),
                ).fetchall():
                    try:
                        receipts[row["order_id"]] = json.loads(row["data_json"])
                    except (ValueError, TypeError):
                        continue
    except Exception as exc:
        record_failopen("commerce_recon", Reason.BACKEND_ERROR, exc)
        return mandates, [], {}, NOT_AVAILABLE

    if not mandates and not orders:
        return mandates, orders, receipts, NOTHING_TO_CHECK
    return mandates, orders, receipts, COUNTED


def active_tenants() -> tuple[list[str], str]:
    """Every tenant with commerce records, and whether the list can be trusted.

    Returns ``(tenant_ids, evidence)``. A reconciler that runs for one hardcoded
    tenant reports "clean" for every other tenant it never looked at, so the
    caller needs to know the difference between "no other tenants" and "could
    not enumerate them".
    """
    try:
        from warden.business_community.agentic_commerce.ap2 import _conn, _db_lock
    except Exception as exc:
        record_failopen("commerce_recon", Reason.IMPORT_MISSING, exc)
        return [], NOT_AVAILABLE

    found: set[str] = set()
    try:
        with _db_lock, _conn() as con:
            # Written out rather than interpolated from a loop variable: the
            # table names are fixed, and a constant statement needs no
            # "this interpolation is safe" suppression to prove it.
            for sql in (
                "SELECT DISTINCT tenant_id FROM commerce_mandates",
                "SELECT DISTINCT tenant_id FROM commerce_orders",
            ):
                for row in con.execute(sql).fetchall():
                    if row["tenant_id"]:
                        found.add(str(row["tenant_id"]))
    except Exception as exc:
        record_failopen("commerce_recon", Reason.BACKEND_ERROR, exc)
        return sorted(found), NOT_AVAILABLE

    return sorted(found), (COUNTED if found else NOTHING_TO_CHECK)


def reconcile_commerce(tenant_id: str = "default") -> dict[str, Any]:
    """Reconcile mandates, orders and receipts for one tenant.

    Never raises. ``ok`` is True only when the check actually ran and found
    nothing; a check that could not run reports ``ok=False`` with
    ``evidence="not_available"``.
    """
    mandates, orders, receipts, evidence = _load(tenant_id)

    findings: list[dict[str, Any]] = []
    now = _now()

    # ── Orders grouped by mandate ────────────────────────────────────────────
    paid_by_mandate: dict[str, float] = {}
    for o in orders:
        if str(o.get("status", "")).upper() == "PAID":
            mid = str(o.get("mandate_id", ""))
            paid_by_mandate[mid] = paid_by_mandate.get(mid, 0.0) + float(o.get("total") or 0.0)

    # ── Mandate checks ───────────────────────────────────────────────────────
    for m in mandates:
        mid = getattr(m, "id", "")
        spent = float(getattr(m, "spent_so_far", 0.0) or 0.0)
        cap = float(getattr(m, "max_amount", 0.0) or 0.0)
        status = str(getattr(m, "status", "")).upper()

        if spent - cap > _CENT:
            findings.append({
                "type": "cap_breach", "severity": "critical", "mandate_id": mid,
                "detail": f"spent ${spent:.2f} exceeds cap ${cap:.2f}",
            })

        expires = _parse_ts(str(getattr(m, "valid_until", "")))
        if status == "ACTIVE" and expires is not None and expires < now:
            findings.append({
                "type": "expired_active", "severity": "high", "mandate_id": mid,
                "detail": f"valid_until {expires.isoformat()} has passed but status is ACTIVE",
            })

        booked = paid_by_mandate.get(mid, 0.0)
        if abs(booked - spent) > _CENT:
            zero = spent == 0.0 and booked > 0.0
            findings.append({
                "type": "spend_drift",
                "severity": "critical" if zero else "high",
                "mandate_id": mid,
                "detail": (
                    f"paid orders total ${booked:.2f} but mandate records "
                    f"${spent:.2f}"
                    + (" — spend was never written back (ghost-schema signature)"
                       if zero else "")
                ),
                "orders_total": round(booked, 2),
                "mandate_spent": round(spent, 2),
            })

    # ── Order / receipt checks ───────────────────────────────────────────────
    for o in orders:
        oid = str(o.get("id", ""))
        status = str(o.get("status", "")).upper()
        total = float(o.get("total") or 0.0)
        rec = receipts.get(oid)

        if status == "PAID" and rec is None:
            findings.append({
                "type": "receipt_gap", "severity": "high", "order_id": oid,
                "detail": f"order is PAID (${total:.2f}) with no receipt row",
            })
        elif rec is not None:
            amount = float(rec.get("amount") or 0.0)
            if abs(amount - total) > _CENT:
                findings.append({
                    "type": "receipt_gap", "severity": "critical", "order_id": oid,
                    "detail": f"receipt says ${amount:.2f}, order says ${total:.2f}",
                })

        items = o.get("items") or []
        if total <= _CENT and items:
            line_total = sum(
                float(i.get("unit_price") or 0.0) * int(i.get("qty") or 1) for i in items
            )
            if line_total > _CENT:
                findings.append({
                    "type": "zero_total", "severity": "critical", "order_id": oid,
                    "detail": f"order total is $0.00 but line items sum to ${line_total:.2f}",
                })

    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    return {
        "ok": evidence != NOT_AVAILABLE and not findings,
        "evidence": evidence,
        "tenant_id": tenant_id,
        "mandates_checked": len(mandates),
        "orders_checked": len(orders),
        "receipts_seen": len(receipts),
        "findings": findings,
        "by_type": by_type,
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "checked_at": now.isoformat(),
    }
