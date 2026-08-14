"""
warden/finops/order_recon.py — FT-6 Phase C readiness (order-model mirror).

FT-6 Phase B put `m2m_store` and `agentic_commerce` on a dual write: after their
own order table write succeeds, they mirror a fielded row into
`marketplace_purchases` keyed on `(domain, purchase_id)`. Their own tables stay
the source of truth and **every reader still queries them** — the mirror is
explicitly documented as "fail-soft best-effort, not yet trusted".

Phase C is the cutover: readers start querying the mirror. The gate on that is
"the mirror can be trusted", which until now nothing measured. That is the same
shape as the FT-2 ledger cutover, which was gated on a report that could pass
without checking anything (see `ledger_recon.py`) — so this module deliberately
speaks the same vocabulary rather than inventing a second one.

Three ways a mirror row can be wrong, all counted separately because they have
different causes:

    missing     the source has an order the mirror never received — a dropped
                dual write, which is exactly what the three fail-soft
                `except Exception: log.debug(...)` sites at the call sites
                produce when the mirror DB is unavailable
    mismatched  both rows exist and disagree on status or amount
    orphaned    the mirror holds a row for a source order that does not exist

Status comparison has one legitimate exception. `agentic_commerce/ap2.py`
mirrors a *receipt* by upserting `status="PAID"` onto the order's own
`purchase_id`, so once a receipt exists the mirror reads PAID while
`commerce_orders.data_json["status"]` may still read whatever the order was
last set to. That is correct behaviour, not drift, and is treated as such —
an unencoded "we'll eyeball it before Phase C" would have flagged every paid
order in the system.

Amount comparison relies on `upsert_mirrored_order` deliberately never
UPDATE-ing `price_paid` (it is set once at creation). A source total that later
disagrees with the mirror is therefore a genuine finding, not an artefact.

Cross-module reads use lazy imports (the `ledger_recon.py` pattern) so this
stays an error-swallowing adapter over the order modules rather than a hard
import dependency. Pure computation — scheduling lives in
`warden/workers/order_recon_job.py`.
"""
from __future__ import annotations

import json
import logging

from warden.observability import COUNTED, NOT_AVAILABLE, NOTHING_TO_CHECK, Reason, record_failopen

log = logging.getLogger("warden.finops.order_recon")

#: (domain marker written by upsert_mirrored_order, source table)
_SOURCES = (
    ("m2m_store", "m2m_orders"),
    ("agentic_commerce", "commerce_orders"),
)

# Money is compared in whole cents: both sides store a float, and a float
# round-trip through JSON must not be reported as a Phase C blocker.
_CENT = 0.005


def _source_conn(domain: str):
    """Return the source module's connection helper, or None if unavailable."""
    if domain == "m2m_store":
        from warden.m2m_store.inventory import _conn
        return _conn
    from warden.business_community.agentic_commerce.service import _conn
    return _conn


def _receipted_orders(conn_factory) -> set[str]:
    """Order ids that have a receipt — their mirror is expected to read PAID."""
    try:
        with conn_factory() as con:
            return {
                r[0] for r in con.execute("SELECT DISTINCT order_id FROM commerce_receipts")
            }
    except Exception:
        # No receipts table yet (or unreadable): assume none, which makes the
        # status check stricter, never looser.
        return set()


def order_mirror_drift() -> dict:
    """Compare every source-of-truth order to its FT-6 Phase B mirror row.

    Returns::

        {orders_checked, orders_enumerated, unreadable, missing, mismatched,
         orphaned, drifted, ok, evidence, details, by_source}

    ``ok`` means no disagreement was found *among the orders actually
    compared* — read ``evidence`` and ``unreadable`` to learn whether that was
    any order at all. Fail-soft: a read error yields an unreadable report
    rather than raising. Reconciliation observes, it never blocks.
    """
    try:
        from warden.marketplace import listing
    except Exception as exc:
        record_failopen("order_mirror_recon", Reason.IMPORT_MISSING, exc)
        log.debug("order_recon: marketplace.listing unavailable (%s)", exc)
        return _summary([], {}, evidence=NOT_AVAILABLE)

    details: list[dict] = []
    by_source: dict[str, dict] = {}
    checked = enumerated = unreadable = 0
    any_source_readable = False

    for domain, table in _SOURCES:
        rep = _reconcile_source(listing, domain, table)
        by_source[domain] = rep
        enumerated += rep["orders_enumerated"]
        checked += rep["orders_checked"]
        unreadable += rep["unreadable"]
        details.extend(rep["details"])
        if rep["evidence"] != NOT_AVAILABLE:
            any_source_readable = True

    if not any_source_readable:
        evidence = NOT_AVAILABLE
    elif any(r["evidence"] == COUNTED for r in by_source.values()):
        evidence = COUNTED
    elif unreadable:
        evidence = NOT_AVAILABLE
    else:
        evidence = NOTHING_TO_CHECK

    return _summary(
        details, by_source,
        checked=checked, enumerated=enumerated, unreadable=unreadable, evidence=evidence,
    )


def _reconcile_source(listing, domain: str, table: str) -> dict:
    """Reconcile one source table against its slice of the mirror."""
    try:
        conn_factory = _source_conn(domain)
    except Exception as exc:
        record_failopen(f"order_mirror_{domain}", Reason.IMPORT_MISSING, exc)
        log.debug("order_recon: %s unavailable (%s)", domain, exc)
        return _summary([], {}, evidence=NOT_AVAILABLE)

    try:
        with conn_factory() as con:
            rows = con.execute(f"SELECT id, data_json FROM {table}").fetchall()  # noqa: S608
    except Exception as exc:
        record_failopen(f"order_mirror_{domain}", Reason.BACKEND_ERROR, exc)
        log.debug("order_recon: %s enumeration failed (%s)", domain, exc)
        return _summary([], {}, evidence=NOT_AVAILABLE)

    try:
        with listing._conn() as con:
            mirrored = {
                r["purchase_id"]: r
                for r in con.execute(
                    "SELECT purchase_id, status, price_paid FROM marketplace_purchases "
                    "WHERE domain = ?",
                    (domain,),
                ).fetchall()
            }
    except Exception as exc:
        record_failopen(f"order_mirror_{domain}", Reason.BACKEND_ERROR, exc)
        log.debug("order_recon: mirror read failed for %s (%s)", domain, exc)
        return _summary([], {}, evidence=NOT_AVAILABLE, enumerated=len(rows), unreadable=len(rows))

    receipted = (
        _receipted_orders(conn_factory) if domain == "agentic_commerce" else frozenset()
    )

    details: list[dict] = []
    checked = unreadable = 0
    seen: set[str] = set()

    for row in rows:
        order_id = row["id"]
        seen.add(order_id)
        try:
            src = json.loads(row["data_json"])
        except Exception as exc:
            unreadable += 1
            record_failopen(f"order_mirror_{domain}", Reason.PARSE_ERROR, exc)
            continue

        mirror = mirrored.get(order_id)
        if mirror is None:
            checked += 1
            details.append({
                "source": domain, "order_id": order_id, "problem": "missing",
                "detail": "the dual write never reached the mirror",
            })
            continue

        checked += 1
        problems = _compare(src, mirror, receipted=order_id in receipted)
        for problem, detail in problems:
            details.append({
                "source": domain, "order_id": order_id,
                "problem": problem, "detail": detail,
            })

    orphans = mirrored.keys() - seen
    for purchase_id in orphans:
        details.append({
            "source": domain, "order_id": purchase_id, "problem": "orphaned",
            "detail": "mirror holds a row the source of truth does not",
        })

    # An orphan counts as evidence: both sides were read successfully and found
    # to disagree. Reporting "nothing_to_check" next to a nonzero orphan count
    # would be the same "ok by vacuity" confusion this vocabulary exists to end.
    observed = checked or orphans
    return _summary(
        details, {},
        checked=checked, enumerated=len(rows), unreadable=unreadable,
        evidence=(
            COUNTED if observed else (NOT_AVAILABLE if unreadable else NOTHING_TO_CHECK)
        ),
    )


def _compare(src: dict, mirror, *, receipted: bool) -> list[tuple[str, str]]:
    """Return (problem, detail) pairs where the mirror row disagrees."""
    out: list[tuple[str, str]] = []

    src_status = str(src.get("status", "") or "")
    mirror_status = str(mirror["status"] or "")
    # A receipted commerce order is mirrored as PAID by ap2.py on purpose.
    if mirror_status != src_status and not (receipted and mirror_status == "PAID"):
        out.append((
            "mismatched",
            f"status: source={src_status!r} mirror={mirror_status!r}",
        ))

    src_total = src.get("total")
    if src_total is not None:
        try:
            if abs(float(src_total) - float(mirror["price_paid"] or 0.0)) > _CENT:
                out.append((
                    "mismatched",
                    f"amount: source={float(src_total)} mirror={float(mirror['price_paid'] or 0.0)}",
                ))
        except (TypeError, ValueError):
            out.append(("mismatched", "amount: source total is not a number"))
    return out


def _summary(
    details: list[dict],
    by_source: dict,
    *,
    checked: int = 0,
    enumerated: int = 0,
    unreadable: int = 0,
    evidence: str,
) -> dict:
    counts = {"missing": 0, "mismatched": 0, "orphaned": 0}
    for d in details:
        counts[d["problem"]] = counts.get(d["problem"], 0) + 1
    rep = {
        "orders_checked": checked,
        "orders_enumerated": enumerated,
        "unreadable": unreadable,
        **counts,
        "drifted": len(details),
        "ok": not details,
        "evidence": evidence,
        "details": details,
    }
    if by_source:
        rep["by_source"] = by_source
    return rep


def phase_c_ready() -> dict:
    """The FT-6 Phase C go/no-go, as code instead of a judgement call.

    Returns ``{ready, reason, mirror}``. Ready requires **positive** evidence
    that the mirror agrees with the source of truth, never merely the absence
    of bad news:

    * orders were genuinely compared (``evidence == "counted"``),
    * nothing was enumerated-but-unreadable, and
    * no order is missing, mismatched or orphaned.

    A zero-order report is not readiness. Both order tables have been empty in
    production since Phase B shipped, so — exactly like the FT-2 shadow period
    — this gate cannot be satisfied by waiting; it needs real order traffic.
    """
    rep = order_mirror_drift()

    blockers: list[str] = []
    if rep["evidence"] != COUNTED:
        blockers.append(
            f"no orders were compared (evidence={rep['evidence']}, "
            f"orders_checked={rep['orders_checked']})"
        )
    if rep["unreadable"]:
        blockers.append(f"{rep['unreadable']} order(s) could not be read")
    for problem in ("missing", "mismatched", "orphaned"):
        if rep[problem]:
            blockers.append(f"{rep[problem]} {problem}")

    return {
        "ready": not blockers,
        "reason": "; ".join(blockers) if blockers else "the mirror agrees with every order read",
        "mirror": rep,
    }
