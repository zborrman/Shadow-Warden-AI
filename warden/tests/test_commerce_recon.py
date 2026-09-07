"""
warden/tests/test_commerce_recon.py
────────────────────────────────────
PR-7 — mandate ↔ order ↔ receipt reconciliation and the LLM-free watchdog
that schedules it.
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")

from warden.finops import commerce_recon as cr  # noqa: E402
from warden.observability import COUNTED, NOT_AVAILABLE, NOTHING_TO_CHECK  # noqa: E402


def _mandate(mid="m1", cap=1000.0, spent=0.0, status="ACTIVE", valid_until="2099-01-01T00:00:00Z"):
    return SimpleNamespace(id=mid, max_amount=cap, spent_so_far=spent,
                           status=status, valid_until=valid_until)


def _order(oid="o1", mid="m1", total=100.0, status="PAID", items=None):
    return {"id": oid, "mandate_id": mid, "total": total, "status": status,
            "items": items or []}


def _patch_load(monkeypatch, mandates, orders, receipts, evidence=COUNTED):
    monkeypatch.setattr(cr, "_load", lambda _t: (mandates, orders, receipts, evidence))


def test_clean_books_reconcile(monkeypatch):
    _patch_load(monkeypatch,
                [_mandate(spent=100.0)],
                [_order()],
                {"o1": {"amount": 100.0}})
    r = cr.reconcile_commerce("acme")
    assert r["ok"] is True
    assert r["findings"] == []
    assert r["evidence"] == COUNTED


def test_ghost_spend_is_critical(monkeypatch):
    """The live production signature: paid orders, mandate spend still $0.00."""
    _patch_load(monkeypatch,
                [_mandate(cap=4000.0, spent=0.0)],
                [_order(total=1000.0)],
                {"o1": {"amount": 1000.0}})
    r = cr.reconcile_commerce("acme")
    drift = [f for f in r["findings"] if f["type"] == "spend_drift"]
    assert len(drift) == 1
    assert drift[0]["severity"] == "critical"
    assert "never written back" in drift[0]["detail"]
    assert drift[0]["orders_total"] == 1000.0
    assert r["ok"] is False


def test_cap_breach_detected(monkeypatch):
    _patch_load(monkeypatch, [_mandate(cap=100.0, spent=250.0)],
                [_order(total=250.0)], {"o1": {"amount": 250.0}})
    types = {f["type"] for f in cr.reconcile_commerce("acme")["findings"]}
    assert "cap_breach" in types


def test_expired_mandate_still_active(monkeypatch):
    _patch_load(monkeypatch,
                [_mandate(spent=0.0, valid_until="2020-01-01T00:00:00Z")], [], {})
    fs = cr.reconcile_commerce("acme")["findings"]
    assert [f["type"] for f in fs] == ["expired_active"]


def test_expired_but_revoked_is_not_a_finding(monkeypatch):
    _patch_load(monkeypatch,
                [_mandate(status="REVOKED", valid_until="2020-01-01T00:00:00Z")], [], {})
    assert cr.reconcile_commerce("acme")["findings"] == []


def test_paid_order_without_receipt(monkeypatch):
    _patch_load(monkeypatch, [_mandate(spent=100.0)], [_order()], {})
    fs = cr.reconcile_commerce("acme")["findings"]
    assert any(f["type"] == "receipt_gap" for f in fs)


def test_receipt_amount_mismatch(monkeypatch):
    _patch_load(monkeypatch, [_mandate(spent=100.0)], [_order(total=100.0)],
                {"o1": {"amount": 1.0}})
    gap = [f for f in cr.reconcile_commerce("acme")["findings"] if f["type"] == "receipt_gap"]
    assert gap and gap[0]["severity"] == "critical"


def test_zero_total_order_with_line_items(monkeypatch):
    order = _order(total=0.0, status="PENDING",
                   items=[{"unit_price": 25.0, "qty": 4}])
    _patch_load(monkeypatch, [], [order], {})
    fs = cr.reconcile_commerce("acme")["findings"]
    assert [f["type"] for f in fs] == ["zero_total"]
    assert "100.00" in fs[0]["detail"]


def test_float_noise_is_not_a_finding(monkeypatch):
    _patch_load(monkeypatch, [_mandate(spent=100.0000001)],
                [_order(total=100.0)], {"o1": {"amount": 99.999999}})
    assert cr.reconcile_commerce("acme")["findings"] == []


def test_unreadable_tables_are_never_ok(monkeypatch):
    """A reconciliation that could not run must not look like one that passed."""
    _patch_load(monkeypatch, [], [], {}, evidence=NOT_AVAILABLE)
    r = cr.reconcile_commerce("acme")
    assert r["ok"] is False
    assert r["evidence"] == NOT_AVAILABLE


def test_empty_tenant_is_nothing_to_check(monkeypatch):
    _patch_load(monkeypatch, [], [], {}, evidence=NOTHING_TO_CHECK)
    r = cr.reconcile_commerce("acme")
    assert r["ok"] is True and r["evidence"] == NOTHING_TO_CHECK


def test_load_scopes_receipts_to_tenant_orders(tmp_path, monkeypatch):
    """commerce_receipts has no tenant column — the read must not cross tenants."""
    import sqlite3
    db = tmp_path / "c.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.executescript(
        "CREATE TABLE commerce_orders (id TEXT, tenant_id TEXT, mandate_id TEXT,"
        " data_json TEXT, created_at TEXT);"
        "CREATE TABLE commerce_receipts (id TEXT, order_id TEXT, data_json TEXT,"
        " created_at TEXT);"
    )
    con.execute("INSERT INTO commerce_orders VALUES ('o1','acme','m1',?,'')",
                (json.dumps(_order()),))
    con.execute("INSERT INTO commerce_receipts VALUES ('r1','o1',?,'')",
                (json.dumps({"amount": 100.0}),))
    con.execute("INSERT INTO commerce_receipts VALUES ('r9','other-tenant-order',?,'')",
                (json.dumps({"amount": 999.0}),))
    con.commit()

    import contextlib
    import threading

    from warden.business_community.agentic_commerce import ap2
    monkeypatch.setattr(ap2, "_db_lock", threading.RLock())
    monkeypatch.setattr(ap2, "_conn",
                        lambda *_a, **_k: contextlib.nullcontext(con))
    monkeypatch.setattr(ap2.AP2Processor, "list_mandates",
                        lambda _s, _t: [_mandate(spent=100.0)])

    _m, orders, receipts, evidence = cr._load("acme")
    assert evidence == COUNTED
    assert list(receipts) == ["o1"]
    assert len(orders) == 1
    con.close()


# ── Tool + cron wiring ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reconcile_orders_tool_registered(monkeypatch):
    from warden.agent import tools as t
    assert "reconcile_orders" in t.TOOL_HANDLERS
    assert "reconcile_orders" in {d["name"] for d in t.TOOLS}
    # read-only: must not require human approval
    assert "reconcile_orders" not in t.OPERATOR_TOOLS

    monkeypatch.setattr("warden.finops.commerce_recon.reconcile_commerce",
                        lambda tid: {"ok": True, "tenant_id": tid})
    assert (await t.reconcile_orders(tenant_id="acme"))["tenant_id"] == "acme"


def test_every_tool_schema_matches_its_handler():
    """A required schema param the handler does not accept is silently ignored.

    semantic_query advertised `model` while the handler took `model_id`; the
    model's argument fell into **_ and the default ran instead.
    """
    import inspect

    from warden.agent import tools as t
    problems = []
    for spec in t.TOOLS:
        handler = t.TOOL_HANDLERS.get(spec["name"])
        if handler is None:
            problems.append(f"{spec['name']}: no handler")
            continue
        params = inspect.signature(handler).parameters
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            declared = set(params)
            for prop in spec["input_schema"].get("required", []):
                if prop not in declared:
                    problems.append(f"{spec['name']}: required '{prop}' not in handler signature")
    assert not problems, problems


@pytest.mark.asyncio
async def test_watchdog_alerts_on_findings(monkeypatch):
    from warden.agent import scheduler as sch
    sent: list[str] = []
    monkeypatch.setattr(sch, "_slack", lambda msg: sent.append(msg) or _noop())
    monkeypatch.setattr(
        "warden.finops.commerce_recon.reconcile_commerce",
        lambda _t: {"ok": False, "evidence": COUNTED, "findings": [
            {"type": "spend_drift", "severity": "critical", "mandate_id": "m1",
             "detail": "paid orders total $1000.00 but mandate records $0.00"}],
            "critical": 1, "by_type": {"spend_drift": 1},
            "mandates_checked": 1, "orders_checked": 1, "receipts_seen": 1,
            "tenant_id": "acme", "checked_at": "now"})
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "alerted"
    assert sent and "spend_drift" in sent[0]


@pytest.mark.asyncio
async def test_watchdog_alerts_when_it_could_not_run(monkeypatch):
    """'The reconciler was down' must not read the same as 'the books balance'."""
    from warden.agent import scheduler as sch
    sent: list[str] = []
    monkeypatch.setattr(sch, "_slack", lambda msg: sent.append(msg) or _noop())
    monkeypatch.setattr(
        "warden.finops.commerce_recon.reconcile_commerce",
        lambda _t: {"ok": False, "evidence": NOT_AVAILABLE, "findings": [],
                    "critical": 0, "by_type": {}, "mandates_checked": 0,
                    "orders_checked": 0, "receipts_seen": 0, "tenant_id": "acme",
                    "checked_at": "now"})
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "degraded"
    assert sent and "could not read" in sent[0]


@pytest.mark.asyncio
async def test_watchdog_is_quiet_when_clean(monkeypatch):
    from warden.agent import scheduler as sch
    sent: list[str] = []
    monkeypatch.setattr(sch, "_slack", lambda msg: sent.append(msg) or _noop())
    monkeypatch.setattr(
        "warden.finops.commerce_recon.reconcile_commerce",
        lambda _t: {"ok": True, "evidence": COUNTED, "findings": [], "critical": 0,
                    "by_type": {}, "mandates_checked": 2, "orders_checked": 3,
                    "receipts_seen": 3, "tenant_id": "acme", "checked_at": "now"})
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "ok"
    assert sent == []


async def _noop() -> None:
    return None


def test_watchdog_registered_as_cron_and_manual_task():
    from warden.api.agent import _MANUAL_TASKS
    assert _MANUAL_TASKS["commerce-watchdog"] == "sova_commerce_watchdog"

    try:
        from warden.workers import settings as ws
    except ImportError:
        # arq is not installed in every dev env, but "the cron was never
        # registered" is precisely the failure this test exists to catch — so
        # fall back to asserting on the source rather than skipping outright.
        import pathlib
        src = pathlib.Path(ws_path()).read_text(encoding="utf-8")
        assert "cron(sova_commerce_watchdog" in src
        assert "        sova_commerce_watchdog," in src        # functions tuple
        return
    names = {getattr(c, "name", getattr(c, "__name__", "")) for c in ws.WorkerSettings.cron_jobs}
    assert any("commerce_watchdog" in str(n) for n in names)
    assert any("commerce_watchdog" in str(getattr(f, "name", f))
               for f in ws.WorkerSettings.functions)


def ws_path() -> str:
    import pathlib

    import warden
    return str(pathlib.Path(warden.__file__).parent / "workers" / "settings.py")
