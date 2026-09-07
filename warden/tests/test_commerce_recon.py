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
    """commerce_receipts has no tenant column — the read must not cross tenants.

    Built through `open_db` against the commerce DDL that ap2.py registers,
    rather than a hand-written CREATE TABLE: a fixture that declares its own
    schema can drift from production and still pass, which is how a reconciler
    ends up agreeing with a table shape nothing actually writes.
    """
    import threading

    from warden.business_community.agentic_commerce import ap2
    from warden.db.connect import open_db

    db = str(tmp_path / "commerce.db")
    with open_db("commerce", db, module_default_path=db) as con:
        con.execute(
            "INSERT INTO commerce_orders(id, tenant_id, mandate_id, data_json,"
            " created_at) VALUES ('o1','acme','m1',?,'')", (json.dumps(_order()),))
        con.execute("INSERT INTO commerce_receipts(id, order_id, data_json,"
                    " created_at) VALUES ('r1','o1',?,'')",
                    (json.dumps({"amount": 100.0}),))
        con.execute("INSERT INTO commerce_receipts(id, order_id, data_json,"
                    " created_at) VALUES ('r9','other-tenant-order',?,'')",
                    (json.dumps({"amount": 999.0}),))

    monkeypatch.setattr(ap2, "_db_lock", threading.RLock())
    monkeypatch.setattr(ap2, "_conn",
                        lambda *_a, **_k: open_db("commerce", db, module_default_path=db))
    monkeypatch.setattr(ap2.AP2Processor, "list_mandates",
                        lambda _s, _t: [_mandate(spent=100.0)])

    _m, orders, receipts, evidence = cr._load("acme")
    assert evidence == COUNTED
    assert list(receipts) == ["o1"]          # the other tenant's receipt is not read
    assert len(orders) == 1


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
def _report(tenant, findings=(), critical=0, evidence=COUNTED, mandates=1, orders=1):
    return {"ok": not findings, "evidence": evidence, "findings": list(findings),
            "critical": critical, "by_type": {}, "mandates_checked": mandates,
            "orders_checked": orders, "receipts_seen": orders,
            "tenant_id": tenant, "checked_at": "now"}


def _patch_watchdog(monkeypatch, sch, tenants, evidence, per_tenant):
    sent: list[str] = []
    monkeypatch.setattr(sch, "_slack", lambda msg: sent.append(msg) or _noop())
    monkeypatch.setattr("warden.finops.commerce_recon.active_tenants",
                        lambda: (list(tenants), evidence))
    monkeypatch.setattr("warden.finops.commerce_recon.reconcile_commerce", per_tenant)
    return sent


_DRIFT = {"type": "spend_drift", "severity": "critical", "mandate_id": "m1",
          "detail": "paid orders total $1000.00 but mandate records $0.00"}


@pytest.mark.asyncio
async def test_watchdog_alerts_on_findings(monkeypatch):
    from warden.agent import scheduler as sch
    sent = _patch_watchdog(monkeypatch, sch, ["acme"], COUNTED,
                           lambda t: _report(t, [_DRIFT], critical=1))
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "alerted"
    assert sent and "spend_drift" in sent[0]


@pytest.mark.asyncio
async def test_watchdog_checks_every_tenant_not_just_the_default(monkeypatch):
    """A reconciler that checks one hardcoded tenant reports nothing wrong for
    every tenant it never looked at — the same silence as no reconciler."""
    from warden.agent import scheduler as sch
    seen: list[str] = []

    def _per_tenant(tid):
        seen.append(tid)
        return _report(tid, [_DRIFT], critical=1) if tid == "acme-2" else _report(tid)

    sent = _patch_watchdog(monkeypatch, sch, ["acme-1", "acme-2", "acme-3"],
                           COUNTED, _per_tenant)
    out = await sch.sova_commerce_watchdog({})
    assert {"acme-1", "acme-2", "acme-3"} <= set(seen)
    assert out["status"] == "alerted"
    assert out["tenants_checked"] >= 3
    assert out["findings"][0]["tenant_id"] == "acme-2"
    assert sent and "acme-2" in sent[0]


@pytest.mark.asyncio
async def test_one_bad_tenant_does_not_stop_the_sweep(monkeypatch):
    from warden.agent import scheduler as sch
    seen: list[str] = []

    def _per_tenant(tid):
        seen.append(tid)
        if tid == "boom":
            raise RuntimeError("db locked")
        return _report(tid)

    sent = _patch_watchdog(monkeypatch, sch, ["a", "boom", "z"], COUNTED, _per_tenant)
    out = await sch.sova_commerce_watchdog({})
    assert {"a", "boom", "z"} <= set(seen)          # kept going past the failure
    assert out["unreadable"] == 1
    assert out["status"] == "alerted"               # and says so rather than "ok"
    assert sent and "could not be read" in sent[0]


@pytest.mark.asyncio
async def test_a_tenant_that_could_not_be_read_is_not_counted_clean(monkeypatch):
    from warden.agent import scheduler as sch
    sent = _patch_watchdog(monkeypatch, sch, ["a"], COUNTED,
                           lambda t: _report(t, evidence=NOT_AVAILABLE))
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "alerted"
    assert sent and "could not be read" in sent[0]
    # Every tenant checked came back not_available (the default tenant is always
    # added to the sweep), and none of them was counted as clean.
    assert out["unreadable"] == out["tenants_checked"]
    assert out["mandates_checked"] == 0


@pytest.mark.asyncio
async def test_watchdog_alerts_when_it_cannot_enumerate_tenants(monkeypatch):
    """'The reconciler was down' must not read the same as 'the books balance'."""
    from warden.agent import scheduler as sch
    sent = _patch_watchdog(monkeypatch, sch, [], NOT_AVAILABLE,
                           lambda t: _report(t))
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "degraded"
    assert sent and "could not enumerate" in sent[0]


@pytest.mark.asyncio
async def test_watchdog_is_quiet_when_clean(monkeypatch):
    from warden.agent import scheduler as sch
    sent = _patch_watchdog(monkeypatch, sch, ["a", "b"], COUNTED, lambda t: _report(t))
    out = await sch.sova_commerce_watchdog({})
    assert out["status"] == "ok"
    assert sent == []
    assert out["tenants_checked"] >= 2


@pytest.mark.asyncio
async def test_the_default_tenant_survives_the_cap(monkeypatch):
    """Appending the default tenant and then slicing dropped it on every run
    once discovery alone filled the cap — while the docstring claimed it is
    always checked."""
    from warden.agent import scheduler as sch
    from warden.config import settings
    seen: list[str] = []

    def _per_tenant(tid):
        seen.append(tid)
        return _report(tid)

    discovered = [f"t-{i}" for i in range(600)]      # more than the 500 cap
    assert settings.default_tenant_id not in discovered
    _patch_watchdog(monkeypatch, sch, discovered, COUNTED, _per_tenant)

    out = await sch.sova_commerce_watchdog({})
    assert settings.default_tenant_id in seen
    assert out["truncated"] > 0                       # the cap did apply
    assert out["tenants_checked"] == 500


async def _noop() -> None:
    return None


def test_watchdog_registered_as_cron_and_manual_task():
    from warden.api.agent import _MANUAL_TASKS
    assert _MANUAL_TASKS["commerce-watchdog"] == "sova_commerce_watchdog"

    # The source check runs unconditionally, because it is the half that can
    # always run and "the cron was never registered" is exactly what this test
    # exists to catch. Importing the module is the stronger check but it is not
    # always possible: without arq it raises ImportError, and *with* arq under a
    # `memory://` REDIS_URL its module-level RedisSettings.from_dsn() raises
    # RuntimeError("invalid DSN scheme"). Guarding on only one of those made a
    # missing registration invisible in whichever environment hit the other —
    # which is how this passed locally and failed in CI.
    src = _ws_source()
    assert "cron(sova_commerce_watchdog" in src
    assert "        sova_commerce_watchdog," in src            # functions tuple

    try:
        from warden.workers import settings as ws
    except (ImportError, RuntimeError):
        return
    names = {getattr(c, "name", getattr(c, "__name__", "")) for c in ws.WorkerSettings.cron_jobs}
    assert any("commerce_watchdog" in str(n) for n in names)
    assert any("commerce_watchdog" in str(getattr(f, "name", f))
               for f in ws.WorkerSettings.functions)


def _ws_source() -> str:
    import pathlib

    import warden
    path = pathlib.Path(warden.__file__).parent / "workers" / "settings.py"
    return path.read_text(encoding="utf-8")
