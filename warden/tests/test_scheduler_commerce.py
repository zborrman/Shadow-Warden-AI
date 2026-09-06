"""
warden/tests/test_scheduler_commerce.py
────────────────────────────────────────
PR-7: sova_commerce_watchdog + reconcile_orders.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


@pytest.mark.asyncio
async def test_commerce_watchdog_flags_overcap_and_bad_settlement(monkeypatch):
    from warden.agent import scheduler, tools

    async def _spend(**_):
        return {"mandates": [
            {"id": "m-over", "max_amount": 100.0, "spent": 120.0, "status": "ACTIVE",
             "valid_until": "2999-01-01T00:00:00+00:00"},
            {"id": "m-expired", "max_amount": 100.0, "spent": 1.0, "status": "ACTIVE",
             "valid_until": "2000-01-01T00:00:00+00:00"},
        ]}

    async def _auctions(**_):
        return {"auctions": [{"id": "a1"}]}

    async def _auction(**_):
        return {"winner": {"risk_score": 0.9, "recommended_vendor": "sketchy.example"}}

    async def _reconcile(**_):
        return {"mismatch_count": 1, "mismatches": [
            {"order_id": "o1", "order_total": 42.0, "settled_amount": 0.0, "reason": "zero settlement"},
        ]}

    slack_msgs = []

    async def _slack(msg):
        slack_msgs.append(msg)

    monkeypatch.setattr(tools, "get_agentic_spend", _spend)
    monkeypatch.setattr(tools, "list_commerce_auctions", _auctions)
    monkeypatch.setattr(tools, "get_commerce_auction", _auction)
    monkeypatch.setattr(tools, "reconcile_orders", _reconcile)
    monkeypatch.setattr(scheduler, "_slack", _slack)

    out = await scheduler.sova_commerce_watchdog({})
    assert out["status"] == "alerted"
    assert out["risky_auctions"] == 1
    assert out["mismatches"] == 1
    assert slack_msgs and "zero settlement" in slack_msgs[0]
    assert "past expiry" in slack_msgs[0]
    assert "at/over cap" in slack_msgs[0]


@pytest.mark.asyncio
async def test_commerce_watchdog_quiet_when_clean(monkeypatch):
    from warden.agent import scheduler, tools

    async def _spend(**_):
        return {"mandates": [{"id": "m1", "max_amount": 100.0, "spent": 10.0,
                              "status": "ACTIVE", "valid_until": "2999-01-01T00:00:00+00:00"}]}

    async def _auctions(**_):
        return {"auctions": []}

    async def _reconcile(**_):
        return {"mismatch_count": 0, "mismatches": []}

    called = []
    monkeypatch.setattr(tools, "get_agentic_spend", _spend)
    monkeypatch.setattr(tools, "list_commerce_auctions", _auctions)
    monkeypatch.setattr(tools, "reconcile_orders", _reconcile)

    async def _slack(msg):
        called.append(msg)

    monkeypatch.setattr(scheduler, "_slack", _slack)

    out = await scheduler.sova_commerce_watchdog({})
    assert out["status"] == "ok"
    assert not called


@pytest.mark.asyncio
async def test_reconcile_orders_detects_zero_settlement(monkeypatch):
    from warden.agent import tools

    async def _fake_get(path, tenant="default", params=None):
        if path.endswith("/orders"):
            return {"orders": [
                {"id": "o1", "total": 50.0, "status": "PAID", "created_at": ""},
                {"id": "o2", "total": 10.0, "status": "PENDING", "created_at": ""},
            ]}
        if path.endswith("/orders/o1"):
            return {"order": {"id": "o1", "total": 50.0, "status": "PAID"},
                    "receipt": {"amount": 0.0}}
        return {}

    monkeypatch.setattr(tools, "_get", _fake_get)
    out = await tools.reconcile_orders(hours=48, tenant_id="default")
    assert out["checked"] == 1            # only the PAID order
    assert out["mismatch_count"] == 1
    assert out["mismatches"][0]["reason"] == "zero settlement"


def test_commerce_watchdog_registered():
    from warden.agent import scheduler
    from warden.api.agent import _MANUAL_TASKS
    assert _MANUAL_TASKS["commerce-watchdog"] == "sova_commerce_watchdog"
    assert callable(scheduler.sova_commerce_watchdog)

    try:
        from warden.workers.settings import WorkerSettings
    except ModuleNotFoundError:
        pytest.skip("arq not installed in this environment")
    names = {getattr(f, "__name__", "") for f in WorkerSettings.functions}
    assert "sova_commerce_watchdog" in names
    crons = [getattr(c, "coroutine", getattr(c, "func", None)) for c in WorkerSettings.cron_jobs]
    assert any(getattr(fn, "__name__", "") == "sova_commerce_watchdog" for fn in crons if fn)
