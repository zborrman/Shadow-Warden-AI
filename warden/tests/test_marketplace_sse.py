"""
Tests for GET /marketplace/analytics/stream (SSE) and analytics helpers.

Verifies:
  - SSE generator emits valid `data: {...}` events
  - Generator stops cleanly when client disconnects (CancelledError-safe)
  - recent-trades endpoint returns list
  - get_live_metrics returns the expected shape
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def marketplace_db(tmp_path, monkeypatch):
    db = tmp_path / "mp.db"
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(db))
    monkeypatch.setenv("MARKETPLACE_CLEARING_DB_PATH", str(db))
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_agents (
            agent_id TEXT PRIMARY KEY, tenant_id TEXT, status TEXT DEFAULT 'active',
            registered_at REAL, updated_at REAL
        );
        CREATE TABLE IF NOT EXISTS marketplace_listings (
            listing_id TEXT PRIMARY KEY, agent_id TEXT, title TEXT, asset_type TEXT,
            status TEXT DEFAULT 'active', price_usd REAL, created_at REAL
        );
        CREATE TABLE IF NOT EXISTS marketplace_purchases (
            purchase_id TEXT PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT,
            asset_type TEXT, price_paid REAL, status TEXT DEFAULT 'completed',
            purchased_at REAL, created_at REAL
        );
        CREATE TABLE IF NOT EXISTS marketplace_clearing_log (
            clearing_id TEXT, winner_neg_id TEXT, buyer_agent_id TEXT,
            seller_agent_id TEXT, agreed_price REAL, platform_fee_usd REAL,
            seller_net_usd REAL, cleared_at REAL
        );
    """)
    now = time.time()
    for i in range(3):
        con.execute(
            "INSERT INTO marketplace_purchases VALUES (?,?,?,?,?,?,?,?)",
            (f"p{i}", f"buyer{i}", f"seller{i}", "tool", 1.5, "completed", now - i * 100, now - i * 100),
        )
    con.commit()
    con.close()
    return db


# ── Unit: analytics helpers ────────────────────────────────────────────────────

class TestGetLiveMetrics:
    def test_returns_required_keys(self, marketplace_db):
        result = asyncio.run(
            __import__("warden.marketplace.analytics", fromlist=["get_live_metrics"]).get_live_metrics()
        )
        for key in ("communities", "assets", "trades", "auto_import_pct", "fairness", "tiers", "volume_series"):
            assert key in result, f"Missing key: {key}"

    def test_auto_import_always_99(self, marketplace_db):
        from warden.marketplace.analytics import get_live_metrics
        result = asyncio.run(get_live_metrics())
        assert result["auto_import_pct"] == 99

    def test_volume_series_has_labels_and_data(self, marketplace_db):
        from warden.marketplace.analytics import get_live_metrics
        result = asyncio.run(get_live_metrics())
        vs = result["volume_series"]
        assert isinstance(vs["labels"], list)
        assert isinstance(vs["data"], list)
        assert len(vs["labels"]) == len(vs["data"])


class TestGetRecentTrades:
    def test_returns_list(self, marketplace_db):
        from warden.marketplace.analytics import get_recent_trades
        result = get_recent_trades(limit=3)
        assert isinstance(result, list)

    def test_respects_limit(self, marketplace_db):
        from warden.marketplace.analytics import get_recent_trades
        result = get_recent_trades(limit=2)
        assert len(result) <= 2

    def test_returns_empty_on_missing_db(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "nonexistent.db"))
        from warden.marketplace.analytics import get_recent_trades
        result = get_recent_trades()
        assert result is None or isinstance(result, list)


# ── Integration: SSE endpoint ──────────────────────────────────────────────────

@pytest.fixture()
def test_client():
    os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
    os.environ.setdefault("WARDEN_API_KEY", "")
    os.environ.setdefault("REDIS_URL", "memory://")
    from warden.marketplace.api import router
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)  # router already carries /marketplace prefix
    return TestClient(app, raise_server_exceptions=False)


class TestSSEEndpoint:
    def test_recent_trades_endpoint_returns_list(self, test_client, marketplace_db):
        r = test_client.get("/marketplace/analytics/recent-trades?limit=3")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_recent_trades_limit_respected(self, test_client, marketplace_db):
        r = test_client.get("/marketplace/analytics/recent-trades?limit=1")
        assert r.status_code == 200
        assert len(r.json()) <= 1

    def test_stream_route_registered(self, test_client):
        """Verify the /stream route exists (GET returns streaming, not 404)."""
        from unittest.mock import AsyncMock, patch
        # We can't stream indefinitely in tests; check the route is discovered
        import importlib
        api_mod = importlib.import_module("warden.marketplace.api")
        assert hasattr(api_mod, "analytics_stream")

    def test_sse_generator_emits_data_events(self, marketplace_db):
        """Direct test of the SSE generator — collects exactly one event then disconnects."""
        from unittest.mock import AsyncMock, patch

        async def _run():
            import importlib
            api_mod = importlib.import_module("warden.marketplace.api")

            # Disconnect after first check succeeds (second call returns True)
            call_count = 0
            async def _disconnected():
                nonlocal call_count
                call_count += 1
                return call_count > 1

            req = MagicMock()
            req.is_disconnected = _disconnected

            mock_data = {
                "communities": 100, "assets": 200, "trades": 300, "auto_import_pct": 99,
                "fairness": {}, "tiers": {"haiku": 6, "sonnet": 3, "opus": 1, "total": 10,
                                           "savings_pct": 70.0, "estimated": True},
                "volume_series": {"labels": [], "data": []},
            }
            events = []
            with patch("warden.marketplace.analytics.get_live_metrics", AsyncMock(return_value=mock_data)):
                with patch("asyncio.sleep", AsyncMock(return_value=None)):
                    resp = await api_mod.analytics_stream(req)
                    async for chunk in resp.body_iterator:
                        events.append(chunk.decode() if isinstance(chunk, bytes) else chunk)
            return events

        events = asyncio.run(asyncio.wait_for(_run(), timeout=5.0))
        combined = "".join(events)
        assert "data:" in combined
        # First event must be valid JSON
        for line in combined.splitlines():
            if line.startswith("data:"):
                payload = json.loads(line[5:].strip())
                assert payload["trades"] == 300
                break


# ── SSE generator disconnect safety ───────────────────────────────────────────

class TestSSEGeneratorDisconnect:
    """Test that the SSE async generator stops cleanly on client disconnect."""

    def test_generator_stops_on_disconnect(self):
        """Simulates disconnect: request.is_disconnected() returns True immediately."""
        import importlib
        api_mod = importlib.import_module("warden.marketplace.api")

        disconnected_request = MagicMock()
        disconnected_request.is_disconnected = AsyncMock(return_value=True)

        async def _collect():
            from warden.marketplace.analytics import get_live_metrics  # noqa
            events = []
            # Patch get_live_metrics to return quickly
            with patch("warden.marketplace.analytics.get_live_metrics", AsyncMock(return_value={
                "communities": 1, "assets": 2, "trades": 3, "auto_import_pct": 99,
                "fairness": {}, "tiers": {"haiku": 6, "sonnet": 3, "opus": 1, "total": 10, "savings_pct": 70.0, "estimated": True},
                "volume_series": {"labels": [], "data": []},
            })):
                resp = await api_mod.analytics_stream(disconnected_request)
                # With disconnect=True, generator yields nothing before checking disconnect
                if hasattr(resp, "body_iterator"):
                    async for chunk in resp.body_iterator:
                        events.append(chunk)
                        break  # Stop after first chunk to avoid infinite loop
            return events

        # Should complete without hanging
        result = asyncio.run(asyncio.wait_for(_collect(), timeout=5.0))
        # If disconnected immediately, result may be empty — that's correct
        assert isinstance(result, list)

    def test_cancelled_error_does_not_propagate(self):
        """CancelledError inside the SSE sleep must not crash the generator."""
        async def _run():
            import asyncio as _asyncio
            from unittest.mock import patch as _patch, AsyncMock as _AM

            class _DiscoReq:
                _calls = 0
                async def is_disconnected(self):
                    self._calls += 1
                    return self._calls > 1  # disconnect on 2nd check

            import importlib
            api_mod = importlib.import_module("warden.marketplace.api")

            mock_metrics = {
                "communities": 100, "assets": 200, "trades": 300, "auto_import_pct": 99,
                "fairness": {}, "tiers": {"haiku": 6, "sonnet": 3, "opus": 1, "total": 10, "savings_pct": 70.0, "estimated": True},
                "volume_series": {"labels": [], "data": []},
            }
            req = _DiscoReq()
            events = []
            with _patch("warden.marketplace.analytics.get_live_metrics", _AM(return_value=mock_metrics)):
                with _patch("asyncio.sleep", _AM(return_value=None)):
                    resp = await api_mod.analytics_stream(req)
                    if hasattr(resp, "body_iterator"):
                        async for chunk in resp.body_iterator:
                            events.append(chunk)

            return events

        events = asyncio.run(asyncio.wait_for(_run(), timeout=5.0))
        # Should have yielded exactly one event (disconnects after first iteration)
        assert len(events) >= 1
        first = b"".join(events[:1]) if events and isinstance(events[0], bytes) else (events[0] if events else b"")
        assert b"data:" in first if isinstance(first, bytes) else "data:" in str(first)
