"""
Phase 6 — GSAM ingest health endpoint (GET /gsam/health).

The GSAM collector is fail-OPEN toward ClickHouse: when the OLAP store is down it
spools observations to NDJSON and replays them later. That is correct behaviour but
it fails *silently*, so ClickHouse being "on" in prod is unverifiable without a
health signal. These tests pin the degraded-detection logic.
"""
from __future__ import annotations

from unittest import mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.gsam.api import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _stats(**over):
    base = {
        "queue_depth": 0,
        "queue_max": 10000,
        "dropped": 0,
        "flushed": 12,
        "spool_bytes": 0,
        "clickhouse_enabled": True,
        "clickhouse_reachable": True,
    }
    base.update(over)
    return base


class TestHealth:
    def test_healthy_when_clickhouse_reachable_and_no_spool(self, client):
        with mock.patch("warden.gsam.collector.stats", return_value=_stats()):
            r = client.get("/gsam/health")
        assert r.status_code == 200
        body = r.json()
        assert body["clickhouse_enabled"] is True
        assert body["clickhouse_reachable"] is True
        assert body["degraded"] is False

    def test_degraded_when_enabled_but_unreachable(self, client):
        with mock.patch(
            "warden.gsam.collector.stats",
            return_value=_stats(clickhouse_reachable=False),
        ):
            r = client.get("/gsam/health")
        assert r.json()["degraded"] is True

    def test_degraded_when_spool_has_backlog(self, client):
        """The silent-failure case: CH looks reachable but a backlog is draining."""
        with mock.patch(
            "warden.gsam.collector.stats",
            return_value=_stats(spool_bytes=4096),
        ):
            r = client.get("/gsam/health")
        assert r.json()["degraded"] is True

    def test_degraded_when_observations_dropped(self, client):
        with mock.patch("warden.gsam.collector.stats", return_value=_stats(dropped=3)):
            r = client.get("/gsam/health")
        assert r.json()["degraded"] is True

    def test_not_degraded_when_clickhouse_disabled_and_clean(self, client):
        """CH off by config is a deliberate state, not a degradation."""
        with mock.patch(
            "warden.gsam.collector.stats",
            return_value=_stats(clickhouse_enabled=False, clickhouse_reachable=False),
        ):
            r = client.get("/gsam/health")
        assert r.json()["degraded"] is False

    def test_exposes_backpressure_fields(self, client):
        with mock.patch("warden.gsam.collector.stats", return_value=_stats(queue_depth=7)):
            body = client.get("/gsam/health").json()
        for k in ("queue_depth", "queue_max", "dropped", "flushed", "spool_bytes"):
            assert k in body
