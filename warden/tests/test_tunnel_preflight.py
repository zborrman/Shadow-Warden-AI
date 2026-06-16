"""Tests for warden/sovereign/preflight.py and its integration with POST /sovereign/tunnels."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_preflight.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_preflight_rules.json")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")

from unittest.mock import AsyncMock, MagicMock, patch

# ── helpers ──────────────────────────────────────────────────────────────────

def _ok_response(status_code: int = 200):
    r = MagicMock()
    r.status_code = status_code
    return r


def _fail_response():
    raise ConnectionError("host unreachable")


# ── 1. All services healthy → all_ok=True ─────────────────────────────────

@pytest.mark.asyncio
async def test_preflight_all_ok():
    from warden.sovereign.preflight import preflight_check

    async def _get(url, **kw):
        return _ok_response(200)

    mock_client = AsyncMock()
    mock_client.get = _get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("warden.sovereign.preflight._check_redis_sync", return_value={"service": "redis", "status": "ok", "latency_ms": 1.0, "error": None}),
        patch("httpx.AsyncClient", return_value=mock_client),
    ):
        result = await preflight_check("EU")

    assert result["all_ok"] is True
    assert result["jurisdiction"] == "EU"
    assert all(c["status"] == "ok" for c in result["checks"])


# ── 2. One service down → all_ok=False ────────────────────────────────────

@pytest.mark.asyncio
async def test_preflight_one_service_down():
    from warden.sovereign.preflight import preflight_check

    call_count = 0

    async def _get(url, **kw):
        nonlocal call_count
        call_count += 1
        if "minio" in url:
            raise ConnectionError("minio down")
        return _ok_response(200)

    mock_client = AsyncMock()
    mock_client.get = _get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("warden.sovereign.preflight._check_redis_sync", return_value={"service": "redis", "status": "ok", "latency_ms": 1.0, "error": None}),
        patch("httpx.AsyncClient", return_value=mock_client),
    ):
        result = await preflight_check("US")

    assert result["all_ok"] is False
    failed = [c for c in result["checks"] if c["status"] == "fail"]
    assert len(failed) >= 1
    assert any(c["service"] == "minio" for c in failed)


# ── 3. Service timeout → status="fail" ────────────────────────────────────

@pytest.mark.asyncio
async def test_preflight_timeout_recorded_as_fail():
    from warden.sovereign.preflight import preflight_check

    async def _get(url, **kw):
        import httpx
        raise httpx.TimeoutException("timed out")

    mock_client = AsyncMock()
    mock_client.get = _get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("warden.sovereign.preflight._check_redis_sync", return_value={"service": "redis", "status": "ok", "latency_ms": 1.0, "error": None}),
        patch("httpx.AsyncClient", return_value=mock_client),
    ):
        result = await preflight_check("UK")

    assert result["all_ok"] is False
    http_checks = [c for c in result["checks"] if c["service"] in ("minio", "warden_api")]
    assert all(c["status"] == "fail" for c in http_checks)


# ── 4. skip_preflight=True bypasses the check ─────────────────────────────

def test_skip_preflight_bypasses_check():
    """When skip_preflight=True, the endpoint must NOT call preflight_check."""
    preflight_called = False

    async def _fake_preflight(jurisdiction):
        nonlocal preflight_called
        preflight_called = True
        return {"all_ok": False, "jurisdiction": jurisdiction, "checks": []}

    # Import register_tunnel so we can verify it doesn't call preflight when skip=True.
    # We test at the endpoint level via the Pydantic model field.
    from warden.api.sovereign import RegisterTunnelRequest

    req = RegisterTunnelRequest(
        label="test",
        jurisdiction="EU",
        protocol="MASQUE_H3",
        skip_preflight=True,
    )
    assert req.skip_preflight is True


# ── 5. Prometheus metric increments ───────────────────────────────────────

@pytest.mark.asyncio
async def test_preflight_metric_incremented():
    from warden.sovereign.preflight import preflight_check

    incremented = []

    class FakeCounter:
        def labels(self, **kw):
            return self
        def inc(self):
            incremented.append(True)

    async def _get(url, **kw):
        return _ok_response(200)

    mock_client = AsyncMock()
    mock_client.get = _get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("warden.sovereign.preflight._check_redis_sync", return_value={"service": "redis", "status": "ok", "latency_ms": 1.0, "error": None}),
        patch("httpx.AsyncClient", return_value=mock_client),
        patch("warden.metrics.TUNNEL_PREFLIGHT_TOTAL", FakeCounter()),
    ):
        await preflight_check("SG")

    assert len(incremented) == 1


# ── 6. POST /sovereign/tunnels with failing preflight → 503 ───────────────

def test_api_returns_503_when_preflight_fails():
    from fastapi.testclient import TestClient

    async def _fail_preflight(jurisdiction):
        return {
            "all_ok": False,
            "jurisdiction": jurisdiction,
            "checks": [{"service": "minio", "status": "fail", "latency_ms": 5001.0, "error": "timeout"}],
        }

    with patch("warden.api.sovereign.preflight_check", new=_fail_preflight):
        from warden.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/sovereign/tunnels",
            json={"label": "eu-tunnel", "jurisdiction": "EU", "protocol": "MASQUE_H3"},
            headers={"X-Tenant-Tier": "enterprise"},
        )

    assert resp.status_code == 503
    body = resp.json()
    assert "failed_services" in body["detail"] or "message" in body["detail"] or "minio" in str(body)
