"""Tests for EscrowDeploymentError and _check_rpc_with_retry in EscrowService."""
from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_escrow_rpc.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_escrow_rpc_rules.json")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")
os.environ.setdefault("MARKETPLACE_DB_PATH", "/tmp/warden_test_escrow_rpc.db")


def _make_web3_stub(connected: bool):
    """Return a fake web3 module where Web3.HTTPProvider + is_connected() is mocked."""
    mock_w3 = MagicMock()
    mock_w3.is_connected.return_value = connected

    mock_web3_cls = MagicMock(return_value=mock_w3)
    mock_web3_cls.HTTPProvider = MagicMock(return_value="http-provider")

    fake_web3 = types.ModuleType("web3")
    fake_web3.Web3 = mock_web3_cls  # type: ignore[attr-defined]
    return fake_web3, mock_w3


def _chain_cfg_with_rpc(rpc_url: str = "http://localhost:8545"):
    """Return a minimal chain config dict with an RPC URL."""
    return {"rpc_url": rpc_url, "chain_id": 11155111}


def _chain_cfg_no_rpc():
    return {"rpc_url": "", "chain_id": 0}


# ── 1. Connected → returns True, deploy proceeds ──────────────────────────

def test_rpc_check_connected_returns_true():
    from warden.marketplace.escrow import EscrowService

    fake_web3, mock_w3 = _make_web3_stub(connected=True)

    with (
        patch.dict(sys.modules, {"web3": fake_web3}),
        patch("warden.marketplace.escrow.EscrowService._check_rpc_with_retry", wraps=None) as _,
        patch("warden.web3.chains.get_chain", return_value=_chain_cfg_with_rpc()),
    ):
        svc = EscrowService()
        # Patch web3 at import site inside the method
        with patch.dict(sys.modules, {"web3": fake_web3, "warden.web3.chains": types.SimpleNamespace(get_chain=lambda c: _chain_cfg_with_rpc())}):
            result = svc._check_rpc_with_retry("sepolia", max_retries=1)

    assert result is True


# ── 2. is_connected() → False → EscrowDeploymentError raised ─────────────

def test_rpc_check_disconnected_raises():
    from warden.marketplace.escrow import EscrowDeploymentError, EscrowService

    fake_web3, mock_w3 = _make_web3_stub(connected=False)

    with patch.dict(sys.modules, {"web3": fake_web3}):
        svc = EscrowService()

        def _get_chain(chain):
            return _chain_cfg_with_rpc()

        with (
            patch("warden.web3.chains.get_chain", side_effect=_get_chain),
            patch("time.sleep"),  # skip real delays
            pytest.raises(EscrowDeploymentError, match="not reachable"),
        ):
            svc._check_rpc_with_retry("sepolia", max_retries=2)


# ── 3. First attempt fails, second succeeds ────────────────────────────────

def test_rpc_check_retry_succeeds_on_second_attempt():
    from warden.marketplace.escrow import EscrowService

    call_count = 0

    class _FakeW3:
        def is_connected(self):
            nonlocal call_count
            call_count += 1
            return call_count >= 2  # False on first call, True on second

    mock_web3_cls = MagicMock(return_value=_FakeW3())
    mock_web3_cls.HTTPProvider = MagicMock(return_value="http-provider")
    fake_web3 = types.ModuleType("web3")
    fake_web3.Web3 = mock_web3_cls  # type: ignore[attr-defined]

    with patch.dict(sys.modules, {"web3": fake_web3}):
        svc = EscrowService()

        with (
            patch("warden.web3.chains.get_chain", return_value=_chain_cfg_with_rpc()),
            patch("time.sleep"),  # skip real delays
        ):
            result = svc._check_rpc_with_retry("sepolia", max_retries=3)

    assert result is True
    assert call_count == 2


# ── 4. API endpoint returns 502 when network unavailable ──────────────────

def test_api_endpoint_returns_502_on_deployment_error():
    from fastapi.testclient import TestClient

    from warden.marketplace.escrow import EscrowDeploymentError

    def _raise(*a, **kw):
        raise EscrowDeploymentError("RPC node offline")

    with patch("warden.marketplace.escrow.EscrowService.create_escrow", side_effect=_raise):
        from warden.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/marketplace/escrow",
            json={
                "listing_id": "LST-abc",
                "buyer_agent_id": "did:shadow:buyer",
                "seller_agent_id": "did:shadow:seller",
                "amount_usd": 10.0,
                "chain": "sepolia",
            },
        )

    assert resp.status_code == 502
    body = resp.json()
    assert "Blockchain" in str(body) or "unavailable" in str(body) or "502" in str(resp.status_code)
