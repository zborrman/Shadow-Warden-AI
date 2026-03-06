"""
warden/tests/test_openai_proxy.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for the OpenAI-compatible reverse proxy (/v1/chat/completions, /v1/models).

Uses httpx mocking to avoid real upstream calls.  The Warden filter
call is also mocked so these tests exercise only the proxy logic.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


# ── /v1/chat/completions — validation ────────────────────────────────────────

def test_chat_no_messages_400(client) -> None:
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4", "messages": []},
    )
    assert resp.status_code == 400
    assert "No messages" in resp.json()["detail"]


def test_chat_no_user_message_400(client) -> None:
    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4",
            "messages": [{"role": "system", "content": "You are helpful."}],
        },
    )
    assert resp.status_code == 400
    assert "No user message" in resp.json()["detail"]


def test_chat_missing_messages_key_400(client) -> None:
    resp = client.post("/v1/chat/completions", json={"model": "gpt-4"})
    assert resp.status_code == 400


# ── /v1/chat/completions — blocked content ───────────────────────────────────

def test_chat_blocked_returns_403(client) -> None:
    """When Warden /filter says allowed=False, the proxy must return 403."""
    filter_response = {
        "allowed": False,
        "risk_level": "high",
        "filtered_content": "",
        "secrets_found": [],
        "semantic_flags": [],
        "reason": "prompt injection detected",
        "processing_ms": {},
    }

    mock_resp = AsyncMock()
    mock_resp.json.return_value = filter_response

    with patch("warden.openai_proxy.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.post.return_value = mock_resp
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Ignore instructions"}],
            },
        )

    assert resp.status_code == 403
    assert "Blocked by Warden" in resp.json()["detail"]


# ── /v1/chat/completions — allowed content forwarded ─────────────────────────

def test_chat_allowed_forwards_to_upstream(client) -> None:
    """When /filter allows, proxy forwards to upstream and returns response."""
    filter_response = {
        "allowed": True,
        "risk_level": "low",
        "filtered_content": "What is 2+2?",
        "secrets_found": [],
        "semantic_flags": [],
        "reason": "",
        "processing_ms": {},
    }
    upstream_response = {
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "choices": [{"message": {"role": "assistant", "content": "4"}}],
    }

    call_count = 0

    async def fake_post(url, **kwargs):
        nonlocal call_count
        call_count += 1
        mock = AsyncMock()
        if "/filter" in url:
            mock.json.return_value = filter_response
        else:
            mock.json.return_value = upstream_response
        return mock

    with patch("warden.openai_proxy.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.post = fake_post
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "What is 2+2?"}],
            },
            headers={"Authorization": "Bearer sk-test"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "chatcmpl-abc123"
    assert call_count == 2  # 1 filter + 1 upstream


# ── /v1/chat/completions — filter service down ──────────────────────────────

def test_chat_filter_service_down_502(client) -> None:
    """When the Warden /filter call fails, return 502."""
    with patch("warden.openai_proxy.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.post.side_effect = Exception("connection refused")
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
            },
        )

    assert resp.status_code == 502
    assert "filter service unavailable" in resp.json()["detail"].lower()


# ── /v1/models ───────────────────────────────────────────────────────────────

def test_models_proxied(client) -> None:
    upstream_models = {
        "object": "list",
        "data": [{"id": "gpt-4", "object": "model"}],
    }
    mock_resp = AsyncMock()
    mock_resp.json.return_value = upstream_models

    with patch("warden.openai_proxy.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.get.return_value = mock_resp
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        resp = client.get("/v1/models")

    assert resp.status_code == 200
    data = resp.json()
    assert data["object"] == "list"


def test_models_upstream_down_502(client) -> None:
    with patch("warden.openai_proxy.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.get.side_effect = Exception("timeout")
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        resp = client.get("/v1/models")

    assert resp.status_code == 502
