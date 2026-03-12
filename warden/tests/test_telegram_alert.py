"""
warden/tests/test_telegram_alert.py
─────────────────────────────────────
Unit tests for telegram_alert — Telegram Bot notification channel.
All network I/O is mocked; no real Telegram token required.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import warden.telegram_alert as tg

# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_http_ok():
    """Return a mock httpx response with status 200."""
    resp = MagicMock()
    resp.status_code = 200
    return resp


def _mock_http_err(code: int = 400):
    resp = MagicMock()
    resp.status_code = code
    resp.text = "Bad Request"
    return resp


# ── is_enabled ────────────────────────────────────────────────────────────────

class TestIsEnabled:
    def test_disabled_without_token(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "")
        assert tg.is_enabled() is False

    def test_enabled_with_token(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "fake:token")
        assert tg.is_enabled() is True


# ── _send ──────────────────────────────────────────────────────────────────────

class TestSend:
    @pytest.mark.asyncio
    async def test_returns_false_without_token(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "")
        result = await tg._send("-123", "hello")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_without_chat_id(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        result = await tg._send("", "hello")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_on_http_200(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok:123")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_http_ok())

        with patch("warden.telegram_alert.httpx.AsyncClient", return_value=mock_client):
            result = await tg._send("-999", "test message")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_http_error(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok:123")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_http_err(400))

        with patch("warden.telegram_alert.httpx.AsyncClient", return_value=mock_client):
            result = await tg._send("-999", "test message")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_network_exception(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok:123")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=Exception("connection refused"))

        with patch("warden.telegram_alert.httpx.AsyncClient", return_value=mock_client):
            result = await tg._send("-999", "test message")
        assert result is False


# ── send_block_alert ──────────────────────────────────────────────────────────

class TestSendBlockAlert:
    @pytest.mark.asyncio
    async def test_no_op_when_disabled(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "")
        # Should complete without calling _send
        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_block_alert(
                tenant_id="t1", risk_level="block", attack_type="INJECTION"
            )
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_op_below_threshold(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_THRESHOLD", 2)   # high=2, so medium=1 is skipped

        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_block_alert(
                tenant_id="t1", risk_level="medium", attack_type="PII"
            )
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_sends_to_tenant_chat(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "")
        monkeypatch.setattr(tg, "_THRESHOLD", 2)

        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_block_alert(
                tenant_id="acme",
                risk_level="block",
                attack_type="INJECTION",
                tenant_chat_id="-100111",
            )
            assert mock_send.call_count == 1
            assert mock_send.call_args[0][0] == "-100111"

    @pytest.mark.asyncio
    async def test_sends_to_global_chat_when_no_tenant_chat(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "-GLOBAL")
        monkeypatch.setattr(tg, "_THRESHOLD", 2)

        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_block_alert(
                tenant_id="acme",
                risk_level="block",
                attack_type="INJECTION",
                tenant_chat_id=None,
            )
            assert mock_send.call_count == 1
            assert mock_send.call_args[0][0] == "-GLOBAL"

    @pytest.mark.asyncio
    async def test_sends_to_both_chats_when_different(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "-GLOBAL")
        monkeypatch.setattr(tg, "_THRESHOLD", 2)

        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_block_alert(
                tenant_id="acme",
                risk_level="block",
                attack_type="INJECTION",
                tenant_chat_id="-TENANT",
            )
            assert mock_send.call_count == 2

    @pytest.mark.asyncio
    async def test_no_duplicate_when_same_chat(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "-SAME")
        monkeypatch.setattr(tg, "_THRESHOLD", 2)

        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_block_alert(
                tenant_id="acme",
                risk_level="block",
                attack_type="INJECTION",
                tenant_chat_id="-SAME",
            )
            assert mock_send.call_count == 1


# ── send_quota_warning ────────────────────────────────────────────────────────

class TestSendQuotaWarning:
    @pytest.mark.asyncio
    async def test_no_op_when_disabled(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "")
        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_quota_warning(
                tenant_id="t1", used_usd=5.0, quota_usd=10.0
            )
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_fires_when_enabled(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "-MSP")
        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_quota_warning(
                tenant_id="t1", used_usd=8.5, quota_usd=10.0
            )
            assert mock_send.call_count >= 1
            text = mock_send.call_args_list[0][0][1]
            assert "85%" in text or "85" in text


# ── send_daily_digest ─────────────────────────────────────────────────────────

class TestSendDailyDigest:
    @pytest.mark.asyncio
    async def test_no_op_without_chat_id(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_daily_digest(
                tenant_id="t1", requests=100, blocked=5, cost_usd=0.01
            )
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_sends_to_tenant_only(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "-GLOBAL")
        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_daily_digest(
                tenant_id="t1",
                requests=100,
                blocked=5,
                cost_usd=0.01,
                tenant_chat_id="-TENANT",
            )
            # Only sent to tenant chat, not global
            assert mock_send.call_count == 1
            assert mock_send.call_args[0][0] == "-TENANT"

    @pytest.mark.asyncio
    async def test_digest_contains_key_metrics(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok")
        monkeypatch.setattr(tg, "_GLOBAL_CHAT", "")
        with patch.object(tg, "_send", new_callable=AsyncMock) as mock_send:
            await tg.send_daily_digest(
                tenant_id="acme",
                requests=200,
                blocked=10,
                cost_usd=0.025,
                top_attack="PROMPT_INJECTION",
                tenant_chat_id="-111",
            )
            text = mock_send.call_args[0][1]
            assert "200" in text
            assert "10" in text
            assert "PROMPT_INJECTION" in text


# ── send_test_message ─────────────────────────────────────────────────────────

class TestSendTestMessage:
    @pytest.mark.asyncio
    async def test_returns_false_without_token(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "")
        result = await tg.send_test_message("-111")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, monkeypatch) -> None:
        monkeypatch.setattr(tg, "_BOT_TOKEN", "tok:123")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_http_ok())

        with patch("warden.telegram_alert.httpx.AsyncClient", return_value=mock_client):
            result = await tg.send_test_message("-222")
        assert result is True
