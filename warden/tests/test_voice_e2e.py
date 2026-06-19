"""
warden/tests/test_voice_e2e.py
End-to-end voice-commerce flow tests (A.3 — Workstream A).

Flow:
  1. Voice session created.
  2. Transcript → NLU → marketplace search intent.
  3. voice_search finds listings, returns speech.
  4. voice_buy triggers escrow creation.
  5. voice_portfolio confirms active escrow.
  6. Prometheus metrics incremented throughout.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")

# ── Fixtures ───────────────────────────────────────────────────────────────────

_MOCK_LISTINGS = {
    "listings": [
        {"listing_id": "L001", "title": "Temperature Sensor Pro", "price_usd": 29.99, "currency": "USD"},
        {"listing_id": "L002", "title": "Temp Sensor Basic",      "price_usd": 19.99, "currency": "USD"},
        {"listing_id": "L003", "title": "Industrial Temp Probe",  "price_usd": 44.99, "currency": "USD"},
    ]
}

_MOCK_ESCROW = {
    "escrow_id":  "ESC-abc123",
    "listing_id": "L002",
    "amount_usd": 19.99,
    "status":     "funded",
    "buyer_id":   "tenant-test",
}

_MOCK_PORTFOLIO = {
    "escrows": [_MOCK_ESCROW],
}


# ── Workstream A.3 Step 1 & 2: session create + NLU search ────────────────────

class TestVoiceSearchFlow:
    @pytest.mark.asyncio
    async def test_voice_search_returns_listings(self):
        """Transcript → NLU → search → speech response with listing results."""
        from warden.voice.agent import voice_search
        from warden.voice.nlu import VoiceIntent

        mock_intent = VoiceIntent(
            intent_type="search",
            entities={"product": "temperature sensors", "max_price": 50.0},
            confidence=0.92,
        )
        with (
            patch("warden.voice.agent._post", new_callable=AsyncMock) as mp,
            patch("warden.voice.nlu.parse_intent", new=AsyncMock(return_value=mock_intent)),
        ):
            mp.return_value = _MOCK_LISTINGS
            result = await voice_search(
                transcript="find temperature sensors under fifty dollars",
                community_id="test-community",
                tenant_id="tenant-test",
            )

        assert len(result["results"]) == 3
        assert "Found" in result["speech"]
        assert result["intent"] == "search"

    @pytest.mark.asyncio
    async def test_voice_search_empty_results_graceful(self):
        """Empty marketplace returns graceful speech response."""
        from warden.voice.agent import voice_search
        from warden.voice.nlu import VoiceIntent

        mock_intent = VoiceIntent(
            intent_type="search",
            entities={"product": "unobtanium"},
            confidence=0.88,
        )
        with (
            patch("warden.voice.agent._post", new_callable=AsyncMock) as mp,
            patch("warden.voice.nlu.parse_intent", new=AsyncMock(return_value=mock_intent)),
        ):
            mp.return_value = {"listings": []}
            result = await voice_search(transcript="unobtanium", tenant_id="tenant-test")

        assert result["results"] == []
        assert "0" in result["speech"] or "Found" in result["speech"]

    @pytest.mark.asyncio
    async def test_voice_search_http_error_fail_open(self):
        """HTTP error → graceful error speech (fail-open)."""
        import httpx

        from warden.voice.agent import voice_search
        from warden.voice.nlu import VoiceIntent

        with (
            patch("warden.voice.agent._post", side_effect=httpx.ConnectError("timeout")),
            patch("warden.voice.nlu.parse_intent", new=AsyncMock(return_value=VoiceIntent("search", {}, 0.5))),
        ):
            result = await voice_search(transcript="anything", tenant_id="tenant-test")

        assert "error" in result or "speech" in result
        assert result.get("speech")


# ── Step 3 & 4: voice_buy → escrow creation ───────────────────────────────────

class TestVoiceBuyFlow:
    @pytest.mark.asyncio
    async def test_voice_buy_creates_escrow(self):
        """voice_buy calls escrow endpoint and returns spoken confirmation."""
        from warden.voice.agent import voice_buy

        with patch("warden.voice.agent._post", new_callable=AsyncMock) as mp:
            mp.return_value = _MOCK_ESCROW
            result = await voice_buy(
                transcript="buy the second one",
                listing_id="L002",
                community_id="test-community",
                tenant_id="tenant-test",
            )

        assert isinstance(result, dict)
        assert result.get("escrow_id") or result.get("speech") or result.get("error") is not None

    @pytest.mark.asyncio
    async def test_voice_buy_no_listing_id_graceful(self):
        """voice_buy without listing_id returns graceful speech."""
        from warden.voice.agent import voice_buy

        with patch("warden.voice.agent._post", new_callable=AsyncMock) as mp:
            mp.return_value = {"error": "missing listing_id", "speech": "Please specify a listing."}
            result = await voice_buy(transcript="buy something", tenant_id="tenant-test")

        assert "speech" in result or "error" in result


# ── Step 5: voice_portfolio confirms active escrow ────────────────────────────

class TestVoicePortfolio:
    @pytest.mark.asyncio
    async def test_portfolio_returns_active_escrows(self):
        """voice_portfolio returns spoken summary of active escrows."""
        from warden.voice.agent import voice_portfolio

        with patch("warden.voice.agent._get", new_callable=AsyncMock) as mg:
            mg.return_value = _MOCK_PORTFOLIO
            result = await voice_portfolio(tenant_id="tenant-test")

        assert result["escrows"]
        assert "speech" in result
        assert "ESC-abc123"[:8] in result["speech"] or "active" in result["speech"].lower()

    @pytest.mark.asyncio
    async def test_portfolio_empty_graceful(self):
        """voice_portfolio with no escrows returns clean speech."""
        from warden.voice.agent import voice_portfolio

        with patch("warden.voice.agent._get", new_callable=AsyncMock) as mg:
            mg.return_value = {"escrows": []}
            result = await voice_portfolio(tenant_id="tenant-test")

        assert result["escrows"] == []
        assert "no active" in result["speech"].lower()

    @pytest.mark.asyncio
    async def test_portfolio_http_error_fail_open(self):
        """HTTP error in portfolio returns graceful speech."""
        import httpx

        from warden.voice.agent import voice_portfolio

        with patch("warden.voice.agent._get", side_effect=httpx.ConnectError("down")):
            result = await voice_portfolio(tenant_id="tenant-test")

        assert "speech" in result
        assert result.get("error")


# ── Step 6: Prometheus metrics incremented ────────────────────────────────────

class TestVoiceMetrics:
    def test_metrics_are_registered(self):
        """All required Prometheus metrics exist in voice/metrics.py."""
        from warden.voice import metrics as m

        assert hasattr(m, "VOICE_SESSION_DURATION")
        assert hasattr(m, "VOICE_LATENCY")
        assert hasattr(m, "VOICE_CONVERSIONS")
        assert hasattr(m, "VOICE_ERRORS")
        assert hasattr(m, "VOICE_ACTIVE_SESSIONS")

    def test_voice_errors_counter_labels(self):
        """VOICE_ERRORS counter accepts stage label."""
        from warden.voice.metrics import VOICE_ERRORS

        VOICE_ERRORS.labels(stage="asr").inc()
        VOICE_ERRORS.labels(stage="nlu").inc()
        VOICE_ERRORS.labels(stage="escrow").inc()

    def test_voice_conversions_increment(self):
        """VOICE_CONVERSIONS counter can be incremented."""
        from warden.voice.metrics import VOICE_CONVERSIONS
        before = VOICE_CONVERSIONS._value.get()
        VOICE_CONVERSIONS.inc()
        assert VOICE_CONVERSIONS._value.get() > before

    def test_voice_session_duration_observe(self):
        """VOICE_SESSION_DURATION histogram can be observed."""
        from warden.voice.metrics import VOICE_SESSION_DURATION
        VOICE_SESSION_DURATION.observe(45.3)

    def test_voice_latency_observe(self):
        """VOICE_LATENCY histogram can be observed."""
        from warden.voice.metrics import VOICE_LATENCY
        VOICE_LATENCY.observe(320)


# ── Tool registration check ───────────────────────────────────────────────────

class TestVoiceToolRegistry:
    def test_portfolio_tool_in_handlers(self):
        """voice_portfolio is registered in VOICE_TOOL_HANDLERS."""
        from warden.voice.agent import VOICE_TOOL_HANDLERS
        assert "voice_portfolio" in VOICE_TOOL_HANDLERS

    def test_portfolio_tool_in_schema(self):
        """voice_portfolio schema is in VOICE_TOOLS list."""
        from warden.voice.agent import VOICE_TOOLS
        names = [t["name"] for t in VOICE_TOOLS]
        assert "voice_portfolio" in names

    def test_all_handlers_are_callable(self):
        """Every registered tool handler is callable."""
        from warden.voice.agent import VOICE_TOOL_HANDLERS
        for name, fn in VOICE_TOOL_HANDLERS.items():
            assert callable(fn), f"{name} is not callable"
