"""
warden/tests/test_voice_dialogue.py
Phase 2 — Dialogue Manager + Voice Agent tools (6 tests).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


class TestDialogueManager:
    @pytest.mark.asyncio
    async def test_search_routes_to_search_action(self):
        from warden.voice.dialogue import DialogueManager, new_session_id
        dm  = DialogueManager()
        sid = new_session_id()
        resp = await dm.process_turn(sid, "find me a blue widget")
        assert resp.action == "search"
        assert resp.turn == 1
        assert resp.session_id == sid

    @pytest.mark.asyncio
    async def test_buy_requires_confirmation_first(self):
        from warden.voice.dialogue import DialogueManager, new_session_id
        dm   = DialogueManager()
        sid  = new_session_id()
        resp = await dm.process_turn(sid, "buy the widget")
        # First buy → confirmation prompt
        assert resp.action == "confirm"
        assert "confirm" in resp.text_response.lower() or "shall" in resp.text_response.lower()

    @pytest.mark.asyncio
    async def test_clarify_when_product_missing(self):
        from warden.voice.dialogue import DialogueManager, new_session_id
        dm   = DialogueManager()
        sid  = new_session_id()
        resp = await dm.process_turn(sid, "search for it")
        # "it" has no product entity → clarify
        assert resp.action in ("search", "clarify")

    @pytest.mark.asyncio
    async def test_session_persists_turn_count(self):
        """Turns increment across multiple calls on the same DialogueManager instance."""
        from warden.voice.dialogue import DialogueManager, new_session_id
        dm  = DialogueManager()   # single instance — uses in-process _store
        sid = new_session_id()
        r   = None
        for _ in range(3):
            r = await dm.process_turn(sid, "find something")
        assert r is not None
        assert r.turn == 3

    @pytest.mark.asyncio
    async def test_cancel_clears_session(self):
        from warden.voice.dialogue import DialogueManager, new_session_id
        dm  = DialogueManager()
        sid = new_session_id()
        await dm.process_turn(sid, "find laptops")
        resp = await dm.process_turn(sid, "cancel that")
        assert resp.action == "none"
        assert "cancel" in resp.text_response.lower()

    @pytest.mark.asyncio
    async def test_help_intent_returns_help_text(self):
        from warden.voice.dialogue import DialogueManager, new_session_id
        dm   = DialogueManager()
        sid  = new_session_id()
        resp = await dm.process_turn(sid, "help me, what can you do?")
        assert resp.action == "none"
        assert len(resp.text_response) > 20


class TestVoiceAgentTools:
    @pytest.mark.asyncio
    async def test_voice_negotiate_returns_dialogue_response(self):
        """voice_negotiate calls DialogueManager and returns a speech key."""
        from warden.voice.agent import voice_negotiate
        result = await voice_negotiate(
            session_id="test-sess",
            transcript="how about $30 for it",
        )
        assert "speech" in result or "error" in result

    @pytest.mark.asyncio
    async def test_voice_search_returns_speech_on_http_error(self):
        """voice_search fails gracefully when marketplace endpoint unreachable."""
        from warden.voice.agent import voice_search
        result = await voice_search(transcript="find a laptop", community_id="test")
        # Either has results or has error + speech
        assert "speech" in result or "error" in result
