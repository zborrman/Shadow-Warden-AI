"""
warden/tests/test_x402.py
Phase 4 — x402 Micropayment Protocol (4 tests).
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("VOICE_X402_DB_PATH", "/tmp/warden_test_x402.db")


class TestX402Protocol:
    def _fresh(self):
        from warden.voice.x402 import X402Protocol
        return X402Protocol()

    def test_402_returned_when_balance_insufficient(self):
        proto = self._fresh()
        exc   = proto.generate_402_response("asr_minute", 0.05, "0xDEAD")
        assert exc.status_code == 402
        assert exc.detail["amount_usd"] == 0.05
        assert "payment_uri" in exc.detail

    def test_payment_channel_creates_balance(self):
        proto = self._fresh()
        agent = f"agent_{uuid.uuid4().hex[:6]}"
        cid   = proto.create_payment_channel(agent, 10.0)
        assert cid  # non-empty channel ID
        bal = proto.get_balance(agent)
        assert bal == pytest.approx(10.0)

    def test_deduct_reduces_balance(self):
        proto = self._fresh()
        agent = f"agent_{uuid.uuid4().hex[:6]}"
        proto.create_payment_channel(agent, 5.0)
        ok    = proto.deduct(agent, 1.50, "asr_call")
        assert ok is True
        bal   = proto.get_balance(agent)
        assert bal == pytest.approx(3.5)

    def test_deduct_fails_when_insufficient(self):
        proto = self._fresh()
        agent = f"agent_{uuid.uuid4().hex[:6]}"
        proto.create_payment_channel(agent, 0.10)
        ok = proto.deduct(agent, 99.0, "premium_search")
        assert ok is False
        # Balance unchanged
        bal = proto.get_balance(agent)
        assert bal == pytest.approx(0.10)

    def test_payment_channel_lifecycle(self):
        """Open → deduct → close."""
        proto = self._fresh()
        agent = f"agent_{uuid.uuid4().hex[:6]}"
        cid   = proto.create_payment_channel(agent, 2.0)
        ok    = proto.deduct(agent, 0.5, "listing_search")
        assert ok is True
        closed = proto.close_channel(cid)
        assert closed is True
        # Balance still readable after close
        bal = proto.get_balance(agent)
        assert bal == pytest.approx(1.5)
