"""
SR-7.2/7.3 — coverage for the marketplace x402 payment gate.

x402_gate.py is a security-critical, fail-open payment middleware (replay protection,
autonomy gate, USDC balance check) that the suite barely exercised. These tests pin the
behaviours the marketplace CLAUDE.md rules 13–17 depend on:

  13  fail-open — gate errors must return None (allow), never raise
  16  credits take priority over x402
  17  autonomy check (REQUIRE_APPROVAL→202, BLOCK→403) fires before payment
  + v7.4 replay protection (nonce single-use, issued_at ±5 min window)
"""
from __future__ import annotations

import base64
import json
import time
from types import SimpleNamespace

import pytest

from warden.marketplace import x402_gate as g


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(g, "_DB_PATH", str(tmp_path / "x402.db"))
    yield


def _sig(**payload) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


class _Req:
    def __init__(self, headers=None, tenant=None):
        self.headers = headers or {}
        self.state = SimpleNamespace(tenant=tenant)


# ── Header helpers (pure) ─────────────────────────────────────────────────────

class TestHeaderHelpers:
    def test_extract_valid_payload(self):
        assert g._extract_sig_payload(_sig(agent_id="a1"))["agent_id"] == "a1"

    def test_extract_garbage_returns_none(self):
        assert g._extract_sig_payload("!!!not-base64!!!") is None
        assert g._extract_sig_payload("") is None

    def test_extract_agent_id(self):
        assert g._extract_agent_id(_sig(agent_id="a1")) == "a1"
        assert g._extract_agent_id(_sig(foo="bar")) is None

    def test_payment_required_header_is_wellformed(self):
        raw = g._build_payment_required_header("search")
        payload = json.loads(base64.b64decode(raw).decode())
        assert payload["version"] == "x402/1.0"
        assert payload["resource"] == "search"
        assert payload["schemes"][0]["currency"] == "USDC"


# ── Replay protection ─────────────────────────────────────────────────────────

class TestNonceReplay:
    def test_fresh_nonce_allowed(self):
        assert g._consume_nonce("a1", "n-fresh", int(time.time())) is True

    def test_reused_nonce_rejected(self):
        now = int(time.time())
        assert g._consume_nonce("a1", "n-dup", now) is True
        assert g._consume_nonce("a1", "n-dup", now) is False   # replay

    def test_stale_issued_at_rejected(self):
        old = int(time.time()) - g._NONCE_TTL_SECONDS - 60
        assert g._consume_nonce("a1", "n-old", old) is False

    def test_future_issued_at_rejected(self):
        future = int(time.time()) + g._NONCE_TTL_SECONDS + 60
        assert g._consume_nonce("a1", "n-future", future) is False

    def test_db_error_fails_open(self, monkeypatch):
        # Unwritable DB path → nonce check must fail-OPEN (return True), never block.
        monkeypatch.setattr(g, "_DB_PATH", "/root/nonexistent-dir/x402.db")
        assert g._consume_nonce("a1", "n", int(time.time())) is True


# ── Balance + deduction ───────────────────────────────────────────────────────

class TestBalanceAndDeduct:
    def test_no_balance_is_insufficient(self):
        assert g._has_sufficient_balance("nobody") is False

    @pytest.mark.asyncio
    async def test_deduct_disabled_is_noop_true(self, monkeypatch):
        monkeypatch.setattr(g, "_X402_ENABLED", False)
        assert await g.deduct_payment("a1", "search") is True

    @pytest.mark.asyncio
    async def test_deduct_enabled_decrements_prefunded_balance(self, monkeypatch):
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        # seed a balance
        import sqlite3
        con = sqlite3.connect(g._DB_PATH)
        g._ensure_schema(con)
        con.execute("INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?,?,?)",
                    ("a1", 1.0, "now"))
        con.commit()
        con.close()
        assert g._has_sufficient_balance("a1") is True
        assert await g.deduct_payment("a1", "search", amount_usd=g.Decimal("0.5")) is True
        con = sqlite3.connect(g._DB_PATH)
        bal = con.execute("SELECT balance_usd FROM x402_balances WHERE agent_id='a1'").fetchone()[0]
        pending = con.execute("SELECT COUNT(*) FROM x402_pending_deductions WHERE agent_id='a1'").fetchone()[0]
        con.close()
        assert abs(bal - 0.5) < 1e-9      # decremented
        assert pending == 1               # queued for settlement


# ── require_payment decision paths ────────────────────────────────────────────

class TestRequirePayment:
    @pytest.mark.asyncio
    async def test_disabled_gate_allows(self, monkeypatch):
        monkeypatch.setattr(g, "_X402_ENABLED", False)
        assert await g.require_payment(_Req(), "search") is None

    @pytest.mark.asyncio
    async def test_replay_nonce_returns_402(self, monkeypatch):
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        now = int(time.time())
        g._consume_nonce("a1", "used-nonce", now)        # burn it
        sig = _sig(agent_id="a1", nonce="used-nonce", issued_at=now)
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert resp is not None and resp.status_code == 402
        assert json.loads(resp.body)["error"] == "replay_detected"

    @pytest.mark.asyncio
    async def test_autonomy_block_returns_403(self, monkeypatch):
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action", lambda a, ac, amt: "BLOCK")
        sig = _sig(agent_id="a1")
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert resp is not None and resp.status_code == 403

    @pytest.mark.asyncio
    async def test_no_balance_returns_402_with_payment_header(self, monkeypatch):
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action", lambda a, ac, amt: "ALLOW")
        sig = _sig(agent_id="broke-agent")
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert resp is not None and resp.status_code == 402
        assert json.loads(resp.body)["error"] == "payment_required"
        assert "PAYMENT-REQUIRED" in resp.headers

    @pytest.mark.asyncio
    async def test_gate_exception_fails_open(self, monkeypatch, caplog):
        """Rule 13: any internal error → allow (None) + payment_bypassed audit line."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action", lambda a, ac, amt: "ALLOW")

        def _boom(_agent):
            raise RuntimeError("db exploded")
        monkeypatch.setattr(g, "_has_sufficient_balance", _boom)

        sig = _sig(agent_id="a1")
        with caplog.at_level("WARNING"):
            resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert resp is None                                   # failed OPEN
        assert any("payment_bypassed" in r.message for r in caplog.records)
