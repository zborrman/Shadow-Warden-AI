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

    def test_payment_required_header_pins_scheme_fields(self):
        """Only currency/resource were pinned before -- amount, scheme, network,
        and payment_address could each drift or be dropped undetected."""
        raw = g._build_payment_required_header("search")
        payload = json.loads(base64.b64decode(raw).decode())
        scheme = payload["schemes"][0]
        assert scheme["scheme"] == "usdc"
        assert scheme["amount"] == str(g._SEARCH_FEE_USD)
        assert scheme["network"] == "polygon-amoy"
        assert scheme["payment_address"] == g._PAYMENT_ADDR


class TestGetTenantId:
    """_get_tenant_id had zero direct coverage -- only exercised incidentally
    through require_payment, which never inspects its return value."""

    def test_dict_tenant_with_tenant_id_key(self):
        req = _Req(tenant={"tenant_id": "t-1"})
        assert g._get_tenant_id(req) == "t-1"

    def test_dict_tenant_falls_back_to_id_key(self):
        req = _Req(tenant={"id": "t-2"})
        assert g._get_tenant_id(req) == "t-2"

    def test_tenant_id_key_wins_over_id_key(self):
        req = _Req(tenant={"tenant_id": "t-1", "id": "t-2"})
        assert g._get_tenant_id(req) == "t-1"

    def test_non_dict_tenant_falls_back_to_header(self):
        req = _Req(tenant="not-a-dict", headers={"X-Tenant-ID": "t-header"})
        assert g._get_tenant_id(req) == "t-header"

    def test_no_tenant_no_header_returns_unknown(self):
        req = _Req()
        assert g._get_tenant_id(req) == "unknown"

    def test_empty_dict_tenant_never_consults_header(self):
        """The dict branch resolves entirely from the dict itself -- an empty
        dict returns 'unknown' rather than falling through to X-Tenant-ID.
        Only a non-dict `tenant` takes the header path (see the test above)."""
        req = _Req(tenant={}, headers={"X-Tenant-ID": "t-header"})
        assert g._get_tenant_id(req) == "unknown"


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

        from warden.db.ddl_registry import ensure_schema
        con = sqlite3.connect(g._DB_PATH)
        ensure_schema(con, "marketplace_x402", g._DB_PATH)
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

    @pytest.mark.asyncio
    async def test_deduct_default_amount_is_search_fee(self, monkeypatch):
        """amount_usd=None must fall back to _SEARCH_FEE_USD, not 0 or None --
        the ternary on line ~289 had no test pinning the default branch."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        import sqlite3

        from warden.db.ddl_registry import ensure_schema
        con = sqlite3.connect(g._DB_PATH)
        ensure_schema(con, "marketplace_x402", g._DB_PATH)
        con.execute("INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?,?,?)",
                    ("a2", 1.0, "now"))
        con.commit()
        con.close()
        assert await g.deduct_payment("a2", "search") is True   # no amount_usd
        con = sqlite3.connect(g._DB_PATH)
        amount = con.execute(
            "SELECT amount_usd FROM x402_pending_deductions WHERE agent_id='a2'"
        ).fetchone()[0]
        con.close()
        assert abs(amount - float(g._SEARCH_FEE_USD)) < 1e-12

    @pytest.mark.asyncio
    async def test_deduct_fails_open_on_db_error(self, monkeypatch):
        """The bare except-return-True path in deduct_payment had zero coverage
        -- unlike require_payment's exception path, which is pinned below."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr(g, "_DB_PATH", "/root/nonexistent-dir/x402.db")
        assert await g.deduct_payment("a1", "search") is True


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
    async def test_credits_fast_path_allows_and_deducts(self, monkeypatch):
        """Rule 16 (credits take priority) was only ever asserted by mocking
        credits.get_balance to 0 in every OTHER test -- the >=1 success branch
        that actually deducts and returns None was never exercised through
        require_payment itself. A mutant flipping `>= 1` to `> 1` or `>= 2`
        would have survived undetected."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        deducted = []
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 1)
        monkeypatch.setattr("warden.marketplace.credits.deduct_credits",
                             lambda t, n=1: deducted.append((t, n)) or True)
        req = _Req(tenant={"tenant_id": "t-credits"})
        resp = await g.require_payment(req, "search")
        assert resp is None                       # allowed, no 402/403/202
        assert deducted == [("t-credits", 1)]      # exactly one credit spent

    @pytest.mark.asyncio
    async def test_autonomy_require_approval_returns_202_with_header(self, monkeypatch):
        """The BLOCK branch was tested; REQUIRE_APPROVAL (202 + the
        X-Requires-Approval header the caller keys UI behaviour off of) had
        zero coverage through require_payment."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: "REQUIRE_APPROVAL")
        sig = _sig(agent_id="a1")
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert resp is not None and resp.status_code == 202
        assert resp.headers["X-Requires-Approval"] == "pending"
        assert json.loads(resp.body)["status"] == "pending_approval"

    @pytest.mark.asyncio
    async def test_old_client_without_nonce_skips_replay_check(self, monkeypatch):
        """v7.4 docs promise old clients (no nonce/issued_at) are let through
        with only a debug log -- nothing asserted that the else-branch of
        `if nonce and issued_at is not None` actually reaches the rest of the
        gate instead of being silently rejected."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: "ALLOW")
        sig = _sig(agent_id="old-client")   # no nonce, no issued_at
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        # Reaches the balance check (402, not 402 replay_detected) -- proves it
        # was NOT rejected by the replay path.
        assert resp is not None and resp.status_code == 402
        assert json.loads(resp.body)["error"] == "payment_required"

    @pytest.mark.asyncio
    async def test_no_signature_header_reaches_balance_check(self, monkeypatch):
        """agent_id is None (no PAYMENT-SIGNATURE at all) must still resolve
        via the `agent_id is None or not _has_sufficient_balance(...)` OR --
        short-circuiting on the left operand was never distinguished from
        evaluating the right operand and getting the same answer."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        resp = await g.require_payment(_Req(), "search")
        assert resp is not None and resp.status_code == 402
        assert json.loads(resp.body)["error"] == "payment_required"

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


# ── Argument-propagation into gated dependencies (SR-7.3 mutation-testing gap) ─
#
# require_payment/deduct_payment carry 136 of x402_gate.py's 193 surviving
# mutants. Almost every existing test mocks check_action/get_balance/
# _has_sufficient_balance with a lambda that ignores its arguments -- so a
# mutant that corrupts WHICH agent_id, resource, or amount reaches those
# calls (swap for None, wrong dict key, wrong default) still returns the
# same status code and survives. These tests spy on the call arguments
# instead of just the outcome, closing the two functions that gate real
# search access and real money movement.
#
# Scope: the argument-propagation and gating-logic mutants specifically.
# Left out: ~110 survivors that are SQL-keyword casing (SQLite is
# case-insensitive to keywords) or log-message/JSON-key wording -- lower
# value, and each would need its own targeted assertion for one string
# literal. Documented, not attempted here.

class TestArgumentPropagation:
    @pytest.mark.asyncio
    async def test_agent_id_extracted_exactly_from_signature(self, monkeypatch):
        """Pins the whole `str(sig_payload.get("agent_id", "")) or None`
        expression against corruption of its key, default, or the str()
        wrapper -- any of which would still often be truthy and non-empty,
        so only an exact-value spy catches it."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        calls = []
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: calls.append(a) or "ALLOW")
        sig = _sig(agent_id="agent-distinctive-777")
        await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert calls == ["agent-distinctive-777"]

    @pytest.mark.asyncio
    async def test_missing_agent_id_key_never_reaches_autonomy_check(self, monkeypatch):
        """A signature payload with no "agent_id" key must resolve to
        agent_id=None -- which is falsy, so `if agent_id:` must skip the
        autonomy gate entirely. A mutant that made the resolved value
        truthy-but-wrong (e.g. the literal string "None" from a wrapped
        str(None), or a "XXXX" default) would wrongly enter this branch."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        calls = []
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: calls.append(a) or "ALLOW")
        sig = _sig(other_field="no-agent-id-here")
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert calls == []
        assert resp is not None and resp.status_code == 402   # falls through to balance check

    @pytest.mark.asyncio
    async def test_missing_agent_id_never_reaches_replay_check(self, monkeypatch):
        """Kills the `if sig_payload and agent_id:` -> `or` mutant: a
        signature with nonce+issued_at but no agent_id must never reach
        _consume_nonce, since sig_payload alone is truthy and would pass
        an `or`."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        calls = []
        monkeypatch.setattr(g, "_consume_nonce", lambda a, n, i: calls.append(a) or True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        now = int(time.time())
        sig = _sig(nonce="n-1", issued_at=now)   # no agent_id
        await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert calls == []

    @pytest.mark.asyncio
    async def test_nonce_without_issued_at_does_not_silently_bypass(self, monkeypatch):
        """Kills the `if nonce and issued_at is not None:` -> `or` mutant.
        Correct code: nonce present but issued_at missing takes the "old
        client" else-branch and proceeds to the normal balance gate (402).
        Under the `or` mutant, `nonce` alone is truthy, so it tries
        _consume_nonce(agent_id, nonce, int(None)) -- int(None) raises
        TypeError, which the OUTER except swallows and fails open (returns
        None, allowed) -- silently bypassing payment instead of gating it."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: "ALLOW")
        sig = _sig(agent_id="a1", nonce="n-no-issued-at")   # no issued_at key
        resp = await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert resp is not None and resp.status_code == 402
        assert json.loads(resp.body)["error"] == "payment_required"

    @pytest.mark.asyncio
    async def test_credits_balance_checked_for_correct_tenant(self, monkeypatch):
        """get_balance(tenant_id) -> get_balance(None) would still return a
        falsy/zero balance for most fakes and survive on status code alone."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        calls = []
        monkeypatch.setattr("warden.marketplace.credits.get_balance",
                             lambda t: calls.append(t) or 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: "ALLOW")
        req = _Req(tenant={"tenant_id": "t-distinctive"})
        await g.require_payment(req, "search")
        assert calls == ["t-distinctive"]

    @pytest.mark.asyncio
    async def test_autonomy_check_receives_correct_agent_action_and_amount(self, monkeypatch):
        """Pins all three check_action(agent_id, "search", float(fee))
        arguments against corruption in one call -- a wrong action string
        or amount would still commonly resolve to ALLOW/BLOCK the same way
        under most fakes, so only an exact-args spy catches it."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        calls = []
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: calls.append((a, ac, amt)) or "ALLOW")
        sig = _sig(agent_id="a1")
        await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert calls == [("a1", "search", float(g._SEARCH_FEE_USD))]

    @pytest.mark.asyncio
    async def test_balance_check_receives_correct_agent_id(self, monkeypatch):
        """`agent_id is None or not _has_sufficient_balance(agent_id)` ->
        `_has_sufficient_balance(None)` would still return False (no
        balance seeded for None) and survive on status code alone."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: "ALLOW")
        calls = []
        monkeypatch.setattr(g, "_has_sufficient_balance", lambda a: calls.append(a) or False)
        sig = _sig(agent_id="agent-needs-funds")
        await g.require_payment(_Req(headers={"PAYMENT-SIGNATURE": sig}), "search")
        assert calls == ["agent-needs-funds"]

    @pytest.mark.asyncio
    async def test_payment_required_header_carries_the_real_resource(self, monkeypatch):
        """_build_payment_required_header(resource) -> (None) would still
        return a well-formed header and a 402 -- only the embedded resource
        field would be wrong."""
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        monkeypatch.setattr("warden.marketplace.credits.get_balance", lambda t: 0)
        monkeypatch.setattr("warden.marketplace.autonomy.check_action",
                             lambda a, ac, amt: "ALLOW")
        resp = await g.require_payment(_Req(), "premium-search-v2")
        assert resp is not None
        header = json.loads(base64.b64decode(resp.headers["PAYMENT-REQUIRED"]).decode())
        assert header["resource"] == "premium-search-v2"


class TestDeductPaymentIntegrity:
    @pytest.mark.asyncio
    async def test_deduction_id_is_a_fresh_uuid_not_a_literal(self, monkeypatch):
        """str(uuid.uuid4()) -> str(None) would insert the literal string
        "None" as deduction_id (PRIMARY KEY) -- a second call for a
        different agent would then raise IntegrityError, get swallowed by
        the outer except, and silently skip both the deduction row and the
        balance decrement for that second call."""
        import sqlite3
        import uuid as uuid_mod

        from warden.db.ddl_registry import ensure_schema
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        con = sqlite3.connect(g._DB_PATH)
        ensure_schema(con, "marketplace_x402", g._DB_PATH)
        con.execute("INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?,?,?)",
                    ("a1", 1.0, "now"))
        con.commit()
        con.close()

        assert await g.deduct_payment("a1", "search", amount_usd=g.Decimal("0.1")) is True
        con = sqlite3.connect(g._DB_PATH)
        did = con.execute(
            "SELECT deduction_id FROM x402_pending_deductions WHERE agent_id='a1'"
        ).fetchone()[0]
        con.close()
        assert uuid_mod.UUID(did).version == 4   # raises ValueError on "None" or any non-UUID

    @pytest.mark.asyncio
    async def test_billing_audit_receives_correct_fields(self, monkeypatch):
        """Pins all five append_billing_event kwargs against corruption --
        the call sits inside its own inner except, so a wrong/None argument
        never surfaces as a test failure unless the args are asserted
        directly."""
        import sqlite3

        from warden.db.ddl_registry import ensure_schema
        monkeypatch.setattr(g, "_X402_ENABLED", True)
        con = sqlite3.connect(g._DB_PATH)
        ensure_schema(con, "marketplace_x402", g._DB_PATH)
        con.execute("INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?,?,?)",
                    ("a1", 1.0, "now"))
        con.commit()
        con.close()

        calls = []
        monkeypatch.setattr(
            "warden.billing.audit_chain.append_billing_event",
            lambda **kw: calls.append(kw),
        )
        amount = g.Decimal("0.25")
        assert await g.deduct_payment("a1", "premium-search", amount_usd=amount) is True
        assert len(calls) == 1
        from warden.billing.audit_chain import MCP_CALL
        assert calls[0] == {
            "tenant_id": "a1", "event_type": MCP_CALL, "amount_usd": amount,
            "agent_id": "a1", "tool_name": "premium-search",
        }
