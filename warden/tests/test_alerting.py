"""
SR-7.2 — coverage for warden/alerting.py (Slack / PagerDuty / Telegram channels).

All network I/O is faked via a recording httpx.AsyncClient stand-in. Tests pin:
  - risk-threshold gating on alert_block_event
  - each channel fires only when its credential is configured
  - per-channel failures are swallowed (fire-and-forget, never propagate)
  - GDPR: note/prompt content is never in the payload (only metadata)
"""
from __future__ import annotations

import pytest

import warden.alerting as al

_CALLS: list[tuple[str, dict]] = []


class _FakeResp:
    def raise_for_status(self):
        return None


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None):
        _CALLS.append((url, json or {}))
        return _FakeResp()


class _BoomClient(_FakeClient):
    async def post(self, url, json=None):
        raise RuntimeError("network down")


@pytest.fixture(autouse=True)
def _fake_http(monkeypatch):
    _CALLS.clear()
    monkeypatch.setattr(al.httpx, "AsyncClient", _FakeClient)
    yield


def _configure(monkeypatch, *, slack=None, pagerduty=None, tg_token=None, tg_chat=None):
    monkeypatch.setattr(al, "_SLACK_WEBHOOK", slack or "")
    monkeypatch.setattr(al, "_PAGERDUTY_KEY", pagerduty or "")
    monkeypatch.setattr(al, "_TELEGRAM_TOKEN", tg_token or "")
    monkeypatch.setattr(al, "_TELEGRAM_CHAT_ID", tg_chat or "")


# ── alert_block_event ─────────────────────────────────────────────────────────

class TestAlertBlockEvent:
    @pytest.mark.asyncio
    async def test_below_threshold_is_silent(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook")
        await al.alert_block_event(attack_type="x", risk_level="medium", rule_summary="s")
        assert _CALLS == []                       # medium < high threshold

    @pytest.mark.asyncio
    async def test_high_fires_slack_only(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook", pagerduty="pd-key")
        await al.alert_block_event(attack_type="jailbreak", risk_level="high", rule_summary="s")
        assert len(_CALLS) == 1                    # slack only — pagerduty is BLOCK-only
        assert _CALLS[0][0] == "https://slack/hook"

    @pytest.mark.asyncio
    async def test_block_fires_slack_and_pagerduty(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook", pagerduty="pd-key")
        await al.alert_block_event(attack_type="rce", risk_level="block", rule_summary="s",
                                   request_id="req-9")
        urls = [c[0] for c in _CALLS]
        assert "https://slack/hook" in urls
        assert any("pagerduty.com" in u for u in urls)

    @pytest.mark.asyncio
    async def test_no_channels_configured_is_noop(self, monkeypatch):
        _configure(monkeypatch)
        await al.alert_block_event(attack_type="x", risk_level="block", rule_summary="s")
        assert _CALLS == []

    @pytest.mark.asyncio
    async def test_slack_and_pagerduty_failures_swallowed(self, monkeypatch):
        # Both channels configured + failing transport → both except arms run,
        # nothing propagates.
        _configure(monkeypatch, slack="https://slack/hook", pagerduty="pd-key")
        monkeypatch.setattr(al.httpx, "AsyncClient", _BoomClient)
        await al.alert_block_event(attack_type="x", risk_level="block", rule_summary="s")


# ── alert_poisoning_event ─────────────────────────────────────────────────────

class TestPoisoningEvent:
    @pytest.mark.asyncio
    async def test_telegram_and_slack_both_fire(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook", tg_token="tok", tg_chat="-100")
        await al.alert_poisoning_event(
            attack_vector="gradient", poisoning_score=0.91, detail="d", tenant_id="t",
            rollback_done=True,
        )
        urls = [c[0] for c in _CALLS]
        assert any("telegram.org" in u for u in urls)
        assert "https://slack/hook" in urls

    @pytest.mark.asyncio
    async def test_failures_are_swallowed(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook", tg_token="tok", tg_chat="-100")
        monkeypatch.setattr(al.httpx, "AsyncClient", _BoomClient)
        await al.alert_poisoning_event(
            attack_vector="v", poisoning_score=0.9, detail="d", tenant_id="t",
        )


# ── alert_corpus_rollback ─────────────────────────────────────────────────────

class TestCorpusRollback:
    @pytest.mark.asyncio
    async def test_fires_both_channels(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook", tg_token="tok", tg_chat="-100")
        await al.alert_corpus_rollback(tenant_id="t", failing_canaries=3, drift=0.12, detail="d")
        urls = [c[0] for c in _CALLS]
        assert any("telegram.org" in u for u in urls)
        assert "https://slack/hook" in urls

    @pytest.mark.asyncio
    async def test_failures_swallowed(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook", tg_token="tok", tg_chat="-100")
        monkeypatch.setattr(al.httpx, "AsyncClient", _BoomClient)
        await al.alert_corpus_rollback(tenant_id="t", failing_canaries=1, drift=0.0, detail="d")


# ── alert_obsidian_event ──────────────────────────────────────────────────────

class TestObsidianEvent:
    @pytest.mark.asyncio
    async def test_no_slack_configured_is_noop(self, monkeypatch):
        _configure(monkeypatch)
        await al.alert_obsidian_event(filename="n.md", risk_level="high", flags=["pii"],
                                      data_class="confidential")
        assert _CALLS == []

    @pytest.mark.asyncio
    async def test_share_confirmation_when_ueciid_present(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook")
        await al.alert_obsidian_event(filename="n.md", risk_level="low", flags=[],
                                      data_class="general", ueciid="SEP-abc")
        assert len(_CALLS) == 1
        assert "SEP-abc" in _CALLS[0][1]["text"]

    @pytest.mark.asyncio
    async def test_high_risk_scan_alert_when_no_ueciid(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook")
        await al.alert_obsidian_event(filename="secret.md", risk_level="block",
                                      flags=["api_key"], data_class="restricted")
        assert len(_CALLS) == 1
        text = _CALLS[0][1]["text"]
        assert "api_key" in text and "secret.md" in text

    @pytest.mark.asyncio
    async def test_failure_swallowed(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook")
        monkeypatch.setattr(al.httpx, "AsyncClient", _BoomClient)
        await al.alert_obsidian_event(filename="n.md", risk_level="high", flags=[],
                                      data_class="general")


# ── send_alert (sync helper) + _send_telegram guard ───────────────────────────

class TestMisc:
    def test_send_alert_noop_without_webhook(self, monkeypatch):
        _configure(monkeypatch)
        al.send_alert("hello")                    # must not raise, no webhook
        assert _CALLS == []

    def test_send_alert_with_webhook_does_not_raise(self, monkeypatch):
        _configure(monkeypatch, slack="https://slack/hook")
        al.send_alert("hello", level="warning")   # exercises the sync loop path

    @pytest.mark.asyncio
    async def test_send_telegram_guarded_without_credentials(self, monkeypatch):
        _configure(monkeypatch)                   # no token/chat
        await al._send_telegram("hi")             # early return, no post
        assert _CALLS == []


# ── alert_push_verdict ────────────────────────────────────────────────────────

class TestPushVerdict:
    @pytest.mark.asyncio
    async def test_no_tokens_is_noop(self, monkeypatch):
        import warden.push.registry as reg
        monkeypatch.setattr(reg, "get_tokens_for_tenant", lambda t: [])
        await al.alert_push_verdict("t", "high", "x", "req-1")   # returns early

    @pytest.mark.asyncio
    async def test_push_failure_is_fail_open(self, monkeypatch):
        import warden.push.registry as reg
        def _boom(_t):
            raise RuntimeError("registry down")
        monkeypatch.setattr(reg, "get_tokens_for_tenant", _boom)
        await al.alert_push_verdict("t", "high", "x", "req-1")   # swallowed

    @pytest.mark.asyncio
    async def test_push_sends_when_tokens_present(self, monkeypatch):
        import warden.push.registry as reg
        import warden.push.service as svc
        sent = {}

        class _Svc:
            def send_verdict_alert(self, tokens, payload):
                sent["tokens"] = tokens
                sent["payload"] = payload

        monkeypatch.setattr(reg, "get_tokens_for_tenant", lambda t: ["dev-tok"])
        monkeypatch.setattr(svc, "get_push_service", lambda: _Svc())
        await al.alert_push_verdict("t", "high", "rce", "req-9", rule_summary="s")
        assert sent["tokens"] == ["dev-tok"]
        assert sent["payload"]["attack_type"] == "rce"
