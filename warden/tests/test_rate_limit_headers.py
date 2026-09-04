"""
warden/tests/test_rate_limit_headers.py — the throttling contract is published.

An external readiness audit (2026-09-02) probed the public endpoints and found
no rate-limit headers on any of them. The gateway enforced two limits at the
time — a per-tenant window (slowapi) and a monthly quota — and advertised
neither, so the only way for a client to learn either one was to be refused.

These tests hold three things:

  * the header *syntax* matches draft-ietf-httpapi-ratelimit-headers-09 and the
    earlier draft it supersedes, because a client parses the spelling, not the
    intent;
  * a route that consumes no quota publishes the policy and no counter — a
    "remaining" reading that belongs to no bucket would be a fabricated number;
  * the middleware cannot fail a request. Every branch in it is best-effort.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import MutableHeaders

from warden.billing.quota_middleware import (
    _publish_quota_policy,
    _seconds_until_month_rolls_over,
)
from warden.middleware.rate_limit_headers import (
    MINUTE_POLICY,
    MONTH_POLICY,
    MONTH_WINDOW_SECONDS,
    RateLimitHeadersMiddleware,
    _apply,
    _minute_limit,
    _quoted,
    _state,
)


def _headers(**start) -> MutableHeaders:
    message = {"type": "http.response.start", "status": 200, "headers": [], **start}
    return MutableHeaders(scope=message)


# ── Structured-field syntax (RFC 9651, as used by the RateLimit draft) ────────


class TestFieldSyntax:
    def test_policy_names_are_quoted_strings(self):
        assert _quoted("requests-per-minute") == '"requests-per-minute"'

    def test_a_quote_inside_a_policy_name_is_escaped(self):
        """An unescaped quote would split one member into two malformed ones."""
        assert _quoted('we"ird') == '"we\\"ird"'

    def test_the_policy_field_carries_quota_and_window(self):
        h = _headers()
        _apply(h, 200, 60, None, None)
        assert h["RateLimit-Policy"] == f'"{MINUTE_POLICY}";q=60;w=60'

    def test_the_live_field_carries_remaining_and_reset(self):
        h = _headers()
        _apply(h, 200, 60, (60, 59, 41), None)
        assert h["RateLimit"] == f'"{MINUTE_POLICY}";r=59;t=41'

    def test_both_drafts_and_the_legacy_spelling_agree(self):
        """
        Three spellings are emitted because three generations of client parse
        three different things. Disagreement between them is worse than silence.
        """
        h = _headers()
        _apply(h, 200, 60, (60, 59, 41), None)
        assert h["RateLimit-Limit"] == h["X-RateLimit-Limit"] == "60"
        assert h["RateLimit-Remaining"] == h["X-RateLimit-Remaining"] == "59"
        assert h["RateLimit-Reset"] == "41"
        # The X- spelling predates the draft and is an epoch, not a delta.
        assert int(h["X-RateLimit-Reset"]) > 1_700_000_000

    def test_the_fields_parse_as_a_list_of_members(self):
        h = _headers()
        _apply(h, 200, 60, (60, 59, 41), {"limit": 5000, "remaining": 4000, "reset": 900})
        member = re.compile(r'^"[^"]+"(;[a-z]+=[^;,]+)+$')
        for field in ("RateLimit-Policy", "RateLimit"):
            for part in h[field].split(", "):
                assert member.match(part), f"{field} member is malformed: {part!r}"


# ── What is published, and what is deliberately not ──────────────────────────


class TestWhatIsPublished:
    def test_a_route_that_consumed_nothing_publishes_no_counter(self):
        """
        No bucket was hit, so there is no remaining reading that belongs to this
        request. Publishing one would be a number with nothing behind it.
        """
        h = _headers()
        _apply(h, 200, 60, None, None)
        assert "RateLimit-Policy" in h
        assert "RateLimit" not in h
        assert "RateLimit-Remaining" not in h
        assert "X-RateLimit-Remaining" not in h

    def test_the_monthly_quota_is_published_as_a_second_policy(self):
        h = _headers()
        _apply(h, 200, 60, (60, 59, 41), {"limit": 5000, "remaining": 4321, "reset": 900})
        assert h["RateLimit-Policy"] == (
            f'"{MINUTE_POLICY}";q=60;w=60, "{MONTH_POLICY}";q=5000;w={MONTH_WINDOW_SECONDS}'
        )
        assert f'"{MONTH_POLICY}";r=4321;t=900' in h["RateLimit"]

    def test_a_quota_with_no_reading_publishes_the_policy_alone(self):
        """Redis down: the plan limit is still known, the counter is not."""
        h = _headers()
        _apply(h, 200, 60, None, {"limit": 5000, "remaining": None, "reset": None})
        assert f'"{MONTH_POLICY}";q=5000' in h["RateLimit-Policy"]
        assert "RateLimit" not in h

    def test_an_unlimited_plan_publishes_no_monthly_policy(self):
        scope: dict = {"state": {}}
        _publish_quota_policy(scope, limit=None, used=3)
        assert "quota_policy" not in scope["state"]

    def test_nothing_is_published_when_no_limit_can_be_resolved(self):
        h = _headers()
        _apply(h, 200, None, None, None)
        assert "RateLimit-Policy" not in h
        assert "RateLimit-Limit" not in h


class TestRetryAfter:
    def test_a_429_names_the_same_instant_as_the_reset(self):
        """
        The draft: when both are present they must point at the same time, and
        the client must prefer Retry-After.
        """
        h = _headers()
        _apply(h, 429, 60, (60, 0, 37), None)
        assert h["Retry-After"] == "37" == h["RateLimit-Reset"]

    def test_a_429_without_a_window_reading_still_answers(self):
        h = _headers()
        _apply(h, 429, 60, None, None)
        assert h["Retry-After"] == "60"

    def test_an_existing_retry_after_is_not_overwritten(self):
        """The quota 429 sets its own (a day), which the window does not know."""
        h = _headers()
        h["Retry-After"] = "86400"
        _apply(h, 429, 60, (60, 0, 37), None)
        assert h["Retry-After"] == "86400"

    def test_retry_after_is_not_sent_on_a_success(self):
        h = _headers()
        _apply(h, 200, 60, (60, 59, 41), None)
        assert "Retry-After" not in h


# ── The monthly window ───────────────────────────────────────────────────────


class TestMonthReset:
    def test_it_counts_to_the_start_of_the_next_month(self):
        now = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
        expected = (datetime(2026, 10, 1, tzinfo=UTC) - now).total_seconds()
        assert _seconds_until_month_rolls_over(now) == int(expected)

    def test_december_rolls_into_the_next_year(self):
        now = datetime(2026, 12, 31, 23, 0, 0, tzinfo=UTC)
        assert _seconds_until_month_rolls_over(now) == 3600

    def test_it_is_never_zero(self):
        """A reset of 0 tells a client to retry immediately, forever."""
        now = datetime(2026, 9, 30, 23, 59, 59, 999_999, tzinfo=UTC)
        assert _seconds_until_month_rolls_over(now) >= 1


# ── Failure is silent ────────────────────────────────────────────────────────


class TestNeverFailsTheRequest:
    @pytest.mark.asyncio
    async def test_a_broken_limiter_does_not_break_the_response(self, monkeypatch):
        import warden.middleware.rate_limit_headers as mod

        def _boom(_scope):
            raise RuntimeError("key store on fire")

        monkeypatch.setattr(mod, "_minute_limit", _boom)

        sent: list[dict] = []

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def send(message):
            sent.append(message)

        await RateLimitHeadersMiddleware(app)(
            {"type": "http", "path": "/health", "headers": [], "state": {}}, None, send
        )
        assert sent[0]["status"] == 200
        assert sent[1]["body"] == b"ok"

    @pytest.mark.asyncio
    async def test_a_non_http_scope_is_passed_straight_through(self):
        seen: list = []

        async def app(scope, receive, send):
            seen.append(scope["type"])

        await RateLimitHeadersMiddleware(app)({"type": "websocket"}, None, None)
        assert seen == ["websocket"]

    @pytest.mark.asyncio
    async def test_the_env_kill_switch_removes_every_header(self, monkeypatch):
        monkeypatch.setenv("RATELIMIT_HEADERS_ENABLED", "false")
        sent: list[dict] = []

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})

        async def send(message):
            sent.append(message)

        await RateLimitHeadersMiddleware(app)(
            {"type": "http", "path": "/health", "headers": [], "state": {}}, None, send
        )
        assert sent[0]["headers"] == []

    def test_a_missing_state_is_not_an_error(self):
        assert _state({}) == {}
        assert _state({"state": "not a dict"}) == {}

    def test_the_minute_limit_reads_the_callers_key(self):
        """It must consult the same store slowapi's tenant_limit does."""
        scope = {"headers": [(b"x-api-key", b"nonexistent-key")]}
        assert _minute_limit(scope) == _minute_limit({"headers": []})


# ── End to end, through the real app ─────────────────────────────────────────


class TestThroughTheGateway:
    def test_an_unlimited_route_still_advertises_the_policy(self, client):
        response = client.get("/health")
        assert response.headers["RateLimit-Policy"].startswith(f'"{MINUTE_POLICY}";q=')
        assert response.headers["RateLimit-Limit"].isdigit()

    def test_the_filter_route_reports_its_own_bucket(self, client):
        response = client.post("/filter", json={"content": "hello"})
        assert response.status_code == 200
        limit = int(response.headers["RateLimit-Limit"])
        remaining = int(response.headers["RateLimit-Remaining"])
        assert 0 <= remaining < limit, "the request that was served was not counted"
        assert response.headers["RateLimit"].startswith(f'"{MINUTE_POLICY}";r={remaining};t=')

    def test_a_real_429_carries_the_whole_contract(self):
        """
        The one response that matters most. Built on its own app with a tiny
        limit rather than by hammering the shared fixture, so it is fast and
        does not leave the session's bucket drained for other tests.
        """
        from fastapi import FastAPI
        from starlette.requests import Request
        from slowapi import _rate_limit_exceeded_handler
        from slowapi.errors import RateLimitExceeded

        from warden.limiter import limiter
        from warden.middleware.rate_limit_headers import RateLimitHeadersMiddleware

        app = FastAPI()
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(RateLimitHeadersMiddleware)

        async def narrow(request):  # noqa: ARG001
            return {"ok": True}

        # slowapi finds the Request argument by comparing the parameter's
        # *annotation object* to starlette.Request. This module has
        # `from __future__ import annotations`, which makes every annotation a
        # string — so a decorated route declared the usual way silently loses
        # its limit and never returns 429. Bind the real class, then apply the
        # decorators in the order the sugar would have.
        narrow.__annotations__ = {"request": Request}
        app.get("/narrow")(limiter.limit("2/minute")(narrow))

        with TestClient(app, raise_server_exceptions=False) as http:
            statuses = [http.get("/narrow") for _ in range(4)]

        refused = next(r for r in statuses if r.status_code == 429)
        assert refused.headers["RateLimit"] == f'"{MINUTE_POLICY}";r=0;t={refused.headers["RateLimit-Reset"]}'
        assert refused.headers["Retry-After"] == refused.headers["RateLimit-Reset"]
        assert int(refused.headers["Retry-After"]) >= 1
        assert refused.headers["RateLimit-Policy"].startswith(f'"{MINUTE_POLICY}";q=2;w=60')

    def test_every_header_is_latin_1_and_single_line(self, client):
        """A header carrying a newline is a response-splitting bug."""
        response = client.get("/health")
        for name, value in response.headers.items():
            if "ratelimit" not in name.lower():
                continue
            assert "\n" not in value and "\r" not in value
            value.encode("latin-1")
