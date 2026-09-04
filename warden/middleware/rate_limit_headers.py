"""
warden/middleware/rate_limit_headers.py
────────────────────────────────────────
Publish the throttling contract on every API response, so an agent can pace
itself instead of discovering the limit by being refused.

Until this existed the gateway enforced two independent limits and advertised
neither: a per-tenant sliding window (slowapi, default 60/min) and a monthly
request quota (``warden.billing.quota_middleware``). A caller learned about
either one only by receiving a 429, which is exactly the request an autonomous
client cannot plan around. An external readiness audit probed the public
endpoints and found no rate-limit headers at all.

What is emitted
───────────────
Two header families, because two generations of client read two different
things and the cost of both is a handful of bytes:

  RateLimit-Policy   the *static* contract, RFC 9651 structured fields as
  RateLimit          specified by draft-ietf-httpapi-ratelimit-headers-09:

                       RateLimit-Policy: "requests-per-minute";q=60;w=60
                       RateLimit: "requests-per-minute";r=59;t=41

                     `q` = quota units, `w` = window seconds, `r` = remaining,
                     `t` = seconds until the window resets.

  RateLimit-Limit    the earlier draft's separate fields (draft-06/07), which
  RateLimit-Remaining  is what most SDKs and crawlers still parse, plus the
  RateLimit-Reset      ``X-RateLimit-*`` spelling that predates the draft and is
  X-RateLimit-*        already emitted by ``warden/marketplace/rate_limit.py``.

  Retry-After        on 429 only, per RFC 9110 §10.2.3. The draft says that when
                     both are present they must point at the same instant, and
                     that the client MUST prefer Retry-After — so it is derived
                     from the same reset value.

What is *not* emitted, and why
──────────────────────────────
The live counters (``RateLimit``, ``*-Remaining``, ``*-Reset``) appear only on
responses from routes that actually consumed quota — that is, routes carrying
``@limiter.limit(...)``, which record ``request.state.view_rate_limit``. On any
other route the only honest thing to publish is the policy: no bucket was
touched, so there is no "remaining" reading that belongs to this request. The
alternative — reading the bucket speculatively on every request — would add a
Redis round trip to endpoints that do not rate-limit at all, and this codebase
has already had two production latency incidents caused by middleware doing
synchronous Redis work on the event loop.

For the same reason the one read that *is* performed runs through
``asyncio.to_thread``: ``limits`` ships a synchronous Redis client, and
``get_window_stats`` is a network call.

``get_window_stats`` is non-consuming — it reports the bucket, it does not hit
it — so publishing these headers never costs the caller quota.

Implementation notes
────────────────────
Pure ASGI rather than ``BaseHTTPMiddleware``: the headers are decided at
``http.response.start``, which needs nothing but the outgoing message, and
``BaseHTTPMiddleware`` brings a task-group and a request/response copy that
this does not need (and which has already broken ``BackgroundTasks`` here).

Every failure path is silent and falls through to the unmodified response. A
missing header is a degraded response; an exception here would be an outage.

ENV
───
  RATELIMIT_HEADERS_ENABLED  — default "true". "false" disables the middleware.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from starlette.datastructures import MutableHeaders

log = logging.getLogger("warden.middleware.rate_limit_headers")

#: Policy names published in RateLimit-Policy / RateLimit. Stable strings — a
#: client may key its own bookkeeping on them.
MINUTE_POLICY = "requests-per-minute"
MONTH_POLICY = "requests-per-month"

#: Nominal month, matching the quota counter's calendar-month key.
MONTH_WINDOW_SECONDS = 30 * 86400

#: Scraped by Prometheus many times a minute and read by no agent.
_SKIP_PATHS = frozenset({"/metrics"})


def _enabled() -> bool:
    return os.getenv("RATELIMIT_HEADERS_ENABLED", "true").strip().lower() != "false"


def _quoted(name: str) -> str:
    """A structured-field String: double-quoted, per RFC 9651 §3.3.3."""
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _minute_limit(scope: dict) -> int | None:
    """The per-minute allowance for this caller, or None if it cannot be read.

    Resolved from the same key store slowapi's ``tenant_limit`` consults, so the
    number published is the number enforced. In-memory after the first load —
    no I/O on the request path.
    """
    try:
        from warden.auth_guard import get_rate_limit

        api_key = ""
        for raw_name, raw_value in scope.get("headers") or []:
            if raw_name == b"x-api-key":
                api_key = raw_value.decode("utf-8", errors="ignore")
                break
        return int(get_rate_limit(api_key))
    except Exception as exc:
        log.debug("rate-limit headers: minute limit unavailable (%r)", exc)
        return None


def _state(scope: dict) -> dict:
    """The request-scoped state dict Starlette shares with inner layers."""
    state = scope.get("state")
    return state if isinstance(state, dict) else {}


async def _window_stats(scope: dict) -> tuple[int, int, int] | None:
    """(limit, remaining, reset_seconds) for the bucket this request consumed.

    ``view_rate_limit`` is set by slowapi's ``__evaluate_limits`` as
    ``(RateLimitItem, [key, scope])`` — including on the path that raises
    ``RateLimitExceeded``, so a 429 reports its own bucket correctly.
    """
    recorded = _state(scope).get("view_rate_limit")
    if not recorded:
        return None
    try:
        item, identifiers = recorded[0], recorded[1]
        from warden.limiter import limiter

        reset_at, remaining = await asyncio.to_thread(
            limiter.limiter.get_window_stats, item, *identifiers
        )
        reset_in = max(0, int(reset_at - time.time()) + 1)
        return int(item.amount), max(0, int(remaining)), reset_in
    except Exception as exc:
        log.debug("rate-limit headers: window stats unavailable (%r)", exc)
        return None


def _apply(
    headers: MutableHeaders,
    status: int,
    minute_limit: int | None,
    stats: tuple[int, int, int] | None,
    quota: dict[str, Any] | None,
) -> None:
    policies: list[str] = []
    live: list[str] = []

    limit = stats[0] if stats else minute_limit
    if limit is not None:
        policies.append(f"{_quoted(MINUTE_POLICY)};q={limit};w=60")
        # draft-06/07 spelling + the pre-draft X- spelling, both still widely parsed.
        headers["RateLimit-Limit"] = str(limit)
        headers["X-RateLimit-Limit"] = str(limit)

    if stats is not None:
        _, remaining, reset_in = stats
        live.append(f"{_quoted(MINUTE_POLICY)};r={remaining};t={reset_in}")
        headers["RateLimit-Remaining"] = str(remaining)
        headers["RateLimit-Reset"] = str(reset_in)
        headers["X-RateLimit-Remaining"] = str(remaining)
        headers["X-RateLimit-Reset"] = str(int(time.time()) + reset_in)

    if quota:
        month_limit = quota.get("limit")
        if month_limit is not None:
            policies.append(
                f"{_quoted(MONTH_POLICY)};q={int(month_limit)};w={MONTH_WINDOW_SECONDS}"
            )
            remaining = quota.get("remaining")
            reset_in = quota.get("reset")
            if remaining is not None and reset_in is not None:
                live.append(
                    f"{_quoted(MONTH_POLICY)};r={int(remaining)};t={int(reset_in)}"
                )

    if policies:
        headers["RateLimit-Policy"] = ", ".join(policies)
    if live:
        headers["RateLimit"] = ", ".join(live)

    if status == 429 and "retry-after" not in headers:
        # RFC 9110 §10.2.3 — delta-seconds. The draft requires it to name the
        # same instant as the reset parameter, so it is taken from there.
        retry = stats[2] if stats else 60
        headers["Retry-After"] = str(max(1, int(retry)))


class RateLimitHeadersMiddleware:
    """Attach the RateLimit family to every HTTP response."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not _enabled() or scope.get("path") in _SKIP_PATHS:
            await self.app(scope, receive, send)
            return

        started = False

        async def send_wrapper(message) -> None:
            nonlocal started
            if not started and message.get("type") == "http.response.start":
                started = True
                try:
                    headers = MutableHeaders(scope=message)
                    _apply(
                        headers,
                        int(message.get("status", 200)),
                        _minute_limit(scope),
                        await _window_stats(scope),
                        _state(scope).get("quota_policy"),
                    )
                except Exception as exc:
                    # A missing header is degraded; a raise here is an outage.
                    log.debug("rate-limit headers: not attached (%r)", exc)
            await send(message)

        await self.app(scope, receive, send_wrapper)
