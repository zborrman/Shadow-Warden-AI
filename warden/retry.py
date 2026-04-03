"""
warden/retry.py
━━━━━━━━━━━━━━
Lightweight async (and sync) retry decorator — no external dependencies.

Design goals
────────────
  • No new packages — only stdlib (asyncio, functools, logging, random, time).
  • Configurable: max attempts, base delay, max delay, jitter, retryable predicate.
  • Fail-loud by default: re-raises the last exception after exhausting attempts.
  • Works as a plain decorator or as a parameterised decorator factory.

Usage
─────

  from warden.retry import async_retry, RetryConfig, ALERT_RETRY, NIM_RETRY

  # Pre-built config (recommended)
  @async_retry(ALERT_RETRY)
  async def _send_slack(payload: dict) -> None: ...

  # Custom config
  MY_RETRY = RetryConfig(max_attempts=5, base_delay=2.0, max_delay=30.0)
  @async_retry(MY_RETRY)
  async def my_api_call() -> str: ...

  # Conditional retry (e.g. don't retry 4xx HTTP errors)
  @async_retry(RetryConfig(retryable_on=lambda e: not isinstance(e, httpx.HTTPStatusError)
                                                  or e.response.status_code >= 500))
  async def call_nim() -> str: ...

Pre-built configs
─────────────────
  ALERT_RETRY   — 3 attempts, 1 s base, 10 s max, jitter on.
                  Use for Slack / PagerDuty / Telegram HTTP calls.
  WEBHOOK_RETRY — 3 attempts, 1 s base, 8 s max, jitter on.
                  Use for outbound tenant webhook delivery.
  NIM_RETRY     — 3 attempts, 1 s base, 4 s max, no 4xx retry.
                  Use for NVIDIA NIM / Nemotron API calls.
  FAST_RETRY    — 2 attempts, 0.5 s base, 2 s max.
                  Use for quick internal service calls.

Jitter
──────
  When jitter=True the actual sleep is uniformly sampled in [delay*0.5, delay].
  This prevents retry storms when many workers fail simultaneously.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

__all__ = [
    "RetryConfig",
    "async_retry",
    "sync_retry",
    "ALERT_RETRY",
    "WEBHOOK_RETRY",
    "NIM_RETRY",
    "FAST_RETRY",
]

log = logging.getLogger("warden.retry")


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RetryConfig:
    """Immutable retry policy."""

    # Total number of attempts (including the first).
    max_attempts: int = 3

    # Initial delay between attempts (seconds).  Doubles each retry.
    base_delay: float = 1.0

    # Hard cap on per-attempt delay (seconds).
    max_delay: float = 60.0

    # When True, sleep is uniformly sampled in [delay*0.5, delay] to spread
    # retries across time and avoid thundering-herd effects.
    jitter: bool = True

    # Predicate: given the raised exception, return True to retry, False to
    # propagate immediately.  Defaults to retrying on any exception.
    retryable_on: Callable[[Exception], bool] = field(
        default=lambda _exc: True,
        compare=False,
        hash=False,
    )

    def delay_for(self, attempt: int) -> float:
        """
        Return the sleep duration before attempt *attempt* (0-indexed).

        Attempt 0 = first retry (after 1st failure).
        Exponential: base_delay * 2^attempt, capped at max_delay, then jittered.
        """
        raw = min(self.base_delay * (2 ** attempt), self.max_delay)
        if self.jitter:
            raw = raw * (0.5 + random.random() * 0.5)
        return raw


# ── Pre-built configs ─────────────────────────────────────────────────────────

# Slack / PagerDuty / Telegram — tolerates brief API hiccups
ALERT_RETRY = RetryConfig(max_attempts=3, base_delay=1.0, max_delay=10.0, jitter=True)

# Outbound tenant webhooks — customer servers may be slow
WEBHOOK_RETRY = RetryConfig(max_attempts=3, base_delay=1.0, max_delay=8.0, jitter=True)

# NVIDIA NIM — don't retry 4xx (bad request / auth), retry 5xx and network
def _nim_retryable(exc: Exception) -> bool:
    try:
        import httpx  # noqa: PLC0415
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code >= 500
        return isinstance(exc, (httpx.TimeoutException, httpx.ConnectError))
    except ImportError:
        return True

NIM_RETRY = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=4.0,
    jitter=False,  # NIM docs suggest fixed back-off
    retryable_on=_nim_retryable,
)

# Fast internal calls — minimal wait, 2 attempts only
FAST_RETRY = RetryConfig(max_attempts=2, base_delay=0.5, max_delay=2.0, jitter=True)


# ── Decorators ────────────────────────────────────────────────────────────────

def async_retry(config: RetryConfig):
    """
    Decorator factory for async functions.

    Parameters
    ----------
    config : RetryConfig
        The retry policy to apply.

    The decorated function is retried up to `config.max_attempts` times.
    On each retry the function is re-called with the same arguments.
    The final exception is re-raised if all attempts fail.
    """
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            for attempt in range(config.max_attempts):
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    if not config.retryable_on(exc):
                        raise
                    last_exc = exc
                    if attempt + 1 == config.max_attempts:
                        break
                    delay = config.delay_for(attempt)
                    log.warning(
                        "retry: %s failed (attempt %d/%d), retrying in %.1fs — %s: %s",
                        fn.__qualname__,
                        attempt + 1,
                        config.max_attempts,
                        delay,
                        type(exc).__name__,
                        exc,
                    )
                    await asyncio.sleep(delay)

            log.error(
                "retry: %s exhausted %d attempts — %s: %s",
                fn.__qualname__,
                config.max_attempts,
                type(last_exc).__name__,
                last_exc,
            )
            raise last_exc  # type: ignore[misc]

        return wrapper
    return decorator


def sync_retry(config: RetryConfig):
    """
    Decorator factory for synchronous functions.

    Same semantics as `async_retry` but uses `time.sleep` instead of
    `asyncio.sleep`.  Suitable for blocking I/O helpers called from
    worker threads or startup code.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            for attempt in range(config.max_attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    if not config.retryable_on(exc):
                        raise
                    last_exc = exc
                    if attempt + 1 == config.max_attempts:
                        break
                    delay = config.delay_for(attempt)
                    log.warning(
                        "retry: %s failed (attempt %d/%d), retrying in %.1fs — %s: %s",
                        fn.__qualname__,
                        attempt + 1,
                        config.max_attempts,
                        delay,
                        type(exc).__name__,
                        exc,
                    )
                    time.sleep(delay)

            log.error(
                "retry: %s exhausted %d attempts — %s: %s",
                fn.__qualname__,
                config.max_attempts,
                type(last_exc).__name__,
                last_exc,
            )
            raise last_exc  # type: ignore[misc]

        return wrapper
    return decorator
