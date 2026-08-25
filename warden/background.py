"""
warden/background.py
────────────────────
Detached execution for work that must not sit on the request path.

Why this module exists
──────────────────────
FastAPI's ``BackgroundTasks`` is documented as running *after* the response is
returned. That is true only for a pure-ASGI middleware stack. This app has five
``BaseHTTPMiddleware`` instances in it (``MTLSMiddleware``, ``RegionMiddleware``,
``_ExtensionCORSMiddleware``, and two more), and ``BaseHTTPMiddleware`` awaits
the inner call — background tasks included — before the response is released.
So ``background_tasks.add_task()`` on this app is not backgrounded at all: the
caller waits for it.

Measured on production 2026-08-24/25 with request spans (PR #385). A blocked
request, traced end to end::

    +   0.0            POST /filter
    +  31.4   14.5ms   ml_inference
    +  46.0   30.9ms   data_poison
    +  77.2    0.0ms   decision            ← the filter is finished at 77 ms
    +  81.2 1736.7ms   BackgroundTask process_blocked
    +1728.9    0.1ms   POST /filter http send   ← the client waited 1730 ms

and again on organic traffic — the 15-minute corpus canary, which fires blocked
payloads — at 20:45:00Z, 21:45:00Z and 00:00:01Z::

    2488.2ms  first http send +2486.9ms   process_blocked 2088.9ms
    2485.4ms  first http send +2477.1ms   process_blocked 2064.3ms
    2337.7ms  first http send +2335.3ms   process_blocked 1965.1ms

Every HIGH/BLOCK request was paying ~2 s for the Evolution Engine and the Slack
webhook inline. Clean traffic was unaffected (p50 25 ms), so this only ever
showed up as a P99 tail — which is why it survived: the number it moved was the
one nobody could resolve until the histogram gained buckets (#383) and tracing
started working (#385).

Why a task and not the arq queue
────────────────────────────────
arq is already in the stack and would survive a restart, which a task does not.
It was rejected for this path because the Evolution Engine takes the *prompt
content* as its argument, and enqueuing means writing that content into Redis.
"Content is NEVER logged — only metadata" is a hard GDPR requirement here, and a
queue payload is a worse persistence than a log line: it sits in a shared store
with its own retention. Keeping the work in-process keeps content in-process.

The trade that buys: work spawned here is lost if the process exits before it
finishes. For rule learning and alerting that is acceptable — a missed rule is
re-learned on the next matching attack. Do not use ``spawn`` for anything whose
loss is not acceptable; use arq, and pass an identifier rather than content.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

log = logging.getLogger("warden.background")

# Strong references to in-flight tasks.
#
# asyncio keeps only a *weak* reference to a task it did not create for you, so
# a bare `create_task(...)` whose result nobody holds can be garbage-collected
# mid-flight — the work silently never finishes. Holding the task here until its
# done-callback removes it is the documented fix, not a precaution.
_INFLIGHT: set[asyncio.Task[Any]] = set()


def inflight_count() -> int:
    """Number of tasks currently running. Exposed for tests and diagnostics."""
    return len(_INFLIGHT)


def _on_done(task: asyncio.Task[Any]) -> None:
    _INFLIGHT.discard(task)
    if task.cancelled():
        log.warning("background task cancelled: %s", task.get_name())
        return
    exc = task.exception()
    if exc is None:
        return
    # A detached task that raises into the void is precisely the failure mode
    # this codebase keeps finding, so it is logged loudly and counted.
    log.error(
        "background task failed: %s: %s", task.get_name(), exc, exc_info=exc
    )
    try:
        from warden.metrics import BACKGROUND_TASK_FAILURES

        if BACKGROUND_TASK_FAILURES is not None:
            BACKGROUND_TASK_FAILURES.labels(task=task.get_name()).inc()
    except Exception:  # pragma: no cover — metrics must never break the app
        pass


def spawn(
    fn: Callable[..., Coroutine[Any, Any, Any]],
    /,
    *args: Any,
    name: str | None = None,
    **kwargs: Any,
) -> asyncio.Task[Any] | None:
    """Run ``fn(*args, **kwargs)`` detached from the caller.

    Returns the task, or ``None`` if there is no running loop — in which case
    the call is a no-op rather than an error, so sync call sites and tests that
    exercise the surrounding code without a loop are unaffected.

    The returned task is *not* awaited by the request, which is the entire
    point. Callers must not depend on its completion.
    """
    task_name = name or getattr(fn, "__name__", "background")
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        log.debug("spawn(%s) with no running loop — skipped", task_name)
        return None

    task: asyncio.Task[Any] = loop.create_task(
        fn(*args, **kwargs), name=task_name
    )
    _INFLIGHT.add(task)
    task.add_done_callback(_on_done)
    return task
