"""
warden/observability.py
───────────────────────
Fail-open observability — turn silent bypasses into loud, countable events
(Deep-Eng program, phase P0). See docs/deep-engineering.md.

The dominant failure mode of a security gateway is not a crash: it is a guard
that throws, gets swallowed by ``except: pass``, and lets the request through
while every dashboard stays green. This module gives every fail-open site a
single primitive to call so the bypass becomes a Prometheus counter + a
structured log line.

GDPR (FAILOPEN-03): nothing here ever receives or logs request content — only
``stage``, ``reason``, and the caught exception's ``repr``.
"""
from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from warden import metrics

log = logging.getLogger("warden.failopen")

__all__ = [
    "SecurityDegradedError",
    "Reason",
    "record_failopen",
    "failopen_guard",
    "run_pipeline_canary",
]


class SecurityDegradedError(RuntimeError):
    """A security-critical component is unavailable AND the caller opted into
    fail-closed behaviour. Raised only where a documented invariant says the
    request/boot must NOT proceed on failure (e.g. the startup canary gate under
    ``PIPELINE_FAILCLOSED_ON_CANARY=true``). Ordinary fail-open sites never raise
    this — they call :func:`record_failopen` and continue."""


class Reason:
    """Canonical machine-readable ``reason`` labels — keep the metric cardinality
    bounded. Prefer one of these over a free-form string."""

    REDIS_UNAVAILABLE = "redis_unavailable"
    MODEL_NOT_LOADED = "model_not_loaded"
    TIMEOUT = "timeout"
    IMPORT_MISSING = "import_missing"
    PARSE_ERROR = "parse_error"
    NETWORK_ERROR = "network_error"
    BACKEND_ERROR = "backend_error"
    UNKNOWN = "unknown"


def record_failopen(stage: str, reason: str, exc: BaseException | None = None) -> None:
    """Count + log a fail-open event. Never raises; never logs content.

    Call this at the moment a guard errors and the code chooses to allow the
    operation to proceed (fail-open). ``stage`` is the pipeline stage or
    subsystem (e.g. ``"brain"``, ``"cache"``, ``"kya"``); ``reason`` should be a
    :class:`Reason` constant.
    """
    # metric backend must never break the hot path
    with contextlib.suppress(Exception):
        metrics.STAGE_FAILOPEN_TOTAL.labels(stage=stage, reason=reason).inc()
    try:
        if exc is not None:
            log.warning("fail-open [%s/%s]: %r", stage, reason, exc)
        else:
            log.warning("fail-open [%s/%s]", stage, reason)
    except Exception:  # noqa: BLE001 — logging must never break the hot path
        pass


@contextmanager
def failopen_guard(stage: str, reason: str) -> Iterator[None]:
    """Context manager wrapping a fail-open block: any exception is counted via
    :func:`record_failopen` then swallowed, so control returns to the caller
    which supplies its own safe default.

        with failopen_guard("cache", Reason.REDIS_UNAVAILABLE):
            return _redis.get(key)      # on error → counted, then falls through
        return None                     # caller's documented safe default
    """
    try:
        yield
    except Exception as exc:  # noqa: BLE001 — deliberate fail-open, now observable
        record_failopen(stage, reason, exc)


async def run_pipeline_canary() -> dict:
    """Fire the canary corpus through the LIVE FilterPipeline and report a verdict.

    Exercises the real 9-stage orchestrator (not a mock) with a synthetic internal
    auth context, so it proves the detector still *detects* — not merely that the
    stage modules import. Requires the orchestrator to be published (post-lifespan);
    if it is not yet available the verdict is ``available: False`` and treated as
    non-fatal by callers.

    Returns a dict: ``{available, caught, missed, false_positive, healthy}``.
    Sets the ``warden_pipeline_canary_missed`` / ``_false_pos`` gauges as a
    side effect. Never raises.
    """
    verdict = {"available": False, "caught": 0, "missed": 0,
               "false_positive": 0, "healthy": False}
    try:
        from warden.auth_guard import AuthResult
        from warden.observability_canaries import CANARY_BENIGN, CANARY_JAILBREAKS
        from warden.schemas import FilterRequest
        from warden.services.pipeline import FilterPipeline, is_available

        if not is_available():
            return verdict

        pipeline = FilterPipeline()
        auth = AuthResult(api_key="__canary__", tenant_id="__canary__")

        def _blocked(resp: object) -> bool:
            if getattr(resp, "blocked", False):
                return True
            risk = str(getattr(resp, "risk_level", getattr(resp, "risk", ""))).upper()
            return risk in ("HIGH", "BLOCK", "CRITICAL")

        caught = 0
        for jb in CANARY_JAILBREAKS:
            req = FilterRequest(content=jb, tenant_id="__canary__")
            resp = await pipeline.run(req, uuid.uuid4().hex, auth)
            if _blocked(resp):
                caught += 1

        benign_req = FilterRequest(content=CANARY_BENIGN, tenant_id="__canary__")
        benign_resp = await pipeline.run(benign_req, uuid.uuid4().hex, auth)
        false_pos = 1 if _blocked(benign_resp) else 0

        missed = len(CANARY_JAILBREAKS) - caught
        verdict = {
            "available": True,
            "caught": caught,
            "missed": missed,
            "false_positive": false_pos,
            "healthy": missed == 0 and false_pos == 0,
        }
        try:
            metrics.PIPELINE_CANARY_MISSED.set(missed)
            metrics.PIPELINE_CANARY_FALSE_POS.set(false_pos)
        except Exception:  # noqa: BLE001
            pass
        return verdict
    except Exception as exc:  # noqa: BLE001 — the self-test must never crash the app
        record_failopen("pipeline_canary", Reason.BACKEND_ERROR, exc)
        return verdict
