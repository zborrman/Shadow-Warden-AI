"""
S6 — fail-**safe** injection pre-screen for Digital Staff freetext (modernization-plan-v8 §6d).

Rec-1 requires every staff tool that ingests freetext (`screen_sanctions_list`,
`score_kyc_profile`, `generate_sar`, `generate_seo_content`) to send it through `/filter`
before it enters an agent's reasoning context. That call **silently allowed the text through
on a filter timeout** — a `log.debug` and carry on — so a targeted timeout of the local
filter was a *silent* way to smuggle an injection payload straight past the guardrail.

This helper keeps availability (a dead filter must not brick compliance work) but makes the
bypass **observable and throttled** instead of silent:

* **bounded retry** — a transient blip gets a second chance before we ever bypass.
* **observable** — a genuine bypass increments the P0 `record_failopen` Prometheus counter
  (alertable) and emits a structured `injection_prescreen_bypassed` audit line.
* **throttled** — each bypass bumps a per-tenant sliding counter; once a tenant crosses the
  threshold the audit escalates to `status="degraded"` and `should_throttle` flips True, so
  the caller / velocity layer can tighten that tenant's rate limit. We never *reject* on
  bypass — availability is preserved — but a burst of bypasses is now loud and rate-limitable.

A filter verdict of `blocked=True` remains **fail-CLOSED** (the input is rejected) exactly as
before — that path was never the weakness.
"""
from __future__ import annotations

import logging
import os
import time
from collections import deque
from dataclasses import dataclass

from warden.observability import Reason, record_failopen
from warden.staff.structured_log import emit

log = logging.getLogger(__name__)

_STAGE = "staff_injection_prescreen"

# Bounded-retry + timeout budget (env-tunable). attempts includes the first try.
_ATTEMPTS = max(1, int(os.getenv("STAFF_PRESCREEN_ATTEMPTS", "2")))
_TIMEOUT_S = float(os.getenv("STAFF_PRESCREEN_TIMEOUT_S", "4"))
_MAX_CHARS = 4000

# Per-tenant bypass throttle: count bypass events in a sliding window; over the
# threshold the tenant is flagged degraded so the caller can tighten its rate limit.
_THROTTLE_WINDOW_S = float(os.getenv("STAFF_PRESCREEN_THROTTLE_WINDOW_S", "300"))
_THROTTLE_THRESHOLD = max(1, int(os.getenv("STAFF_PRESCREEN_THROTTLE_THRESHOLD", "3")))
_bypass_hits: dict[str, deque[float]] = {}


@dataclass
class PrescreenResult:
    """Outcome of a fail-safe pre-screen."""

    allowed: bool          # may the freetext enter the analysis context?
    blocked: bool = False  # filter positively said blocked=True (fail-CLOSED)
    bypassed: bool = False # filter unreachable → bypass, allowed but audited
    should_throttle: bool = False  # tenant crossed the bypass threshold this window
    bypass_count: int = 0  # bypasses for this tenant in the current window


def _record_bypass(tenant_id: str) -> tuple[int, bool]:
    """Bump the per-tenant sliding bypass counter; return (count, over_threshold)."""
    now = time.monotonic()
    dq = _bypass_hits.setdefault(tenant_id, deque())
    dq.append(now)
    cutoff = now - _THROTTLE_WINDOW_S
    while dq and dq[0] < cutoff:
        dq.popleft()
    count = len(dq)
    return count, count >= _THROTTLE_THRESHOLD


async def prescreen_freetext(
    text: str,
    tenant_id: str,
    *,
    agent_id: str = "",
    stage_detail: str = "",
) -> PrescreenResult:
    """
    Send *text* through `/filter`, fail-**safe**. Returns a :class:`PrescreenResult`.

    - filter clean  → ``allowed=True``
    - filter blocked → ``allowed=False, blocked=True`` (fail-CLOSED)
    - filter unreachable after bounded retries → ``allowed=True, bypassed=True`` with a
      `record_failopen` counter + structured audit + per-tenant throttle bump.
    """
    if not text:
        return PrescreenResult(allowed=True)

    import httpx  # noqa: PLC0415 — lazy, matches the rest of the staff tool layer

    last_exc: Exception | None = None
    for attempt in range(1, _ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_S) as c:
                r = await c.post(
                    "http://localhost:8001/filter",
                    json={"content": text[:_MAX_CHARS], "tenant_id": tenant_id},
                )
            if r.status_code == 200:
                if r.json().get("blocked"):
                    log.warning(
                        "STAFF prescreen: content BLOCKED by filter (injection) tenant=%s %s",
                        tenant_id, stage_detail,
                    )
                    return PrescreenResult(allowed=False, blocked=True)
                return PrescreenResult(allowed=True)
            # Non-200 is treated as a transient failure — retry, then bypass.
            last_exc = RuntimeError(f"filter returned HTTP {r.status_code}")
        except Exception as exc:  # noqa: BLE001 — any failure is retried, then bypassed
            last_exc = exc
        if attempt < _ATTEMPTS:
            log.debug("STAFF prescreen: attempt %d/%d failed, retrying: %r",
                      attempt, _ATTEMPTS, last_exc)

    # Bounded retries exhausted → fail-safe bypass: observable + throttled, still allowed.
    reason = Reason.TIMEOUT if isinstance(last_exc, (TimeoutError, )) else Reason.NETWORK_ERROR
    record_failopen(_STAGE, reason, last_exc)
    count, over = _record_bypass(tenant_id)
    emit(
        "injection_prescreen_bypassed",
        agent_id=agent_id or "staff",
        tenant_id=tenant_id,
        tool_name=stage_detail,
        status="degraded" if over else "bypassed",
        detail=(
            f"/filter unreachable after {_ATTEMPTS} attempts — freetext entered analysis "
            f"UNSCREENED (fail-safe bypass); tenant bypasses={count} in {_THROTTLE_WINDOW_S:.0f}s"
        ),
        extra={"bypass_count": count, "over_threshold": over, "reason": reason},
    )
    if over:
        log.warning(
            "STAFF prescreen: tenant=%s crossed bypass threshold (%d in %.0fs) — throttle recommended",
            tenant_id, count, _THROTTLE_WINDOW_S,
        )
    return PrescreenResult(
        allowed=True, bypassed=True, should_throttle=over, bypass_count=count
    )
