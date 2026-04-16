"""
warden/agent/healer.py
━━━━━━━━━━━━━━━━━━━━━
WardenHealer — lightweight autonomous self-healing agent.

Runs after the corpus watchdog detects anomalies or on demand from SOVA.
Performs direct HTTP probes against localhost:8001 — no LLM overhead on the
happy path.

Failure modes handled
─────────────────────
  1. Circuit breaker OPEN         → alert Slack with cooldown remaining
  2. High bypass rate (>15%)      → alert with recent block stats
  3. Gateway unreachable / 500    → alert; marks all checks failed
  4. Corpus DEGRADED (audit trail)→ alert with rebuild instructions
  5. Canary probe blocked         → safe "What is 2+2?" should always pass

Each check produces a HealAction (target, action, result, success).
All actions are fire-and-forget Slack alerts; no destructive side-effects.

Usage
─────
    from warden.agent.healer import WardenHealer
    report = await WardenHealer().run()
    print(report.summary())
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

log = logging.getLogger("warden.agent.healer")

_BASE    = "http://localhost:8001"
_TIMEOUT = 10.0


def _ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class HealAction:
    target:  str
    action:  str
    result:  str
    success: bool


@dataclass
class HealReport:
    ts:      str              = field(default_factory=_ts)
    actions: list[HealAction] = field(default_factory=list)
    alerted: bool             = False

    @property
    def has_issues(self) -> bool:
        return any(not a.success for a in self.actions)

    @property
    def healed(self) -> bool:
        return any(a.success for a in self.actions)

    def summary(self) -> str:
        status = "HEALED" if self.healed else ("ISSUES" if self.has_issues else "HEALTHY")
        lines = [f"[{status}] WardenHealer @ {self.ts}"]
        for a in self.actions:
            icon = "✓" if a.success else "✗"
            lines.append(f"  {icon} [{a.target}] {a.action}")
            lines.append(f"     → {a.result}")
        return "\n".join(lines)


# ── Healer ─────────────────────────────────────────────────────────────────────

class WardenHealer:
    """
    Autonomous self-healing agent — probes the gateway and alerts on anomalies.

    All checks are independent; a failure in one does not stop the others.
    Slack alerts are sent only when at least one check finds an issue.
    """

    def __init__(self, api_key: str = "") -> None:
        self._headers = {"X-API-Key": api_key} if api_key else {}

    async def run(self) -> HealReport:
        """Run all health checks and return a consolidated HealReport."""
        report = HealReport()

        health = await self._fetch_health(report)
        if health is not None:
            self._check_circuit_breaker(health, report)
            self._check_bypass_rate(health, report)
            self._check_corpus(health, report)
            await self._run_canary_probe(report)

        if report.has_issues:
            report.alerted = await self._send_alert(report)

        log.info("healer: run complete — issues=%s alerted=%s actions=%d",
                 report.has_issues, report.alerted, len(report.actions))
        return report

    # ── Checks ────────────────────────────────────────────────────────────────

    async def _fetch_health(self, report: HealReport) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(f"{_BASE}/health", headers=self._headers)
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            report.actions.append(HealAction(
                target="gateway",
                action="health check",
                result=f"UNREACHABLE: {exc}",
                success=False,
            ))
            return None

    def _check_circuit_breaker(self, health: dict, report: HealReport) -> None:
        cb = health.get("circuit_breaker", {})
        status = cb.get("status", "unknown")
        if status == "open":
            cooldown = cb.get("cooldown_remaining_s", 0)
            bypasses = cb.get("bypasses_in_window", 0)
            report.actions.append(HealAction(
                target="circuit_breaker",
                action="check status",
                result=(
                    f"OPEN — {bypasses} bypasses in window, "
                    f"auto-reset in {cooldown}s. "
                    "No action needed; circuit resets automatically via Redis TTL."
                ),
                success=False,
            ))
        else:
            report.actions.append(HealAction(
                target="circuit_breaker",
                action="check status",
                result=f"OK (status={status})",
                success=True,
            ))

    def _check_bypass_rate(self, health: dict, report: HealReport) -> None:
        rate = health.get("bypass_rate_1m", 0.0)
        bypasses = health.get("bypasses_1m", 0)
        rps = health.get("filter_rps_1m", 0.0)
        if rate > 0.15:
            report.actions.append(HealAction(
                target="bypass_rate",
                action="anomaly detection",
                result=(
                    f"HIGH: {rate:.1%} bypass rate in last 60s "
                    f"({bypasses} bypasses, {rps:.1f} req/s). "
                    "Possible attack wave — check logs for source IP/tenant."
                ),
                success=False,
            ))
        else:
            report.actions.append(HealAction(
                target="bypass_rate",
                action="anomaly detection",
                result=f"OK ({rate:.1%} bypass rate, {rps:.1f} req/s)",
                success=True,
            ))

    def _check_corpus(self, health: dict, report: HealReport) -> None:
        # The audit trail status is surfaced in /health overall status.
        # DEGRADED = audit trail DB inaccessible or corpus snapshot mismatch.
        overall = health.get("status", "ok")
        if overall == "degraded":
            cache_status = health.get("cache", {}).get("status", "unknown")
            cb_status = health.get("circuit_breaker", {}).get("status", "closed")
            # Attribute to corpus only if CB is closed (not a CB-induced degraded)
            if cb_status != "open":
                report.actions.append(HealAction(
                    target="corpus/audit",
                    action="degraded detection",
                    result=(
                        f"DEGRADED — overall={overall} cache={cache_status}. "
                        "If corpus snapshot is stale: "
                        "`docker exec warden rm -f /warden/data/corpus_snapshot.npz` "
                        "then restart warden service to force rebuild."
                    ),
                    success=False,
                ))
                return
        report.actions.append(HealAction(
            target="corpus/audit",
            action="degraded detection",
            result=f"OK (status={overall})",
            success=True,
        ))

    async def _run_canary_probe(self, report: HealReport) -> None:
        """Send a safe canary request — should always be allowed with LOW risk."""
        payload = {"content": "What is 2 + 2?", "tenant_id": "default"}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.post(
                    f"{_BASE}/filter",
                    json=payload,
                    headers={**self._headers, "Content-Type": "application/json"},
                )
                body = r.json() if r.status_code < 500 else {}
                allowed = body.get("allowed", False)
                risk = body.get("risk_level", "?")
                if allowed and risk.upper() in ("LOW", "MEDIUM"):
                    report.actions.append(HealAction(
                        target="pipeline",
                        action="canary probe",
                        result=f"OK (allowed={allowed} risk={risk})",
                        success=True,
                    ))
                else:
                    report.actions.append(HealAction(
                        target="pipeline",
                        action="canary probe",
                        result=(
                            f"UNEXPECTED RESULT: allowed={allowed} risk={risk} "
                            f"HTTP {r.status_code} — pipeline may be misconfigured."
                        ),
                        success=False,
                    ))
        except Exception as exc:
            report.actions.append(HealAction(
                target="pipeline",
                action="canary probe",
                result=f"FAILED: {exc}",
                success=False,
            ))

    # ── Alert ─────────────────────────────────────────────────────────────────

    async def _send_alert(self, report: HealReport) -> bool:
        from warden.agent.tools import send_slack_alert

        lines = [f"*WardenHealer Alert* [{report.ts}]"]
        for a in report.actions:
            if not a.success:
                lines.append(f"• *{a.target}*: {a.result}")

        try:
            result = await send_slack_alert(message="\n".join(lines))
            return bool(result.get("sent"))
        except Exception as exc:
            log.warning("healer: slack alert failed: %s", exc)
            return False
