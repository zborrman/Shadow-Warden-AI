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

Proactive intelligence (v4.11)
──────────────────────────────
  6. Trend prediction             → linear extrapolation of bypass_rate;
                                    preemptive Slack alert if >15% predicted
                                    within the next ~1.5 hours
  7. LLM incident classification  → on anomaly, Haiku classifies incident type
                                    and generates a 3-step remediation plan
  8. Recipe cache                 → successful remedy templates stored in SQLite
                                    and reused on identical incident fingerprints

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
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Generator

import httpx

log = logging.getLogger("warden.agent.healer")

_BASE    = "http://localhost:8001"
_TIMEOUT = 10.0

# Trend analysis parameters
_TREND_WINDOW   = 12   # lookback: last 12 readings (~6h at 30-min watchdog interval)
_PREDICT_AHEAD  = 3    # forecast 3 readings ahead (~1.5h)
_BYPASS_LIMIT   = 0.15

# SQLite file for rolling metrics + recipe cache
_METRICS_DB = os.getenv("HEALER_METRICS_DB", "/tmp/warden_healer_metrics.db")


def _ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


# ── SQLite helpers ─────────────────────────────────────────────────────────────

@contextmanager
def _db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(_METRICS_DB, timeout=5)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bypass_metrics (
                ts           INTEGER,
                bypass_rate  REAL,
                filter_rps   REAL,
                cb_status    TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_recipes (
                fingerprint  TEXT PRIMARY KEY,
                remedy       TEXT,
                used_count   INTEGER DEFAULT 0,
                last_used    INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        yield conn
    finally:
        conn.close()


def _record_metric(bypass_rate: float, filter_rps: float, cb_status: str) -> None:
    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO bypass_metrics VALUES (?,?,?,?)",
                (int(time.time()), bypass_rate, filter_rps, cb_status),
            )
            cutoff = int(time.time()) - 48 * 3600
            conn.execute("DELETE FROM bypass_metrics WHERE ts < ?", (cutoff,))
            conn.commit()
    except Exception as exc:
        log.debug("healer: metric record failed: %s", exc)


def _recent_bypass_rates(n: int = _TREND_WINDOW) -> list[float]:
    try:
        with _db() as conn:
            rows = conn.execute(
                "SELECT bypass_rate FROM bypass_metrics ORDER BY ts DESC LIMIT ?", (n,)
            ).fetchall()
            return [r[0] for r in reversed(rows)]
    except Exception:
        return []


def _linear_trend(values: list[float], ahead: int = _PREDICT_AHEAD) -> float:
    """OLS linear extrapolation. Returns predicted value `ahead` steps into the future."""
    n = len(values)
    if n < 2:
        return values[-1] if values else 0.0
    xs = list(range(n))
    x_mean = sum(xs) / n
    y_mean = sum(values) / n
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, values))
    den = sum((x - x_mean) ** 2 for x in xs)
    slope = num / den if den != 0 else 0.0
    return y_mean + slope * (n - 1 - x_mean + ahead)


def _load_recipe(fingerprint: str) -> str | None:
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT remedy FROM incident_recipes WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE incident_recipes SET used_count=used_count+1, last_used=? WHERE fingerprint=?",
                    (int(time.time()), fingerprint),
                )
                conn.commit()
                return row[0]
    except Exception:
        pass
    return None


def _save_recipe(fingerprint: str, remedy: str) -> None:
    try:
        with _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO incident_recipes VALUES (?,?,0,?)",
                (fingerprint, remedy, int(time.time())),
            )
            conn.commit()
    except Exception as exc:
        log.debug("healer: recipe save failed: %s", exc)


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class HealAction:
    target:  str
    action:  str
    result:  str
    success: bool


@dataclass
class HealReport:
    ts:                     str              = field(default_factory=_ts)
    actions:                list[HealAction] = field(default_factory=list)
    alerted:                bool             = False
    incident_classification: str             = ""

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
        if self.incident_classification:
            lines.append("  ── LLM Classification ──")
            for line in self.incident_classification.splitlines():
                lines.append(f"  {line}")
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
            self._check_trend_prediction(health, report)

        if report.has_issues:
            classification = await self._llm_classify_incident(report, health or {})
            if classification:
                report.incident_classification = classification
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
        if rate > _BYPASS_LIMIT:
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
        overall = health.get("status", "ok")
        if overall == "degraded":
            cache_status = health.get("cache", {}).get("status", "unknown")
            cb_status = health.get("circuit_breaker", {}).get("status", "closed")
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

    def _check_trend_prediction(self, health: dict, report: HealReport) -> None:
        """
        Record current bypass_rate to the rolling metric store, then run a
        linear trend forecast.  If the predicted value exceeds the bypass
        threshold while the current value is still safe, add a WARN action
        so the Slack alert fires early (preemptive notice).
        """
        bypass_rate = health.get("bypass_rate_1m", 0.0)
        cb_status   = health.get("circuit_breaker", {}).get("status", "closed")
        filter_rps  = health.get("filter_rps_1m", 0.0)

        _record_metric(bypass_rate, filter_rps, cb_status)

        rates = _recent_bypass_rates()
        if len(rates) < 4:
            return

        predicted = _linear_trend(rates)
        horizon_min = _PREDICT_AHEAD * 30   # watchdog runs every 30 min

        if predicted > _BYPASS_LIMIT and bypass_rate <= _BYPASS_LIMIT:
            report.actions.append(HealAction(
                target="trend_prediction",
                action="bypass rate forecast",
                result=(
                    f"WARN: bypass rate trending up — current={bypass_rate:.1%} "
                    f"predicted={predicted:.1%} in ~{horizon_min}min. "
                    "Preemptive alert issued before threshold is breached."
                ),
                success=False,
            ))
        else:
            report.actions.append(HealAction(
                target="trend_prediction",
                action="bypass rate forecast",
                result=f"OK (current={bypass_rate:.1%} predicted={predicted:.1%})",
                success=True,
            ))

    # ── LLM incident classification ───────────────────────────────────────────

    async def _llm_classify_incident(
        self, report: HealReport, health: dict
    ) -> str:
        """
        Use Claude Haiku to classify the incident and suggest a 3-step remedy.

        Returns a cached recipe when the same incident fingerprint has been
        seen before.  Saves a new recipe on first classification so subsequent
        identical incidents skip the LLM entirely.
        """
        failed_targets = sorted(a.target for a in report.actions if not a.success)
        fingerprint    = "|".join(failed_targets)

        cached = _load_recipe(fingerprint)
        if cached:
            log.info("healer: cached recipe for '%s'", fingerprint)
            return cached

        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return ""

        issues_text = "\n".join(
            f"- {a.target}: {a.result}" for a in report.actions if not a.success
        )
        health_snap = {
            "status":      health.get("status"),
            "bypass_rate": health.get("bypass_rate_1m"),
            "cb_status":   health.get("circuit_breaker", {}).get("status"),
            "bypasses_1m": health.get("bypasses_1m"),
        }

        classify_prompt = (
            "You are an SRE incident classifier for an AI security gateway.\n\n"
            f"Health snapshot: {health_snap}\n\n"
            f"Active issues:\n{issues_text}\n\n"
            "Classify this incident into exactly one type:\n"
            "  resource_exhaustion | deploy_regression | network_partition | "
            "data_corruption | attack_wave | unknown\n\n"
            "Provide a concise 3-step remediation plan. Respond in this exact format:\n"
            "INCIDENT_TYPE: <type>\n"
            "STEPS:\n1. ...\n2. ...\n3. ..."
        )

        try:
            import anthropic as _anthropic
            client = _anthropic.AsyncAnthropic(api_key=api_key)
            msg = await client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=256,
                messages=[{"role": "user", "content": classify_prompt}],
            )
            remedy = msg.content[0].text.strip() if msg.content else ""
            if remedy:
                _save_recipe(fingerprint, remedy)
                log.info("healer: LLM classified '%s' — recipe saved", fingerprint)
            return remedy
        except Exception as exc:
            log.warning("healer: LLM classify failed: %s", exc)
            return ""

    # ── Alert ─────────────────────────────────────────────────────────────────

    async def _send_alert(self, report: HealReport) -> bool:
        from warden.agent.tools import send_slack_alert

        lines = [f"*WardenHealer Alert* [{report.ts}]"]
        for a in report.actions:
            if not a.success:
                lines.append(f"• *{a.target}*: {a.result}")
        if report.incident_classification:
            lines.append(f"```\n{report.incident_classification}\n```")

        try:
            result = await send_slack_alert(message="\n".join(lines))
            return bool(result.get("sent"))
        except Exception as exc:
            log.warning("healer: slack alert failed: %s", exc)
            return False
