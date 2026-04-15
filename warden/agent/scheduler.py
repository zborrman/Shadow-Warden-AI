"""
warden/agent/scheduler.py
──────────────────────────
SOVA ARQ scheduled job functions.

These are registered in warden/workers/settings.py alongside the
existing reaper and weekly-report jobs.

Cron schedule (UTC)
────────────────────
  sova_morning_brief      — daily 08:00
  sova_threat_sync        — every 6 hours (00, 06, 12, 18)
  sova_rotation_check     — daily 02:00
  sova_sla_report         — every Monday 09:00
  sova_upgrade_scan       — every Sunday 10:00
  sova_corpus_watchdog    — every 30 minutes
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

log = logging.getLogger("warden.agent.scheduler")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


async def _run(task: str, session_id: str) -> str:
    from warden.agent.sova import run_task
    try:
        return await run_task(task, session_id=session_id)
    except Exception as exc:
        log.error("sova scheduler: task='%s' error: %s", task[:60], exc)
        return f"SOVA error: {exc}"


async def _slack(msg: str) -> None:
    from warden.agent.tools import send_slack_alert
    try:
        await send_slack_alert(message=msg)
    except Exception as exc:
        log.debug("sova: slack send failed: %s", exc)


# ── Job functions (ARQ signature: async def fn(ctx: dict) -> ...) ─────────────

async def sova_morning_brief(ctx: dict) -> dict:
    """
    Daily 08:00 UTC — comprehensive security and operations brief.

    Checks: health, stats (last 24h), top threats, SLA status,
    corpus health, new CVEs/ArXiv papers, ROI snapshot.
    Posts summary to Slack.
    """
    log.info("sova: morning brief starting [%s]", _ts())

    task = (
        "Generate a comprehensive morning operations brief for Shadow Warden. "
        "Include: (1) gateway health and 24h filter stats with block rate; "
        "(2) top 3 threat intelligence items (CVEs + ArXiv attacks); "
        "(3) uptime monitor summary — any incidents or degraded services; "
        "(4) financial: cost saved and ROI snapshot; "
        "(5) any communities with key rotation overdue (>90 days); "
        "(6) recommended actions for today. "
        "Format as a structured Slack message with emojis and clear sections. "
        "Send it to Slack when done."
    )

    response = await _run(task, session_id="sched-morning-brief")
    log.info("sova: morning brief complete (%d chars)", len(response))
    return {"status": "ok", "ts": _ts(), "chars": len(response)}


async def sova_threat_sync(ctx: dict) -> dict:
    """
    Every 6 hours — refresh threat intelligence and synthesize new attacks.

    Triggers OSV CVE scan + ArXiv refresh. If new high-severity items
    found, alerts Slack immediately.
    """
    log.info("sova: threat sync starting [%s]", _ts())

    task = (
        "Perform a threat intelligence sync: "
        "(1) Trigger a threat intel refresh (OSV CVE + ArXiv); "
        "(2) List any NEW high-severity CVEs or critical ArXiv LLM-attack papers discovered; "
        "(3) For each critical finding, describe the attack vector and recommended mitigation; "
        "(4) If any CRITICAL severity items exist, send a Slack alert with details. "
        "Be specific about CVE IDs and paper titles."
    )

    response = await _run(task, session_id="sched-threat-sync")
    log.info("sova: threat sync complete (%d chars)", len(response))
    return {"status": "ok", "ts": _ts(), "chars": len(response)}


async def sova_rotation_check(ctx: dict) -> dict:
    """
    Daily 02:00 UTC — check all communities for key rotation policy compliance.

    Initiates rotation for any community whose active key is >90 days old
    or has pending rotation_required flag. Logs all actions.
    """
    log.info("sova: rotation check starting [%s]", _ts())

    task = (
        "Perform a key rotation compliance audit for all Business Communities. "
        "For each community: "
        "(1) Check the active kid version and how long it has been active; "
        "(2) If the key is older than 90 days, initiate a rotation immediately; "
        "(3) Check if any rotation is currently in progress and report done/total/failed; "
        "(4) List any communities with failed rotation entities that need manual attention. "
        "Report all actions taken with community IDs and key versions."
    )

    response = await _run(task, session_id="sched-rotation-check")
    log.info("sova: rotation check complete (%d chars)", len(response))
    return {"status": "ok", "ts": _ts(), "chars": len(response)}


async def sova_sla_report(ctx: dict) -> dict:
    """
    Every Monday 09:00 UTC — weekly SLA compliance report.

    Aggregates 7-day uptime % across all monitors, compares against
    SLA thresholds (Pro 99.9% / Enterprise 99.95%), posts to Slack.
    """
    log.info("sova: SLA report starting [%s]", _ts())

    task = (
        "Generate a weekly SLA compliance report for the past 7 days. "
        "For all uptime monitors: "
        "(1) Get 168-hour uptime % and average latency for each; "
        "(2) Flag any monitor below 99.9% uptime (SLA breach); "
        "(3) Identify the worst 3 incidents (longest downtime periods); "
        "(4) Calculate P99 latency from history samples; "
        "(5) Send the full report to Slack with a clear pass/fail verdict per service. "
        "Include specific numbers — uptime %, latency ms, incident durations."
    )

    response = await _run(task, session_id="sched-sla-report")
    log.info("sova: SLA report complete (%d chars)", len(response))
    return {"status": "ok", "ts": _ts(), "chars": len(response)}


async def sova_upgrade_scan(ctx: dict) -> dict:
    """
    Every Sunday 10:00 UTC — scan tenants approaching quota limits.

    Identifies tenants at >80% of monthly quota. Generates upsell
    context for the sales team and posts to Slack.
    """
    log.info("sova: upgrade scan starting [%s]", _ts())

    task = (
        "Perform a tenant upgrade opportunity scan. "
        "(1) Check billing quota usage for all active tenants; "
        "(2) Identify tenants using more than 80% of their monthly quota; "
        "(3) For each identified tenant, get their tenant impact data (blocks blocked, ROI); "
        "(4) Draft a brief upsell context for each: current plan, usage %, key metrics that "
        "demonstrate value delivered; "
        "(5) Post the upgrade candidate list to Slack with recommended tier upgrades."
    )

    response = await _run(task, session_id="sched-upgrade-scan")
    log.info("sova: upgrade scan complete (%d chars)", len(response))
    return {"status": "ok", "ts": _ts(), "chars": len(response)}


async def sova_corpus_watchdog(ctx: dict) -> dict:
    """
    Every 30 minutes — lightweight corpus and circuit breaker health check.

    Does NOT use the full SOVA loop — reads health directly and alerts
    on anomalies without LLM overhead. Falls back to SOVA only if
    action is needed.
    """
    log.info("sova: corpus watchdog [%s]", _ts())

    from warden.agent.tools import get_health, send_slack_alert
    try:
        health = await get_health()
    except Exception as exc:
        log.warning("sova watchdog: health check failed: %s", exc)
        return {"status": "error", "ts": _ts(), "error": str(exc)}

    alerts = []

    # Circuit breaker open?
    cb = health.get("circuit_breaker", {})
    if cb.get("status") == "open":
        cooldown = cb.get("cooldown_remaining_s", 0)
        alerts.append(f"🔴 *Circuit Breaker OPEN* — {cb.get('bypasses_in_window', 0)} bypasses, "
                      f"cooldown {cooldown}s remaining")

    # High bypass rate?
    bypass_rate = health.get("bypass_rate_1m", 0)
    if bypass_rate > 0.15:
        alerts.append(f"⚠️ *High bypass rate* — {bypass_rate:.1%} in last minute")

    if alerts:
        msg = f"*SOVA Watchdog Alert* [{_ts()}]\n" + "\n".join(alerts)
        await send_slack_alert(message=msg)
        log.warning("sova watchdog: alerts sent: %s", alerts)

    return {
        "status":      "ok" if not alerts else "alerted",
        "ts":          _ts(),
        "alerts":      len(alerts),
        "cb_status":   cb.get("status", "unknown"),
        "bypass_rate": bypass_rate,
    }
