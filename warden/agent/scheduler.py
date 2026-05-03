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
  sova_corpus_watchdog    — every 30 minutes (delegates to WardenHealer)
  sova_visual_patrol      — daily 03:00 (ScreencastRecorder + Claude Vision → MinIO)
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

    Delegates to WardenHealer for structured anomaly detection.  Healer runs
    all checks directly via HTTP (no LLM) and sends targeted Slack alerts only
    when issues are found.
    """
    log.info("sova: corpus watchdog [%s]", _ts())

    import os  # noqa: PLC0415

    from warden.agent.healer import WardenHealer  # noqa: PLC0415

    api_key = os.getenv("WARDEN_API_KEY", "")
    try:
        report = await WardenHealer(api_key=api_key).run()
    except Exception as exc:
        log.error("sova watchdog: healer failed: %s", exc)
        return {"status": "error", "ts": _ts(), "error": str(exc)}

    log.info("sova watchdog: %s", report.summary())
    return {
        "status":      "alerted" if report.has_issues else "ok",
        "ts":          _ts(),
        "issues":      [a.result for a in report.actions if not a.success],
        "alerted":     report.alerted,
        "action_count": len(report.actions),
    }


# ── Patrol priority weights ───────────────────────────────────────────────────

class _PatrolWeights:
    """
    Redis-backed patrol priority weights.  Each URL starts at 1.0.
    Failures boost the weight (× 1.5, capped at 10); successes decay it
    (× 0.85) so frequently-failing routes get checked every run while
    stable ones gradually drop in priority.

    Falls back to an in-process dict when Redis is unavailable.
    """

    _KEY   = "sova:patrol_weights"
    _DECAY = 0.85
    _BOOST = 1.5
    _CAP   = 10.0
    _TTL   = 86_400 * 7   # 7 days

    def __init__(self) -> None:
        self._local: dict[str, float] = {}

    async def _redis(self):
        import os as _os  # noqa: PLC0415
        url = _os.getenv("REDIS_URL", "")
        if not url or url == "memory://":
            return None
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
            return aioredis.from_url(url)
        except Exception:
            return None

    async def load(self, urls: list[str]) -> dict[str, float]:
        weights: dict[str, float] = dict.fromkeys(urls, 1.0)
        r = await self._redis()
        if r:
            try:
                stored = await r.hgetall(self._KEY)
                for raw_k, raw_v in stored.items():
                    k = raw_k.decode() if isinstance(raw_k, bytes) else raw_k
                    if k in weights:
                        weights[k] = float(raw_v)
            except Exception:
                pass
        else:
            for u in urls:
                if u in self._local:
                    weights[u] = self._local[u]
        return weights

    async def update(self, url: str, success: bool) -> None:
        r = await self._redis()
        try:
            if r:
                raw = await r.hget(self._KEY, url)
                w = float(raw) if raw else 1.0
                w = w * self._DECAY if success else min(w * self._BOOST, self._CAP)
                await r.hset(self._KEY, url, round(w, 4))
                await r.expire(self._KEY, self._TTL)
            else:
                w = self._local.get(url, 1.0)
                w = w * self._DECAY if success else min(w * self._BOOST, self._CAP)
                self._local[url] = round(w, 4)
        except Exception as exc:
            log.debug("patrol weights update failed: %s", exc)


async def sova_visual_patrol(ctx: dict) -> dict:
    """
    Nightly 03:00 UTC — visual health patrol using Browser Bind + Claude Vision.

    Uses ScreencastRecorder to bind a named browser session to this job run,
    then calls visual_assert_page on key production endpoints.  Screenshots
    and the full WebM screencast are shipped to MinIO as SOC 2 evidence.

    Smart prioritization (v4.11): patrol targets are sorted by failure weight
    so frequently-failing routes are always checked first.  The run reports
    critical coverage % and sends a weighted summary to Slack.

    Endpoints patrolled (configurable via PATROL_URLS env var):
      • /health      — gateway liveness
      • Dashboard    — Streamlit analytics (if DASHBOARD_URL is set)
      • PATROL_URLS  — comma-separated extra URLs
    """
    log.info("sova: visual patrol starting [%s]", _ts())

    import os  # noqa: PLC0415
    from datetime import datetime  # noqa: PLC0415

    from warden.agent.tools import visual_assert_page  # noqa: PLC0415

    session_id = f"patrol-{datetime.now(UTC).strftime('%Y%m%d-%H%M')}"

    # ── Build target list ─────────────────────────────────────────────────────
    base_url   = os.getenv("WARDEN_BASE_URL", "http://localhost:8001")
    dashboard  = os.getenv("DASHBOARD_URL", "")
    extra_urls = [u.strip() for u in os.getenv("PATROL_URLS", "").split(",") if u.strip()]

    targets_raw: list[tuple[str, str]] = [
        (f"{base_url}/health", "Verify gateway health page is reachable and shows status=ok"),
    ]
    if dashboard:
        targets_raw.append((dashboard, "Verify analytics dashboard loads without errors"))
    for url in extra_urls:
        targets_raw.append((url, ""))

    # ── Load weights and sort by priority (highest weight = most urgent) ──────
    pw = _PatrolWeights()
    url_list = [u for u, _ in targets_raw]
    weights  = await pw.load(url_list)
    targets  = sorted(targets_raw, key=lambda t: weights.get(t[0], 1.0), reverse=True)

    log.info("patrol order: %s", [(u, f"w={weights.get(u,1.0):.2f}") for u, _ in targets])

    findings: list[dict] = []
    issues:   list[str]  = []

    # ── Run visual_assert_page for each target ────────────────────────────────
    async def _run_target(url: str, assertion: str) -> dict:
        result = await visual_assert_page(url=url, assertion=assertion)
        ok = result.get("ok", False) and "error" not in result.get("analysis", "").lower()
        await pw.update(url, success=ok)
        return result

    try:
        from warden.tools.browser import ScreencastRecorder  # noqa: PLC0415
        async with ScreencastRecorder(session_id):
            for url, assertion in targets:
                result = await _run_target(url, assertion)
                findings.append(result)
                if not result.get("ok"):
                    issues.append(f"{url}: {result.get('error', 'unknown error')}")
                elif "error" in result.get("analysis", "").lower():
                    issues.append(f"{url}: Vision flagged: {result['analysis'][:120]}")
                log.info("patrol: %s → ok=%s w=%.2f bytes=%s",
                         url, result.get("ok"), weights.get(url, 1.0),
                         result.get("screenshot_bytes"))
    except ImportError:
        log.warning("sova patrol: Playwright not available — skipping ScreencastRecorder")
        for url, assertion in targets:
            result = await _run_target(url, assertion)
            findings.append(result)
            if not result.get("ok"):
                issues.append(f"{url}: {result.get('error', 'unknown error')}")
    except Exception as exc:
        log.error("sova visual patrol: unexpected error: %s", exc)
        return {"status": "error", "ts": _ts(), "error": str(exc)}

    # ── Coverage report ───────────────────────────────────────────────────────
    # "Critical" = weight > 2 (has failed at least once recently)
    critical_urls    = [u for u in url_list if weights.get(u, 1.0) > 2.0]
    critical_checked = sum(1 for u in critical_urls if any(f.get("url") == u for f in findings))
    coverage_pct     = (critical_checked / len(critical_urls) * 100) if critical_urls else 100.0

    # ── Alert if issues found ─────────────────────────────────────────────────
    if issues:
        weight_summary = " | ".join(
            f"{u.split('/')[-1] or 'root'}: w={weights.get(u, 1.0):.1f}"
            for u, _ in targets[:5]
        )
        await _slack(
            f"*SOVA Visual Patrol Alert* [{_ts()}] `{session_id}`\n"
            + "\n".join(f"• {i}" for i in issues)
            + f"\n_Priority weights: {weight_summary}_"
            + f"\n_Critical coverage: {coverage_pct:.0f}% ({critical_checked}/{len(critical_urls)})_"
        )

    log.info("sova: visual patrol complete — %d targets, %d issues, coverage=%.0f%%",
             len(targets), len(issues), coverage_pct)
    return {
        "status":           "alerted" if issues else "ok",
        "ts":               _ts(),
        "session_id":       session_id,
        "targets":          len(targets),
        "issues":           issues,
        "critical_coverage_pct": coverage_pct,
        "weights":          {u: round(weights.get(u, 1.0), 2) for u in url_list},
    }
