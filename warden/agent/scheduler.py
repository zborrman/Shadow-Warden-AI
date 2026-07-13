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

from warden.config import data_path, settings

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
        "(6) Business Community health digest: call community_moderation_report, "
        "summarise total posts, member count, NIM verdict breakdown (SAFE/WARN/BLOCK), "
        "and flag if any BLOCK verdicts appeared in the last 24 hours; "
        "(7) Obsidian vault digest: call get_obsidian_feed for community_id='default', "
        "report total notes shared, top data_class distribution, "
        "and flag any entries with data_class=CLASSIFIED or PHI; "
        "(8) recommended actions for today. "
        "Format as a structured Slack message with emojis and clear sections. "
        "Send it to Slack when done."
    )

    response = await _run(task, session_id="sched-morning-brief")
    log.info("sova: morning brief complete (%d chars)", len(response))
    return {"status": "ok", "ts": _ts(), "chars": len(response)}


async def sova_threat_sync(ctx: dict) -> dict:
    """
    Every 6 hours — refresh threat intelligence, synthesize new attacks,
    and cross-reference the community knowledge base.

    Triggers OSV CVE scan + ArXiv refresh. If new high-severity items
    found, alerts Slack immediately. Then searches the community feed for
    matching signatures and logs recommendations.
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

    # ── Community knowledge cross-reference ───────────────────────────────────
    # Search the community feed for jailbreak/injection/exfiltration signatures
    # that other tenants have already published and logged recommendations for.
    community_matches: list[dict] = []

    from warden.agent.tools import (  # noqa: PLC0415
        get_community_recommendations,
        search_community_feed,
    )
    tenant_id = settings.default_tenant_id
    keywords = ["jailbreak", "prompt injection", "exfiltration", "adversarial"]
    for kw in keywords:
        try:
            feed = await search_community_feed(query=kw, limit=3, tenant_id=tenant_id)
            hits = feed.get("results", [])
            if hits:
                recs = await get_community_recommendations(
                    incident_type=kw, risk_level="HIGH", tenant_id=tenant_id
                )
                community_matches.append({
                    "keyword":         kw,
                    "hits":            len(hits),
                    "top_ueciid":      hits[0].get("ueciid") if hits else None,
                    "recommendations": recs.get("recommendations", [])[:2],
                    "source":          recs.get("source", "mitre_fallback"),
                })
                log.info("threat sync: community feed '%s' → %d hits, recs=%s",
                         kw, len(hits), recs.get("source"))
        except Exception as exc:
            log.debug("threat sync: community search '%s' failed: %s", kw, exc)

    if community_matches:
        lines = []
        for m in community_matches:
            rec_text = "; ".join(m["recommendations"]) or "—"
            lines.append(
                f"• *{m['keyword']}*: {m['hits']} community entries — {rec_text}"
            )
        await _slack(
            f"*SOVA Community Threat Intel* [{_ts()}]\n"
            + "\n".join(lines)
            + f"\n_Source: community feed × {len(community_matches)} keywords_"
        )

    return {
        "status":            "ok",
        "ts":                _ts(),
        "chars":             len(response),
        "community_matches": len(community_matches),
    }


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


async def sova_community_watchdog(ctx: dict) -> dict:
    """
    Every hour — Business Community moderation watchdog.

    Fetches the pending moderation queue, blocks any post with a WARN score ≥ 0.85,
    re-queues stuck posts (pending > 30 min), and sends a Slack summary when
    the pending queue is non-empty.
    """
    log.info("sova: community watchdog [%s]", _ts())


    from warden.agent.tools import (  # noqa: PLC0415
        get_community_feed,
        moderate_community_post,
    )

    tenant_id = settings.default_tenant_id

    try:
        # Pull the last 100 approved to get verdict distribution stats
        feed = await get_community_feed(tenant_id=tenant_id, limit=100, status="approved")
        posts = feed.get("posts", [])
    except Exception as exc:
        log.warning("community watchdog: feed fetch failed: %s", exc)
        return {"status": "error", "ts": _ts(), "error": str(exc)}

    # Identify high-score WARN posts that slipped through
    auto_blocked = []
    for p in posts:
        if p.get("nim_verdict") == "WARN" and (p.get("nim_score") or 0) >= 0.85:
            result = await moderate_community_post(
                post_id=p["id"], action="block", tenant_id=tenant_id
            )
            if "error" not in result:
                auto_blocked.append(p["id"])
                log.info("community watchdog: auto-blocked %s (WARN score=%.2f)",
                         p["id"], p.get("nim_score", 0))

    block_verdicts = sum(1 for p in posts if p.get("nim_verdict") == "BLOCK")
    warn_verdicts  = sum(1 for p in posts if p.get("nim_verdict") == "WARN")

    if auto_blocked or block_verdicts:
        await _slack(
            f"*Community Watchdog* [{_ts()}]\n"
            f"• Auto-blocked (WARN≥0.85): {len(auto_blocked)}\n"
            f"• Total BLOCK verdict posts: {block_verdicts}\n"
            f"• Total WARN verdict posts:  {warn_verdicts}\n"
            f"• Approved posts sampled:    {len(posts)}"
        )

    log.info("community watchdog: complete — blocked=%d warn=%d",
             len(auto_blocked), warn_verdicts)
    return {
        "status":       "alerted" if (auto_blocked or block_verdicts) else "ok",
        "ts":           _ts(),
        "auto_blocked": len(auto_blocked),
        "block_verdicts": block_verdicts,
        "warn_verdicts":  warn_verdicts,
        "sampled":        len(posts),
    }


async def sova_corpus_watchdog(ctx: dict) -> dict:
    """
    Every 30 minutes — lightweight corpus and circuit breaker health check.

    Delegates to WardenHealer for structured anomaly detection.  Healer runs
    all checks directly via HTTP (no LLM) and sends targeted Slack alerts only
    when issues are found.
    """
    log.info("sova: corpus watchdog [%s]", _ts())


    from warden.agent.healer import WardenHealer  # noqa: PLC0415

    api_key = settings.warden_api_key
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

    from datetime import datetime  # noqa: PLC0415

    from warden.agent.tools import visual_assert_page  # noqa: PLC0415

    session_id = f"patrol-{datetime.now(UTC).strftime('%Y%m%d-%H%M')}"

    # ── Build target list ─────────────────────────────────────────────────────
    base_url   = settings.warden_base_url
    dashboard  = settings.dashboard_url
    extra_urls = [u.strip() for u in settings.patrol_urls.split(",") if u.strip()]

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


async def sova_tunnel_health_check(ctx: dict) -> dict:
    """
    Every 5 minutes — probe all ACTIVE and DEGRADED MASQUE sovereign tunnels.

    Calls probe_tunnel() for each tunnel and updates its status
    (ACTIVE → DEGRADED after 2 failures, DEGRADED → OFFLINE after 5).
    Sends a Slack alert when any tunnel transitions to DEGRADED or OFFLINE.
    """
    log.info("sova: tunnel health check [%s]", _ts())

    try:
        from warden.sovereign.tunnel import list_tunnels, probe_tunnel  # noqa: PLC0415
    except ImportError:
        log.debug("tunnel health check: sovereign module unavailable")
        return {"status": "skip", "ts": _ts(), "reason": "sovereign unavailable"}

    tunnels = [t for t in list_tunnels() if t.status in ("ACTIVE", "DEGRADED")]
    if not tunnels:
        return {"status": "ok", "ts": _ts(), "probed": 0}

    results: list[dict] = []
    degraded: list[str] = []
    offline:  list[str] = []

    for tunnel in tunnels:
        try:
            ok = await probe_tunnel(tunnel.tunnel_id)
            results.append({"id": tunnel.tunnel_id, "ok": ok, "jurisdiction": tunnel.jurisdiction})
            if not ok:
                if tunnel.status == "ACTIVE":
                    degraded.append(tunnel.tunnel_id)
                else:
                    offline.append(tunnel.tunnel_id)
        except Exception as exc:
            log.warning("tunnel health check: probe failed tunnel=%s err=%s", tunnel.tunnel_id, exc)

    import os as _os  # noqa: PLC0415

    import redis.asyncio as aioredis  # noqa: PLC0415
    redis_url = _os.getenv("REDIS_URL", "")
    if redis_url and redis_url != "memory://":
        try:
            r = aioredis.from_url(redis_url)
            await r.set("sova:tunnel_probe:last_run", _ts(), ex=600)
        except Exception:
            pass

    if degraded or offline:
        lines = []
        if degraded:
            lines.append(f"• DEGRADED: {', '.join(degraded)}")
        if offline:
            lines.append(f"• OFFLINE:  {', '.join(offline)}")
        await _slack(
            f"*MASQUE Tunnel Alert* [{_ts()}]\n"
            + "\n".join(lines)
            + f"\n_Probed {len(tunnels)} tunnel(s)_"
        )

    log.info("tunnel health check: probed=%d degraded=%d offline=%d",
             len(tunnels), len(degraded), len(offline))
    return {
        "status":  "alerted" if (degraded or offline) else "ok",
        "ts":      _ts(),
        "probed":  len(tunnels),
        "degraded": degraded,
        "offline":  offline,
    }


async def sova_trusted_entry_cron(ctx: dict) -> dict:
    """
    Daily 01:00 UTC — CM-24: award TRUSTED_ENTRY +3 to tenants whose SEP entries
    are ≥30 days old with no moderation actions taken against them.

    Only awards once per tenant per calendar day (idempotency via Redis key).
    """
    log.info("sova: trusted entry cron [%s]", _ts())

    import os  # noqa: PLC0415

    from warden.communities.reputation import (  # noqa: PLC0415
        award_trusted_entry_batch,
        get_trusted_entry_candidates,
    )

    r = None
    try:
        import redis.asyncio as aioredis  # noqa: PLC0415
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url and redis_url != "memory://":
            r = aioredis.from_url(redis_url)
    except Exception:
        pass

    today = _ts()[:10]  # YYYY-MM-DD
    dedup_key = f"sova:trusted_entry_ran:{today}"

    if r:
        try:
            already_ran = await r.exists(dedup_key)
            if already_ran:
                log.info("trusted entry cron: already ran today, skipping")
                return {"status": "skipped", "ts": _ts(), "reason": "already_ran"}
            await r.setex(dedup_key, 86_400, "1")
        except Exception:
            pass

    candidates = get_trusted_entry_candidates(min_age_days=30)
    if not candidates:
        log.info("trusted entry cron: no qualifying candidates")
        return {"status": "ok", "ts": _ts(), "awarded": 0}

    results = award_trusted_entry_batch(candidates)
    awarded = sum(1 for r_ in results if "error" not in r_)
    log.info("trusted entry cron: awarded TRUSTED_ENTRY +3 to %d tenants", awarded)

    if awarded:
        await _slack(
            f"*TRUSTED_ENTRY Cron* [{_ts()}]\n"
            f"• Awarded +3 TRUSTED_ENTRY to {awarded} community/communities\n"
            f"• Qualifying criteria: entries ≥30 days old, no moderation actions\n"
            f"• Candidates: {', '.join(candidates[:5])}{'...' if len(candidates) > 5 else ''}"
        )

    return {"status": "ok", "ts": _ts(), "awarded": awarded, "candidates": len(candidates)}


async def sova_overage_billing(ctx: dict) -> dict:
    """
    Monthly 00:05 UTC on the 1st — BL-19: compute and log overage charges
    for all tenants that exceeded their request quota.

    Reads quota usage from warden/billing/quota_middleware.py per tenant,
    computes overage charge at tier rate (Pro $0.50/1k, Enterprise $0.10/1k),
    and sends a Slack summary. Actual charging is delegated to Lemon Squeezy
    via /billing/overage/record (called with admin key in production).
    """
    log.info("sova: overage billing [%s]", _ts())


    try:
        from warden.billing.quota_middleware import (  # type: ignore[attr-defined]  # noqa: PLC0415
            list_all_tenants,
        )
    except ImportError:
        log.warning("overage billing: quota_middleware.list_all_tenants not available")
        return {"status": "skip", "ts": _ts(), "reason": "quota_middleware unavailable"}

    tenants     = list_all_tenants()
    overage_rows = []

    from warden.billing.router import _calculate_overage  # noqa: PLC0415

    for tenant_id in tenants:
        try:
            row = _calculate_overage(tenant_id)
            if row["overage_requests"] > 0:
                overage_rows.append(row)
                log.info(
                    "overage billing: tenant=%s overage=%d charge=$%.4f",
                    tenant_id, row["overage_requests"], row["charge_usd"],
                )
        except Exception as exc:
            log.debug("overage billing: tenant=%s error=%s", tenant_id, exc)

    total_charge = sum(r["charge_usd"] for r in overage_rows)

    if overage_rows:
        lines = [
            f"• `{r['tenant_id']}` ({r['plan']}) — {r['overage_requests']:,} overage → ${r['charge_usd']:.2f}"
            for r in overage_rows[:10]
        ]
        await _slack(
            f"*Overage Billing Summary* [{_ts()}]\n"
            + "\n".join(lines)
            + (f"\n_...and {len(overage_rows) - 10} more_" if len(overage_rows) > 10 else "")
            + f"\n_Total projected overage charge: ${total_charge:.2f}_"
        )

    return {
        "status":       "ok",
        "ts":           _ts(),
        "tenants":      len(tenants),
        "overage_count": len(overage_rows),
        "total_charge_usd": total_charge,
    }


async def sova_obsidian_watchdog(ctx: dict) -> dict:
    """
    Every 4 hours — Obsidian vault integrity check.

    Fetches the Obsidian integration stats and the 20 most recent shared
    entries.  Alerts Slack if:
      • Any entry has data_class CLASSIFIED or PHI (high-sensitivity leak risk)
      • More than 5 entries were shared in the last hour (spike detection)
      • The /obsidian/stats endpoint is unreachable (integration down)
    """
    log.info("sova: obsidian watchdog starting [%s]", _ts())

    from warden.agent.tools import get_obsidian_feed  # noqa: PLC0415

    tenant_id    = settings.default_tenant_id
    community_id = settings.obsidian_community_id

    try:
        feed = await get_obsidian_feed(
            community_id=community_id, limit=20, tenant_id=tenant_id
        )
        entries = feed.get("entries", [])
    except Exception as exc:
        await _slack(
            f"⚠️ *Obsidian Watchdog* [{_ts()}] — integration unreachable\n"
            f"Error: `{exc}`"
        )
        return {"status": "error", "ts": _ts(), "error": str(exc)}

    sensitive = [
        e for e in entries
        if e.get("content_type", "").upper() in ("CLASSIFIED", "PHI")
        or e.get("display_name", "").startswith("[CLASSIFIED]")
    ]

    alert_lines: list[str] = []
    if sensitive:
        alert_lines.append(
            f"• {len(sensitive)} high-sensitivity entry/entries detected "
            f"(CLASSIFIED/PHI): "
            + ", ".join(e.get("ueciid", "?") for e in sensitive[:3])
        )
    if len(entries) >= 15:
        alert_lines.append(
            f"• Share volume spike: {len(entries)} entries in the feed (threshold ≥ 15)"
        )

    if alert_lines:
        await _slack(
            f"🔴 *Obsidian Watchdog Alert* [{_ts()}]\n"
            + "\n".join(alert_lines)
            + f"\n_Community: `{community_id}` | Tenant: `{tenant_id}`_"
        )

    log.info("sova: obsidian watchdog complete — entries=%d sensitive=%d alerted=%s",
             len(entries), len(sensitive), bool(alert_lines))
    return {
        "status":    "alerted" if alert_lines else "ok",
        "ts":        _ts(),
        "entries":   len(entries),
        "sensitive": len(sensitive),
        "alerted":   bool(alert_lines),
    }


# ── sova_evidence_bundle — monthly 1st 03:00 UTC (TC-04) ─────────────────────

async def sova_evidence_bundle(ctx: dict) -> dict:
    """Auto-generate SOC 2 Type II evidence bundle for all Pro+ tenants."""
    tenant_ids_env = settings.evidence_bundle_tenants
    tenants = [t.strip() for t in tenant_ids_env.split(",") if t.strip()]

    results = []
    for tenant_id in tenants:
        try:
            from warden.compliance.evidence_bundle import generate_evidence_bundle  # noqa: PLC0415
            result = await generate_evidence_bundle(tenant_id)
            results.append({"tenant_id": tenant_id, "status": "ok", "key": result.get("key"), "size": result.get("size")})
            log.info("sova: evidence bundle generated — tenant=%s key=%s", tenant_id, result.get("key"))
        except Exception as exc:
            log.error("sova: evidence bundle failed — tenant=%s err=%s", tenant_id, exc)
            results.append({"tenant_id": tenant_id, "status": "error", "error": str(exc)})

    await _slack(
        f"📦 *Monthly Evidence Bundle* [{_ts()}]\n"
        + "\n".join(f"• `{r['tenant_id']}`: {r['status']}" for r in results)
    )
    return {"ts": _ts(), "results": results}


# ── sova_threat_feed_sync — every 4h (DET-03) ────────────────────────────────

async def sova_threat_feed_sync(ctx: dict) -> dict:
    """Sync MITRE ATLAS + OWASP LLM + HuggingFace feeds into EvolutionEngine."""
    try:
        from warden.brain.threat_feed import sync_threat_feeds  # noqa: PLC0415
        result = await sync_threat_feeds()
        log.info("sova: threat feed sync — fetched=%s injected=%s", result.get("fetched"), result.get("injected"))
        if result.get("injected", 0) > 0:
            await _slack(
                f"*Threat Feed Sync* [{_ts()}]\n"
                f"• Fetched: {result.get('fetched')} advisories\n"
                f"• Injected: {result.get('injected')} new examples\n"
                f"• Sources: ATLAS={result['sources'].get('atlas',0)} "
                f"OWASP={result['sources'].get('owasp_llm',0)} "
                f"HF={result['sources'].get('huggingface',0)}"
            )
        return result
    except Exception as exc:
        log.error("sova: threat feed sync failed — %s", exc)
        return {"status": "error", "error": str(exc)}


# ── sova_marketplace_state_sync — every 15 min (M2M loop continuity) ─────────

async def sova_marketplace_state_sync(ctx: dict) -> dict:
    """
    Every 15 minutes — write M2M marketplace loop state to data/AGENTS.md.

    Captures active negotiations, pending escrows, fairness metrics, and
    MAESTRO threat flags so subsequent ARQ runs and Claude Code sessions can
    resume from a consistent shared state (Loop Engineering pattern).
    Atomic write via tempfile + os.replace() to prevent corruption.
    """
    import os
    import tempfile
    from pathlib import Path

    log.info("sova: marketplace state sync [%s]", _ts())

    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    state_path = Path(settings.agents_md_path)

    negotiations: list[dict] = []
    escrows: list[dict] = []
    fairness: dict = {}
    maestro_flags: list[dict] = []

    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute(
            "SELECT negotiation_id, status, buyer_agent_id, seller_agent_id, rounds "
            "FROM marketplace_negotiations WHERE status='active' LIMIT 20"
        )
        negotiations = [dict(r) for r in cur.fetchall()]

        cur.execute(
            "SELECT escrow_id, status, amount_usd, buyer_agent_id, seller_agent_id "
            "FROM marketplace_escrows WHERE status IN ('pending_deposit','funded','disputed') LIMIT 20"
        )
        escrows = [dict(r) for r in cur.fetchall()]

        conn.close()
    except Exception as exc:
        log.debug("marketplace state sync: db read failed: %s", exc)

    try:
        from warden.marketplace.analytics import fairness_stats  # noqa: PLC0415
        fairness = fairness_stats(period_days=7, db_path=db_path)
    except Exception as exc:
        log.debug("marketplace state sync: fairness_stats failed: %s", exc)

    try:
        import redis.asyncio as aioredis  # noqa: PLC0415
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url and redis_url != "memory://":
            r = aioredis.from_url(redis_url)
            flags_raw = await r.lrange("maestro:flags:global", 0, 19)  # type: ignore[misc]
            import json
            maestro_flags = [json.loads(f) for f in flags_raw]
    except Exception as exc:
        log.debug("marketplace state sync: maestro flags fetch failed: %s", exc)

    lines = [
        "# AGENTS.md — M2M Marketplace Loop State",
        f"<!-- auto-generated by sova_marketplace_state_sync at {_ts()} -->",
        "",
        "## Active Negotiations",
        f"count: {len(negotiations)}",
    ]
    for n in negotiations[:10]:
        lines.append(
            f"- {n.get('negotiation_id','?')} | buyer={n.get('buyer_agent_id','?')} "
            f"seller={n.get('seller_agent_id','?')} rounds={n.get('rounds',0)}"
        )

    lines += [
        "",
        "## Pending / Funded Escrows",
        f"count: {len(escrows)}",
    ]
    for e in escrows[:10]:
        lines.append(
            f"- {e.get('escrow_id','?')} | status={e.get('status','?')} "
            f"amount=${e.get('amount_usd',0):.2f}"
        )

    lines += [
        "",
        "## Fairness Metrics (last 7d)",
        f"total_purchases: {fairness.get('total_purchases', 'n/a')}",
        f"avg_candidates_evaluated: {fairness.get('avg_candidates_evaluated', 'n/a')}",
        f"first_offer_acceptance_rate: {fairness.get('first_offer_acceptance_rate', 'n/a')}",
        f"min_offers_policy: {fairness.get('min_offers_policy', 'n/a')}",
        "",
        "## MAESTRO Threat Flags",
        f"count: {len(maestro_flags)}",
    ]
    for flag in maestro_flags[:5]:
        lines.append(
            f"- agent={flag.get('agent_id','?')} type={flag.get('flag_type','?')} "
            f"reason={flag.get('reason','?')[:80]}"
        )

    content = "\n".join(lines) + "\n"

    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=state_path.parent, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, state_path)
        log.info("marketplace state sync: wrote %s (%d bytes)", state_path, len(content))
    except Exception as exc:
        log.error("marketplace state sync: write failed: %s", exc)
        return {"status": "error", "ts": _ts(), "error": str(exc)}

    return {
        "status":       "ok",
        "ts":           _ts(),
        "negotiations": len(negotiations),
        "escrows":      len(escrows),
        "maestro_flags": len(maestro_flags),
        "bytes":        len(content),
    }


# ── sova_soc2_daily_collect — daily 00:00 UTC (SOC 2 Type II continuous evidence) ─

async def sova_soc2_daily_collect(ctx: dict) -> dict:
    """
    Daily midnight UTC — collect TSC-mapped SOC 2 Type II evidence for yesterday.

    Writes data/compliance_archives/YYYY-MM-DD_tsc.json atomically.
    Maps evidence to all 5 Trust Services Criteria:
      CC1-CC8  Security     — Confused-Deputy blocks, PQC auth failures
      A1       Availability — Uptime checks, DB pool health
      PI1      Integrity    — ClearingEngine Decimal math verification
      P1-P8    Privacy      — GDPR exports, E2EE activations
      C1       Confidentiality — PQC key ops, vault accesses
    """
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    # Collect for yesterday (the completed calendar day)
    yesterday = (datetime.now(UTC) - timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    try:
        from warden.compliance.soc2_collector import collect_daily_evidence  # noqa: PLC0415
        evidence = collect_daily_evidence(date=yesterday)
        tsc = evidence.get("tsc_evidence", {})
        summary = {
            "security_blocks":    tsc.get("security", {}).get("confused_deputy_block_count", 0),
            "clearings":          tsc.get("processing_integrity", {}).get("clearings_in_window", 0),
            "pi_violations":      tsc.get("processing_integrity", {}).get("decimal_violation_count", 0),
            "gdpr_exports":       tsc.get("privacy", {}).get("gdpr_export_count", 0),
            "availability_pct":   tsc.get("availability", {}).get("availability_pct"),
        }
        await _slack(
            f"📋 *SOC 2 Daily Evidence* [{yesterday.strftime('%Y-%m-%d')}]\n"
            f"• Security blocks: {summary['security_blocks']}\n"
            f"• Clearings verified: {summary['clearings']} "
            f"(violations: {summary['pi_violations']})\n"
            f"• GDPR exports: {summary['gdpr_exports']}\n"
            f"• Availability: {summary['availability_pct']}%"
        )
        log.info("soc2_collect: evidence written for %s", yesterday.date())
        return {"status": "ok", "date": yesterday.date().isoformat(), **summary}
    except Exception as exc:
        log.error("soc2_collect: failed for %s — %s", yesterday.date(), exc)
        await _slack(f"⚠️ *SOC 2 Evidence Collector FAILED* [{yesterday.date()}]: {exc}")
        return {"status": "error", "date": yesterday.date().isoformat(), "error": str(exc)}


async def sova_nightly_backup(ctx: dict) -> dict:
    """
    Nightly 03:30 UTC — Fernet-encrypted backup of every SQLite DB under
    WARDEN_DATA_DIR, with off-box ship to S3/MinIO when configured.

    Delegates to warden.backup.service.run_backup (single source of truth,
    shared with scripts/db_snapshot.py). Fail-CLOSED on VAULT_MASTER_KEY.
    A failed run is counted (record_failopen) and Slack-alerted, never silent.
    Runs off the event loop via asyncio.to_thread.
    """
    import asyncio  # noqa: PLC0415
    from datetime import UTC, datetime  # noqa: PLC0415

    from warden.observability import Reason, record_failopen  # noqa: PLC0415

    try:
        from warden.backup.service import run_backup  # noqa: PLC0415
        label = f"nightly-{datetime.now(UTC).strftime('%Y%m%d')}"
        snap_dir = await asyncio.to_thread(run_backup, label, ship=True)
        dbs = len(list(snap_dir.glob("*.db.enc")))
        log.info("nightly_backup: %d DBs → %s", dbs, snap_dir)
        if dbs == 0:
            await _slack("⚠️ *Nightly DB backup* produced 0 snapshots — check WARDEN_DATA_DIR.")
        return {"status": "ok", "snapshot": str(snap_dir), "dbs": dbs}
    except Exception as exc:
        log.error("nightly_backup: FAILED — %s", exc)
        record_failopen("backup_nightly", Reason.BACKEND_ERROR, exc)
        await _slack(f"🛑 *Nightly DB backup FAILED*: {exc}")
        return {"status": "error", "error": str(exc)}
