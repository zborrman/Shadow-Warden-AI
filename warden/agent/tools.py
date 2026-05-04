"""
warden/agent/tools.py
──────────────────────
SOVA tool implementations — thin HTTP wrappers over the internal API.

All tools call localhost:8001 with the internal WARDEN_API_KEY so the
full pipeline (auth, rate-limit, audit) is exercised identically to
external callers.  Results are returned as dicts for the agent to reason
over.

Tool registry
─────────────
  TOOLS          — Anthropic-format tool definitions (name/description/schema)
  TOOL_HANDLERS  — {name: async callable}
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

log = logging.getLogger("warden.agent.tools")

_BASE      = "http://localhost:8001"
_API_KEY   = os.getenv("WARDEN_API_KEY", "")
_TIMEOUT   = 30.0


def _headers(tenant: str = "default") -> dict:
    return {
        "X-API-Key":   _API_KEY,
        "X-Tenant-ID": tenant,
        "Content-Type": "application/json",
    }


async def _get(path: str, tenant: str = "default", params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(f"{_BASE}{path}", headers=_headers(tenant), params=params or {})
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict, tenant: str = "default") -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{_BASE}{path}", json=body, headers=_headers(tenant))
        r.raise_for_status()
        return r.json()


async def _delete(path: str, tenant: str = "default") -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.delete(f"{_BASE}{path}", headers=_headers(tenant))
        if r.status_code == 204:
            return {"deleted": True}
        r.raise_for_status()
        return r.json()


async def _patch(path: str, body: dict, tenant: str = "default") -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.patch(f"{_BASE}{path}", json=body, headers=_headers(tenant))
        r.raise_for_status()
        return r.json()


# ── Tool handlers ─────────────────────────────────────────────────────────────

async def get_health(**_) -> dict:
    return await _get("/health")


async def get_stats(tenant_id: str = "default", **_) -> dict:
    return await _get("/api/stats", tenant=tenant_id)


async def get_config(tenant_id: str = "default", **_) -> dict:
    return await _get("/api/config", tenant=tenant_id)


async def update_config(changes: dict, tenant_id: str = "default", **_) -> dict:
    return await _post("/api/config", changes, tenant=tenant_id)


async def list_threats(type_filter: str = "", tenant_id: str = "default", **_) -> dict:
    params = {"type": type_filter} if type_filter else {}
    return await _get("/threats/intel", tenant=tenant_id, params=params)


async def refresh_threat_intel(tenant_id: str = "default", **_) -> dict:
    return await _post("/threats/intel/refresh", {}, tenant=tenant_id)


async def dismiss_threat(item_id: str, tenant_id: str = "default", **_) -> dict:
    return await _post(f"/threats/intel/{item_id}/dismiss", {}, tenant=tenant_id)


async def list_communities(tenant_id: str = "default", **_) -> dict:
    return await _get("/communities", tenant=tenant_id)


async def get_community(community_id: str, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/communities/{community_id}", tenant=tenant_id)


async def rotate_community_key(community_id: str, tenant_id: str = "default", **_) -> dict:
    return await _post(f"/communities/{community_id}/rotate", {}, tenant=tenant_id)


async def get_rotation_progress(community_id: str, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/communities/{community_id}/rotation", tenant=tenant_id)


async def list_community_members(community_id: str, tenant_id: str = "default", **_) -> list:
    return await _get(f"/communities/{community_id}/members", tenant=tenant_id)


async def list_monitors(tenant_id: str = "default", **_) -> list:
    return await _get("/monitors/", tenant=tenant_id)


async def get_monitor_status(monitor_id: str, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/monitors/{monitor_id}/status", tenant=tenant_id)


async def get_monitor_uptime(monitor_id: str, hours: int = 24, tenant_id: str = "default", **_) -> dict:
    return await _get(f"/monitors/{monitor_id}/uptime", tenant=tenant_id, params={"hours": hours})


async def get_monitor_history(monitor_id: str, limit: int = 20, tenant_id: str = "default", **_) -> list:
    return await _get(f"/monitors/{monitor_id}/history", tenant=tenant_id, params={"limit": limit})


async def get_financial_impact(tenant_id: str = "default", **_) -> dict:
    return await _get("/financial/impact", tenant=tenant_id)


async def get_cost_saved(tenant_id: str = "default", **_) -> dict:
    return await _get("/financial/cost-saved", tenant=tenant_id)


async def get_billing_quota(tenant_id: str = "default", **_) -> dict:
    return await _get("/billing/quota", tenant=tenant_id)


async def generate_proposal(company_name: str, tenant_id: str = "default", **_) -> dict:
    return await _post("/financial/generate-proposal", {"company_name": company_name}, tenant=tenant_id)


async def list_agents(tenant_id: str = "default", **_) -> list:
    return await _get(f"/agents?tenant_id={tenant_id}", tenant=tenant_id)


async def get_agent_activity(limit: int = 50, tenant_id: str = "default", **_) -> list:
    return await _get("/agents/activity", tenant=tenant_id, params={"limit": limit})


async def revoke_agent(agent_id: str, tenant_id: str = "default", **_) -> dict:
    return await _delete(f"/agents/{agent_id}", tenant=tenant_id)


async def get_tenant_impact(tenant_id: str = "default", **_) -> dict:
    return await _get("/tenant/impact", tenant=tenant_id)


async def send_slack_alert(message: str, **_) -> dict:
    url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not url:
        return {"sent": False, "reason": "SLACK_WEBHOOK_URL not configured"}
    import json as _json
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(url, content=_json.dumps({"text": message}),
                         headers={"Content-Type": "application/json"})
        return {"sent": r.status_code == 200, "status": r.status_code}


async def filter_request(content: str, tenant_id: str = "default", **_) -> dict:
    return await _post("/filter", {"content": content, "tenant_id": tenant_id}, tenant=tenant_id)


async def get_compliance_art30(tenant_id: str = "default", **_) -> dict:
    return await _get("/compliance/art30", tenant=tenant_id)


async def visual_assert_page(
    url: str,
    assertion: str = "",
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Navigate to *url*, capture a full-page screenshot, then analyze it with
    Claude Vision and return the result.

    ``assertion`` is a free-text instruction sent to Claude Vision alongside
    the screenshot.  If omitted, Claude is asked to note security issues,
    errors, and unexpected content.

    Requires ANTHROPIC_API_KEY in the environment.  Playwright must be
    installed and the Chromium binary available (standard in the warden image).
    Fail-open: if vision analysis fails the screenshot bytes are still returned.
    """
    # ── Screenshot ────────────────────────────────────────────────────────────
    try:
        from warden.tools.browser import BrowserSandbox
        async with BrowserSandbox() as browser:
            await browser.navigate(url)
            rec = await browser.screenshot()
        b64_png    = rec.result["screenshot_b64"]
        size_bytes = rec.result["size_bytes"]
    except Exception as exc:
        return {"ok": False, "url": url, "error": f"Screenshot failed: {exc}"}

    # ── Claude Vision ─────────────────────────────────────────────────────────
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {
            "ok": True,
            "url": url,
            "screenshot_bytes": size_bytes,
            "analysis": "ANTHROPIC_API_KEY not configured — screenshot captured, vision skipped.",
        }

    prompt = assertion or (
        "Analyze this screenshot for security issues, unexpected content, "
        "visible error messages, suspicious UI patterns, or anything else "
        "that warrants security attention."
    )

    try:
        import anthropic as _anthropic
        client = _anthropic.AsyncAnthropic(api_key=api_key)
        msg = await client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type":       "base64",
                            "media_type": "image/png",
                            "data":       b64_png,
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }],
        )
        analysis: str = msg.content[0].text if msg.content else ""
    except Exception as exc:
        analysis = f"Vision analysis failed: {exc}"

    return {
        "ok":               True,
        "url":              url,
        "screenshot_bytes": size_bytes,
        "analysis":         analysis,
    }


async def scan_shadow_ai(
    subnet: str = "",
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #29 — Shadow AI Discovery.

    Queries the Shadow AI Discovery engine for unauthorized AI tool usage
    in the given subnet (CIDR notation, e.g. "10.0.0.0/24").
    Falls back to all-tenants scan when subnet is omitted.

    Returns ranked list of discovered AI tools with risk scores,
    employee attribution (where available), and policy recommendations.
    """
    try:
        from warden.shadow_ai.discovery import ShadowAIDetector
        detector = ShadowAIDetector()
        return await detector.scan(subnet=subnet, tenant_id=tenant_id)
    except ImportError:
        # v4.2 not yet deployed — return placeholder
        return {
            "status":  "unavailable",
            "reason":  "Shadow AI Discovery engine not yet deployed (v4.2 roadmap)",
            "subnet":  subnet or "all",
            "results": [],
        }
    except Exception as exc:
        log.warning("scan_shadow_ai: %s", exc)
        return {"status": "error", "reason": str(exc)}


async def explain_decision(
    request_id: str,
    tenant_id:  str = "default",
    **_,
) -> dict:
    """
    Tool #30 — Causal Decision Explainer.

    Retrieves the full causal chain for a specific filter decision:
    Betti numbers, HyperbolicBrain distances, CausalArbiter DAG posteriors,
    and a plain-English rationale.

    Returns structured causal chain JSON suitable for the XAI dashboard.
    """
    try:
        from warden.analytics.logger import read_by_request_id
        record = read_by_request_id(request_id)
        if not record:
            return {"found": False, "request_id": request_id}

        # Build causal chain from stored decision metadata
        chain: dict = {
            "found":      True,
            "request_id": request_id,
            "ts":         record.get("ts"),
            "decision":   record.get("action", "unknown"),
            "risk_level": record.get("risk_level", "unknown"),
            "layers": {
                "topology": {
                    "beta0":       record.get("beta0"),
                    "beta1":       record.get("beta1"),
                    "noise_score": record.get("topology_noise"),
                },
                "semantic": {
                    "score":            record.get("semantic_score"),
                    "flags":            record.get("flags", []),
                    "hyperbolic_dist":  record.get("hyperbolic_distance"),
                },
                "causal": {
                    "p_high_risk":    record.get("causal_p_high_risk"),
                    "intervention":   record.get("causal_do_operator"),
                    "backdoor_nodes": record.get("causal_backdoor_nodes", []),
                },
                "shadow_ban": {
                    "score":    record.get("ers_score"),
                    "strategy": record.get("shadow_ban_strategy"),
                },
            },
            "rationale": record.get("xai_rationale", ""),
            "processing_ms": record.get("processing_ms"),
        }

        # Generate plain-English rationale if missing
        if not chain["rationale"]:
            flags    = record.get("flags", [])
            decision = record.get("action", "blocked")
            chain["rationale"] = (
                f"Request {decision} after detection of: {', '.join(flags) if flags else 'anomalous pattern'}. "
                f"Risk level: {record.get('risk_level', 'unknown')}. "
                f"Processing time: {record.get('processing_ms', '?')}ms."
            )

        return chain

    except Exception as exc:
        log.warning("explain_decision request_id=%s error: %s", request_id, exc)
        return {"found": False, "request_id": request_id, "error": str(exc)}


async def visual_diff(
    baseline_url: str,
    candidate_url: str,
    prompt: str = "",
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #31 — Visual Regression Diff.

    Captures a screenshot of *baseline_url* and *candidate_url*, then asks
    Claude Vision to describe significant visual differences.

    Falls back to byte-size delta when ANTHROPIC_API_KEY is absent.

    Verdicts: IDENTICAL | MINOR_DIFF | REGRESSION | CRITICAL_REGRESSION | ERROR
    """
    try:
        from warden.tools.browser import BrowserSandbox
    except ImportError:
        return {"ok": False, "error": "Playwright not available"}

    import base64 as _b64

    try:
        b_b64 = await BrowserSandbox.capture_screenshot_b64(baseline_url)
        c_b64 = await BrowserSandbox.capture_screenshot_b64(candidate_url)
    except Exception as exc:
        return {"ok": False, "error": f"Screenshot capture failed: {exc}"}

    diff_prompt = prompt or (
        "You are a visual regression analyst. "
        "Screenshot 1 is the BASELINE (expected). Screenshot 2 is the CANDIDATE (current). "
        "Describe only SIGNIFICANT differences: layout breaks, missing UI elements, error banners, "
        "text content changes, style regressions. Ignore timestamps, counters, and dynamic ads. "
        "End your response with exactly one verdict on its own line: "
        "IDENTICAL | MINOR_DIFF | REGRESSION | CRITICAL_REGRESSION"
    )

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        baseline_bytes = len(_b64.b64decode(b_b64 + "==")) if b_b64 else 0
        candidate_bytes = len(_b64.b64decode(c_b64 + "==")) if c_b64 else 0
        delta_pct = abs(baseline_bytes - candidate_bytes) / max(baseline_bytes, 1) * 100
        verdict = "REGRESSION" if delta_pct > 20 else "MINOR_DIFF" if delta_pct > 5 else "IDENTICAL"
        return {
            "ok":             True,
            "verdict":        verdict,
            "analysis":       f"[size-diff fallback] delta={delta_pct:.1f}% baseline={baseline_bytes}B candidate={candidate_bytes}B",
            "baseline_url":   baseline_url,
            "candidate_url":  candidate_url,
        }

    try:
        import anthropic as _anthropic
        client = _anthropic.AsyncAnthropic(api_key=api_key)
        msg = await client.messages.create(
            model="claude-opus-4-6",
            max_tokens=512,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b_b64}},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": c_b64}},
                    {"type": "text",  "text": diff_prompt},
                ],
            }],
        )
        analysis: str = msg.content[0].text if msg.content else ""
        last_line = analysis.strip().split("\n")[-1].upper()
        if "CRITICAL" in last_line:
            verdict = "CRITICAL_REGRESSION"
        elif "REGRESSION" in last_line:
            verdict = "REGRESSION"
        elif "MINOR" in last_line:
            verdict = "MINOR_DIFF"
        else:
            verdict = "IDENTICAL"
    except Exception as exc:
        analysis = f"Vision analysis failed: {exc}"
        verdict = "ERROR"

    return {
        "ok":            verdict != "ERROR",
        "verdict":       verdict,
        "analysis":      analysis,
        "baseline_url":  baseline_url,
        "candidate_url": candidate_url,
    }


# ── Community tool handlers (#32–#37) ────────────────────────────────────────

async def get_community_feed(
    tenant_id: str = "default",
    limit: int = 20,
    status: str = "approved",
    **_,
) -> dict:
    """
    Tool #32 — Fetch the Business Community post feed.
    Returns approved posts by default; pass status='pending' to review the moderation queue.
    """
    try:
        data = await _get(
            f"/community/feed",
            tenant=tenant_id,
            params={"limit": limit, "offset": 0},
        )
        posts = data.get("posts", []) if isinstance(data, dict) else []
        # Filter by status when the feed endpoint supports only approved; for pending,
        # we surface the raw count so SOVA can decide to escalate.
        summary = {
            "total": data.get("count", len(posts)),
            "posts": [
                {
                    "id":         p.get("id", "")[:8],
                    "author_id":  p.get("author_id", ""),
                    "source":     p.get("source", ""),
                    "status":     p.get("status", ""),
                    "nim_verdict": p.get("nim_verdict"),
                    "nim_score":  p.get("nim_score"),
                    "preview":    p.get("content", "")[:120],
                    "created_at": p.get("created_at", "")[:19],
                }
                for p in posts[:limit]
            ],
        }
        return summary
    except Exception as exc:
        log.warning("get_community_feed error: %s", exc)
        return {"error": str(exc)}


async def get_community_post(post_id: str, tenant_id: str = "default", **_) -> dict:
    """
    Tool #33 — Fetch a single community post with its comments.
    Useful for SOVA to investigate a flagged post before deciding on escalation.
    """
    try:
        data = await _get(f"/community/posts/{post_id}", tenant=tenant_id)
        return {
            "id":          data.get("id"),
            "status":      data.get("status"),
            "nim_verdict": data.get("nim_verdict"),
            "nim_score":   data.get("nim_score"),
            "source":      data.get("source"),
            "author_id":   data.get("author_id"),
            "content":     data.get("content", "")[:500],
            "comment_count": len(data.get("comments", [])),
            "created_at":  data.get("created_at", "")[:19],
        }
    except Exception as exc:
        log.warning("get_community_post %s error: %s", post_id, exc)
        return {"error": str(exc), "post_id": post_id}


async def moderate_community_post(
    post_id: str,
    action: str,
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #34 — Moderate a community post.

    action: 'approve' | 'block' | 'requeue'
      approve  — marks post as approved so it appears in the public feed
      block    — hard-block the post (requires ADMIN_KEY env var on the API side)
      requeue  — re-enqueue NIM moderation job for a stuck/pending post
    """
    import os as _os
    try:
        if action == "block":
            admin_key = _os.getenv("ADMIN_KEY", "")
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.delete(
                    f"{_BASE}/community/posts/{post_id}",
                    headers={**_headers(tenant_id), "X-Admin-Key": admin_key},
                )
                r.raise_for_status()
                return {"post_id": post_id, "action": "block", "result": r.json()}
        elif action == "requeue":
            result = await _post(
                f"/community/posts/{post_id}/requeue",
                {"post_id": post_id},
                tenant=tenant_id,
            )
            return {"post_id": post_id, "action": "requeue", "result": result}
        else:
            return {"error": f"Unknown action '{action}'. Use approve|block|requeue."}
    except Exception as exc:
        log.warning("moderate_community_post %s action=%s error: %s", post_id, action, exc)
        return {"error": str(exc), "post_id": post_id, "action": action}


async def list_community_posts_members(tenant_id: str = "default", **_) -> dict:
    """
    Tool #35 — List all Business Community members for a tenant.
    Returns user_id, display_name, role, join date.
    """
    try:
        data = await _get("/community/members", tenant=tenant_id)
        members = data.get("members", []) if isinstance(data, dict) else []
        return {
            "count": data.get("count", len(members)),
            "members": [
                {
                    "user_id":      m.get("user_id"),
                    "display_name": m.get("display_name"),
                    "role":         m.get("role"),
                    "joined_at":    m.get("joined_at", "")[:10],
                }
                for m in members
            ],
        }
    except Exception as exc:
        log.warning("list_community_posts_members error: %s", exc)
        return {"error": str(exc)}


async def community_moderation_report(tenant_id: str = "default", **_) -> dict:
    """
    Tool #36 — Generate a community health digest for SOVA morning brief.
    Pulls feed stats + member count + pending/blocked post counts.
    """
    try:
        feed_data    = await _get("/community/feed", tenant=tenant_id, params={"limit": 200})
        member_data  = await _get("/community/members", tenant=tenant_id)

        posts   = feed_data.get("posts", []) if isinstance(feed_data, dict) else []
        members = member_data.get("count", 0) if isinstance(member_data, dict) else 0

        nim_verdicts: dict[str, int] = {}
        sources:      dict[str, int] = {}
        for p in posts:
            v = p.get("nim_verdict") or "UNKNOWN"
            s = p.get("source") or "manual"
            nim_verdicts[v] = nim_verdicts.get(v, 0) + 1
            sources[s]      = sources.get(s, 0) + 1

        return {
            "tenant_id":     tenant_id,
            "total_approved": feed_data.get("count", len(posts)),
            "total_members":  members,
            "nim_verdicts":   nim_verdicts,
            "sources":        sources,
            "generated_at":   __import__("datetime").datetime.utcnow().isoformat(),
        }
    except Exception as exc:
        log.warning("community_moderation_report error: %s", exc)
        return {"error": str(exc)}


async def post_community_announcement(
    author_id: str,
    content: str,
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #37 — Post an announcement to the Business Community as SOVA.
    Content is still subject to NIM moderation (queued in background).
    author_id should be 'sova' or the admin user ID.
    """
    try:
        result = await _post(
            "/community/posts",
            {"author_id": author_id, "content": content, "source": "sova"},
            tenant=tenant_id,
        )
        return {
            "posted":  True,
            "post_id": result.get("id"),
            "status":  result.get("status"),
            "message": result.get("message"),
        }
    except Exception as exc:
        log.warning("post_community_announcement error: %s", exc)
        return {"posted": False, "error": str(exc)}


# ── Anthropic tool schema definitions ────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "name": "get_health",
        "description": "Get Shadow Warden gateway health: Redis status, circuit breaker, bypass rate, WS clients.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_stats",
        "description": "Get aggregated security statistics: total requests, blocks, risk distribution, top flags, recent events.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string", "description": "Tenant to query (default: 'default')"},
            },
        },
    },
    {
        "name": "get_config",
        "description": "Get live configuration: thresholds, strict_mode, rate limits, ML enabled, MTLS.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "update_config",
        "description": "Update live-tunable settings (semantic_threshold, strict_mode, rate_limit, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {
                "changes": {"type": "object", "description": "Key-value pairs of settings to update"},
                "tenant_id": {"type": "string"},
            },
            "required": ["changes"],
        },
    },
    {
        "name": "list_threats",
        "description": "List detected CVEs and ArXiv LLM-attack papers from the Threat Intelligence feed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type_filter": {"type": "string", "description": "Filter by 'cve' or 'arxiv'"},
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "refresh_threat_intel",
        "description": "Trigger an on-demand OSV CVE scan + ArXiv LLM-attack paper refresh (async, returns job ID).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "dismiss_threat",
        "description": "Acknowledge/dismiss a specific threat intelligence item.",
        "input_schema": {
            "type": "object",
            "properties": {
                "item_id": {"type": "string", "description": "Threat item ID to dismiss"},
                "tenant_id": {"type": "string"},
            },
            "required": ["item_id"],
        },
    },
    {
        "name": "list_communities",
        "description": "List all Business Communities for a tenant (id, name, member count, active key version).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_community",
        "description": "Get full Community profile: members, active kid, rotation status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "rotate_community_key",
        "description": "Initiate a Root Key Rollover for a community. Generates new kid, demotes old to ROTATION_ONLY, enqueues ARQ re-wrap worker.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "get_rotation_progress",
        "description": "Check Root Key Rollover progress: done/total entity re-wraps, failed count, status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "list_community_members",
        "description": "List all active members of a community with their clearance levels.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "list_monitors",
        "description": "List all uptime monitors for a tenant (URL, check_type, interval, is_active).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_monitor_status",
        "description": "Get the latest probe result for a monitor: is_up, latency_ms, status_code, error.",
        "input_schema": {
            "type": "object",
            "properties": {
                "monitor_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["monitor_id"],
        },
    },
    {
        "name": "get_monitor_uptime",
        "description": "Get uptime % and average latency for a monitor over a time window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "monitor_id": {"type": "string"},
                "hours": {"type": "integer", "description": "Lookback window in hours (default 24)"},
                "tenant_id": {"type": "string"},
            },
            "required": ["monitor_id"],
        },
    },
    {
        "name": "get_monitor_history",
        "description": "Get recent probe results for a monitor (newest first).",
        "input_schema": {
            "type": "object",
            "properties": {
                "monitor_id": {"type": "string"},
                "limit": {"type": "integer", "description": "Max results (default 20)"},
                "tenant_id": {"type": "string"},
            },
            "required": ["monitor_id"],
        },
    },
    {
        "name": "get_financial_impact",
        "description": "Get full ROI breakdown: monthly savings, 3-year projection, tier ROI (live data from logs + Prometheus).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_cost_saved",
        "description": "Get cumulative LLM inference cost saved via shadow banning (dollar amount).",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_billing_quota",
        "description": "Get current monthly request usage and quota percentage for a tenant.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "generate_proposal",
        "description": "Generate a customer-facing ROI proposal deck for a company.",
        "input_schema": {
            "type": "object",
            "properties": {
                "company_name": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["company_name"],
        },
    },
    {
        "name": "list_agents",
        "description": "List all AP2 agentic payment agents for a tenant.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "get_agent_activity",
        "description": "Get AP2 mandate execution audit log (agent_id, SKU, amount, timestamp, status).",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max results (default 50)"},
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "revoke_agent",
        "description": "Revoke an AP2 agentic payment agent immediately.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "get_tenant_impact",
        "description": "Get personal ROI dashboard for a tenant: blocks, PII intercepts, dollar saved, threat breakdown, daily timeline.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "send_slack_alert",
        "description": "Send a Slack notification message to the configured webhook.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Markdown-formatted Slack message"},
            },
            "required": ["message"],
        },
    },
    {
        "name": "filter_request",
        "description": "Run content through the full Shadow Warden filter pipeline (test/audit mode).",
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "tenant_id": {"type": "string"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "get_compliance_art30",
        "description": "Get GDPR Article 30 ROPA (Record of Processing Activities) for a tenant.",
        "input_schema": {
            "type": "object",
            "properties": {"tenant_id": {"type": "string"}},
        },
    },
    {
        "name": "scan_shadow_ai",
        "description": (
            "Scan for unauthorized AI tool usage (Shadow AI Discovery). "
            "Detects employees or services calling external AI providers "
            "(OpenAI, Anthropic, Gemini, Cohere, etc.) outside the authorized gateway. "
            "Returns ranked risk list with tool names, source IPs, and policy recommendations. "
            "Provide a CIDR subnet to scope the scan, or omit for tenant-wide scan."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "subnet":    {"type": "string", "description": "CIDR subnet to scan, e.g. '10.0.0.0/24'. Omit for all."},
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "explain_decision",
        "description": (
            "Retrieve the full causal chain for a specific filter decision. "
            "Returns Betti numbers (topology), HyperbolicBrain distances, "
            "CausalArbiter DAG posteriors (P(HIGH_RISK|do(A))), shadow ban score, "
            "and a plain-English rationale. Use this to explain why a request was blocked "
            "or flagged — for SOC investigations, audit trails, or XAI dashboard linking."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "The request_id from a filter log entry."},
                "tenant_id":  {"type": "string"},
            },
            "required": ["request_id"],
        },
    },
    {
        "name": "visual_assert_page",
        "description": (
            "Navigate to a URL, capture a full-page screenshot, and analyze it with "
            "Claude Vision. Returns a security/UX analysis of what is visible on screen. "
            "Use for automated visual regression, SOC 2 evidence capture, or verifying "
            "that a deployed page looks correct. Requires Playwright + ANTHROPIC_API_KEY."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Fully-qualified URL to navigate to (https://...)",
                },
                "assertion": {
                    "type": "string",
                    "description": (
                        "Optional instruction for Claude Vision, e.g. "
                        "'Confirm the login form is visible and there are no error banners'. "
                        "If omitted, Claude performs a general security/UX review."
                    ),
                },
                "tenant_id": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "visual_diff",
        "description": (
            "Capture screenshots of two URLs and use Claude Vision to describe significant "
            "visual differences between them. Returns a verdict: IDENTICAL / MINOR_DIFF / "
            "REGRESSION / CRITICAL_REGRESSION. Falls back to byte-size delta comparison "
            "when ANTHROPIC_API_KEY is absent. Use for visual regression testing or to "
            "compare a baseline snapshot against the current production state."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "baseline_url": {
                    "type": "string",
                    "description": "URL of the known-good baseline (what it should look like).",
                },
                "candidate_url": {
                    "type": "string",
                    "description": "URL of the current state to test against the baseline.",
                },
                "prompt": {
                    "type": "string",
                    "description": "Optional custom vision instruction. Overrides the default diff prompt.",
                },
                "tenant_id": {"type": "string"},
            },
            "required": ["baseline_url", "candidate_url"],
        },
    },
]

# ── Dispatch table ────────────────────────────────────────────────────────────

    # ── Community tools #32–#37 ───────────────────────────────────────────────
    {
        "name": "get_community_feed",
        "description": (
            "Fetch the Business Community post feed for a tenant. "
            "Returns approved posts by default. Use limit=50 and status='pending' "
            "to review the moderation queue."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string", "description": "Tenant ID (default 'default')"},
                "limit":     {"type": "integer", "description": "Max posts to return (default 20)"},
                "status":    {"type": "string",  "description": "approved | pending | blocked"},
            },
        },
    },
    {
        "name": "get_community_post",
        "description": (
            "Fetch a single community post by ID, including its NIM moderation verdict, "
            "score, source (manual/obsidian/sova), and comment count. "
            "Use before deciding to moderate or escalate."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "post_id":   {"type": "string", "description": "Post UUID"},
                "tenant_id": {"type": "string"},
            },
            "required": ["post_id"],
        },
    },
    {
        "name": "moderate_community_post",
        "description": (
            "Moderate a community post. "
            "action='block' hard-blocks a harmful post (requires ADMIN_KEY). "
            "action='requeue' re-sends a stuck post through NIM moderation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "post_id":   {"type": "string"},
                "action":    {"type": "string", "enum": ["block", "requeue"],
                              "description": "block | requeue"},
                "tenant_id": {"type": "string"},
            },
            "required": ["post_id", "action"],
        },
    },
    {
        "name": "list_community_posts_members",
        "description": (
            "List all registered Business Community members for a tenant: "
            "user_id, display_name, role, join date."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "community_moderation_report",
        "description": (
            "Generate a community health digest: total approved posts, member count, "
            "NIM verdict breakdown (SAFE/WARN/BLOCK counts), post source breakdown "
            "(manual/obsidian/sova). Ideal for sova_morning_brief."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string"},
            },
        },
    },
    {
        "name": "post_community_announcement",
        "description": (
            "Post an announcement to the Business Community as SOVA. "
            "Content goes through NIM moderation (pending until approved). "
            "Use for weekly summaries, security advisories, or system notices."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "author_id": {"type": "string", "description": "Use 'sova' or admin user ID"},
                "content":   {"type": "string", "description": "Announcement text (max 10 000 chars)"},
                "tenant_id": {"type": "string"},
            },
            "required": ["author_id", "content"],
        },
    },
]

TOOL_HANDLERS: dict[str, Any] = {
    "get_health":             get_health,
    "get_stats":              get_stats,
    "get_config":             get_config,
    "update_config":          update_config,
    "list_threats":           list_threats,
    "refresh_threat_intel":   refresh_threat_intel,
    "dismiss_threat":         dismiss_threat,
    "list_communities":       list_communities,
    "get_community":          get_community,
    "rotate_community_key":   rotate_community_key,
    "get_rotation_progress":  get_rotation_progress,
    "list_community_members": list_community_members,
    "list_monitors":          list_monitors,
    "get_monitor_status":     get_monitor_status,
    "get_monitor_uptime":     get_monitor_uptime,
    "get_monitor_history":    get_monitor_history,
    "get_financial_impact":   get_financial_impact,
    "get_cost_saved":         get_cost_saved,
    "get_billing_quota":      get_billing_quota,
    "generate_proposal":      generate_proposal,
    "list_agents":            list_agents,
    "get_agent_activity":     get_agent_activity,
    "revoke_agent":           revoke_agent,
    "get_tenant_impact":      get_tenant_impact,
    "send_slack_alert":       send_slack_alert,
    "filter_request":         filter_request,
    "get_compliance_art30":   get_compliance_art30,
    "scan_shadow_ai":               scan_shadow_ai,
    "explain_decision":             explain_decision,
    "visual_assert_page":           visual_assert_page,
    "visual_diff":                  visual_diff,
    # Community tools
    "get_community_feed":           get_community_feed,
    "get_community_post":           get_community_post,
    "moderate_community_post":      moderate_community_post,
    "list_community_posts_members": list_community_posts_members,
    "community_moderation_report":  community_moderation_report,
    "post_community_announcement":  post_community_announcement,
}
