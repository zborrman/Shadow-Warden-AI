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
        analysis: str = msg.content[0].text if msg.content else ""  # type: ignore[union-attr]
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

    # OCR pre-check: extract text from both screenshots and run through the
    # Warden filter before passing images to Vision. This prevents prompt
    # injection attacks embedded as visible text in a screenshot from bypassing
    # all nine text-filter layers.
    try:
        from warden.ocr import extract_text_from_b64 as _ocr
        for _label, _b64img in (("baseline", b_b64), ("candidate", c_b64)):
            _ocr_text = _ocr(_b64img)
            if _ocr_text:
                _check = await _post("/filter", {"text": _ocr_text}, tenant_id)
                if isinstance(_check, dict) and not _check.get("allowed", True):
                    return {
                        "ok":      False,
                        "verdict": "BLOCKED_BY_OCR_PRECHECK",
                        "reason":  f"Prompt injection detected in {_label} screenshot text",
                        "flags":   _check.get("flags", []),
                    }
    except Exception as _ocr_exc:
        log.debug("visual_diff: OCR pre-check skipped — %s", _ocr_exc)

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
        analysis: str = msg.content[0].text if msg.content else ""  # type: ignore[union-attr]
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
            "/community/feed",
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


# ── SEP Community Intelligence tools (#38 – #40) ─────────────────────────────

async def search_community_feed(
    query: str,
    limit: int = 5,
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #38 — Semantic search over the SEP community incident feed.

    Searches the UECIID index by keyword/display-name match.  Returns the top-N
    incident records with UECIID, data_class, jurisdiction, and metadata so SOVA
    can determine whether a new threat has already been documented by peer
    communities before escalating or publishing a duplicate entry.
    """
    try:
        results = await _get(
            "/sep/ueciids/search",
            tenant=tenant_id,
            params={"q": query, "limit": limit},
        )
        entries = results if isinstance(results, list) else results.get("results", [])
        return {
            "query":   query,
            "total":   len(entries),
            "results": [
                {
                    "ueciid":       e.get("ueciid"),
                    "display_name": e.get("display_name"),
                    "data_class":   e.get("data_class"),
                    "jurisdiction": e.get("jurisdiction"),
                    "created_at":   e.get("created_at"),
                    "metadata":     e.get("metadata", {}),
                }
                for e in entries[:limit]
            ],
        }
    except Exception as exc:
        log.warning("search_community_feed error: %s", exc)
        return {"query": query, "total": 0, "results": [], "error": str(exc)}


async def publish_to_community(
    verdict: str,
    rule_id: str,
    risk_level: str,
    evidence_summary: str,
    tenant_id: str = "default",
    community_id: str = "",
    **_,
) -> dict:
    """
    Tool #39 — Publish an anonymized security incident to the SEP hub.

    Workflow:
      1. Validate evidence_summary through /filter — abort if PII/secrets detected.
      2. Register a new UECIID with incident metadata (verdict, rule_id, risk_level).
      3. Return the UECIID so the caller can link it in STIX audit or Slack alerts.

    evidence_summary must already be anonymized (_anonymize_for_evolution output).
    PII or secrets will cause an immediate abort before any SEP write.
    """
    # Step 1: PII gate — confirm evidence is clean before any SEP write
    try:
        check = await _post(
            "/filter",
            {"content": evidence_summary, "tenant_id": tenant_id},
            tenant=tenant_id,
        )
        if check.get("secrets_found"):
            return {
                "published":    False,
                "error":        "Evidence contains secrets/PII — redact before publishing",
                "secrets_found": check["secrets_found"],
            }
    except Exception as exc:
        log.warning("publish_to_community: filter gate error: %s", exc)
        return {"published": False, "error": f"PII filter check failed: {exc}"}

    # Step 2: register UECIID
    display_name = f"[{risk_level}] {rule_id} — {verdict}"
    try:
        reg = await _post(
            "/sep/ueciids",
            {
                "display_name": display_name,
                "data_class":   "GENERAL",
                "metadata": {
                    "verdict":    verdict,
                    "rule_id":    rule_id,
                    "risk_level": risk_level,
                    "evidence":   evidence_summary[:500],
                    "publisher":  "sova",
                },
            },
            tenant=tenant_id,
        )
    except Exception as exc:
        log.warning("publish_to_community: register error: %s", exc)
        return {"published": False, "error": f"UECIID registration failed: {exc}"}

    ueciid = reg.get("ueciid")

    # Award reputation points to the publishing tenant
    try:
        from warden.communities.reputation import award_points  # noqa: PLC0415
        award_points(tenant_id, "PUBLISH_ENTRY", ref_ueciid=ueciid or "")
    except Exception:
        pass

    return {
        "published":    True,
        "ueciid":       ueciid,
        "display_name": display_name,
        "risk_level":   risk_level,
        "verdict":      verdict,
        "community_id": community_id or tenant_id,
    }


def _mitre_fallback(incident_type: str, risk_level: str) -> list[str]:
    """Built-in MITRE ATT&CK-based playbook when community intel is unavailable."""
    recs = [
        f"[MITRE T1190] Review prompt-injection vectors for: {incident_type}",
        "Isolate affected tenant and rotate API keys via rotate_community_key",
        "Add confirmed attack to Evolution Engine corpus via /api/evolution/add-examples",
        f"Escalate to {'MasterAgent' if risk_level == 'HIGH' else 'SOVA'} for root-cause analysis",
    ]
    ltype = incident_type.lower()
    if "jailbreak" in ltype:
        recs.insert(0, "[MITRE T1059.007] Update SemanticGuard patterns and HyperbolicBrain corpus")
    elif "secret" in ltype or "pii" in ltype:
        recs.insert(0, "[MITRE T1552] Verify SecretRedactor patterns cover the leaked credential type")
    elif "phish" in ltype:
        recs.insert(0, "[MITRE T1566] Update PhishGuard domain blocklist and SE-Arbiter thresholds")
    elif "injection" in ltype:
        recs.insert(0, "[MITRE T1055] Check AgentMonitor INJECTION_CHAIN detection and tool allowlist")
    return recs


async def get_community_recommendations(
    incident_type: str,
    risk_level: str = "HIGH",
    tenant_id: str = "default",
    community_id: str = "",
    **_,
) -> dict:
    """
    Tool #40 — Get recommended playbook actions from community intelligence.

    Queries CommunityIntelReport for the tenant/community and filters recommendations
    relevant to the incident_type keyword.  Falls back to built-in MITRE ATT&CK
    playbook when community intel is unavailable or returns no relevant items.
    """
    target = community_id or tenant_id
    try:
        report = await _get(f"/community-intel/{target}/report", tenant=tenant_id)
        all_recs = report.get("recommendations", [])
        ltype = incident_type.lower()
        relevant = [r for r in all_recs if ltype in r.lower() or risk_level.lower() in r.lower()]
        if not relevant:
            relevant = all_recs[:5] or _mitre_fallback(incident_type, risk_level)

        return {
            "incident_type":   incident_type,
            "risk_level":      risk_level,
            "recommendations": relevant,
            "community_risk":  report.get("risk_label", "UNKNOWN"),
            "risk_score":      report.get("risk_score", 0),
            "community_id":    target,
            "source":          "community_intel",
        }
    except Exception as exc:
        log.warning("get_community_recommendations error: %s", exc)
        return {
            "incident_type":   incident_type,
            "risk_level":      risk_level,
            "recommendations": _mitre_fallback(incident_type, risk_level),
            "community_id":    target,
            "source":          "mitre_fallback",
            "note":            "Community intel unavailable — using built-in MITRE playbook",
            "error":           str(exc),
        }


async def sync_misp_feed(**_) -> dict:
    """
    Tool #41 — Trigger MISP threat feed sync.

    Pulls recent events from the configured MISP instance, converts IoC
    attributes to attack descriptions, and synthesises them into the local
    SemanticGuard corpus via EvolutionEngine.

    Returns events_fetched, attrs_extracted, examples_added, errors.
    Requires MISP_URL + MISP_API_KEY env vars.
    """
    try:
        from warden.integrations.misp import MISPConnector  # noqa: PLC0415
        result = await MISPConnector().sync()
        return result.to_dict()
    except ValueError as exc:
        return {"error": str(exc), "note": "Set MISP_URL and MISP_API_KEY to enable MISP integration"}
    except Exception as exc:
        log.warning("sync_misp_feed error: %s", exc)
        return {"error": str(exc)}


async def get_reputation(tenant_id: str = "default", **_) -> dict:
    """
    Tool #42 — Get community reputation for a tenant.

    Returns points, badge, entry_count, and badge_emoji.
    Badge levels: NEWCOMER → CONTRIBUTOR → TOP_SHARER → GUARDIAN → ELITE.
    """
    try:
        from warden.communities.reputation import get_reputation as _get  # noqa: PLC0415
        rec = _get(tenant_id)
        return rec.to_dict()
    except Exception as exc:
        log.warning("get_reputation error: %s", exc)
        return {"tenant_id": tenant_id, "points": 0, "badge": "NEWCOMER", "entry_count": 0, "error": str(exc)}


async def scan_obsidian_note(
    content: str,
    filename: str = "",
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #43 — Scan an Obsidian note through Warden's security pipeline.

    Returns risk_level, secrets_found, data_class, and redacted_content.
    Automatically fires a Slack alert if risk is HIGH or BLOCK.
    """
    return await _post(
        "/obsidian/scan",
        {"content": content, "filename": filename},
        tenant=tenant_id,
    )


async def get_obsidian_feed(
    community_id: str,
    limit: int = 10,
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #44 — Fetch recent Obsidian notes shared to a Business Community via SEP.

    Returns list of entries: ueciid, display_name, content_type, byte_size, shared_at.
    """
    results = await _get(
        "/obsidian/feed",
        tenant=tenant_id,
        params={"community_id": community_id, "limit": min(int(limit), 20)},
    )
    return {"entries": results if isinstance(results, list) else [], "community_id": community_id}


async def share_obsidian_note(
    content: str,
    display_name: str,
    community_id: str,
    filename: str = "",
    data_class: str = "GENERAL",
    tenant_id: str = "default",
    **_,
) -> dict:
    """
    Tool #45 — Share a scanned Obsidian note to the SEP community hub.

    Runs the note through SecretRedactor first — aborts with error if secrets found.
    On success returns ueciid, data_class, and shared_at.
    A Slack notification is sent automatically on successful share.
    """
    return await _post(
        "/obsidian/share",
        {
            "content":      content,
            "filename":     filename,
            "display_name": display_name,
            "community_id": community_id,
            "data_class":   data_class,
        },
        tenant=tenant_id,
    )


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

    # ── SEP Community Intelligence #38–#40 ────────────────────────────────────
    {
        "name": "search_community_feed",
        "description": (
            "Search the SEP community incident feed by keyword. "
            "Returns the top-N relevant incident records (UECIID, data_class, jurisdiction, metadata). "
            "Use before publish_to_community to avoid duplicate entries — check if other "
            "communities have already documented this threat pattern. "
            "Also useful during threat_sync to enrich local CVE/ArXiv findings with peer intelligence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query":     {"type": "string", "description": "Search keyword or threat description"},
                "limit":     {"type": "integer", "description": "Max results to return (default 5, max 20)"},
                "tenant_id": {"type": "string"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "publish_to_community",
        "description": (
            "Publish an anonymized security incident to the SEP community hub. "
            "Runs the evidence_summary through the full filter pipeline first — "
            "if PII or secrets are detected the publish is aborted. "
            "On success, returns a UECIID that other community members can reference. "
            "IMPORTANT: evidence_summary must already be anonymized (no IPs, user IDs, or PII). "
            "Use explain_decision to get the causal chain, then strip identifying fields before calling this."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict":          {"type": "string", "description": "ALLOW | BLOCK | HIGH | MEDIUM"},
                "rule_id":          {"type": "string", "description": "Rule or pattern that fired (e.g. 'jailbreak_v3')"},
                "risk_level":       {"type": "string", "description": "LOW | MEDIUM | HIGH | BLOCK"},
                "evidence_summary": {"type": "string", "description": "Anonymized description of the attack — no PII, no IPs, no secrets"},
                "community_id":     {"type": "string", "description": "Target community ID (default: tenant_id)"},
                "tenant_id":        {"type": "string"},
            },
            "required": ["verdict", "rule_id", "risk_level", "evidence_summary"],
        },
    },
    {
        "name": "get_community_recommendations",
        "description": (
            "Get recommended playbook actions from community intelligence for a given incident type. "
            "Queries CommunityIntelReport and returns filtered recommendations relevant to the incident. "
            "Maps to MITRE ATT&CK techniques (T1190, T1059.007, T1552, T1566, T1055) when available. "
            "Falls back to built-in MITRE playbook if community intel is unavailable. "
            "Use after explain_decision to determine next steps for HIGH/BLOCK incidents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_type": {"type": "string",  "description": "Type of incident: jailbreak | secret_leak | phishing | injection | other"},
                "risk_level":    {"type": "string",  "description": "Risk level to filter recommendations by (default HIGH)"},
                "community_id":  {"type": "string",  "description": "Community to query (default: tenant_id)"},
                "tenant_id":     {"type": "string"},
            },
            "required": ["incident_type"],
        },
    },
    {
        "name": "sync_misp_feed",
        "description": (
            "Trigger a MISP (Malware Information Sharing Platform) threat feed sync. "
            "Fetches recent events from the configured MISP instance, converts IoC attributes "
            "(URLs, domains, hashes, CVEs) to attack descriptions, and synthesises them into "
            "the local SemanticGuard corpus via EvolutionEngine. "
            "Use during threat-sync to cross-reference community IoCs with ISAC/MISP feeds. "
            "Requires MISP_URL and MISP_API_KEY env vars — returns error if not configured."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_reputation",
        "description": (
            "Get community reputation for a tenant: points, badge, entry_count, badge_emoji. "
            "Badges: NEWCOMER (0pts) → CONTRIBUTOR (25pts) → TOP_SHARER (100pts) → "
            "GUARDIAN (300pts) → ELITE (750pts). "
            "Use to assess community standing before trusting published indicators."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string", "description": "Tenant to check reputation for"},
            },
            "required": [],
        },
    },

    # ── Obsidian + Slack unified tools #43–#45 ────────────────────────────────
    {
        "name": "scan_obsidian_note",
        "description": (
            "Scan an Obsidian markdown note through the full Warden security pipeline. "
            "Returns risk_level (ALLOW/LOW/MEDIUM/HIGH/BLOCK), secrets_found list, "
            "data_class (GENERAL/PII/PHI/FINANCIAL/CLASSIFIED), and redacted_content. "
            "Fires a Slack alert automatically when risk is HIGH or BLOCK. "
            "Use before share_obsidian_note to ensure no secrets leak into the community."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "content":   {"type": "string", "description": "Full note markdown content"},
                "filename":  {"type": "string", "description": "Note filename for Slack alert context"},
                "tenant_id": {"type": "string"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "get_obsidian_feed",
        "description": (
            "Fetch recent Obsidian notes shared to a Business Community via the SEP protocol. "
            "Returns list of entries: ueciid, display_name, content_type, byte_size, shared_at. "
            "Use during morning_brief to audit what knowledge was shared by the tenant's vault."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string", "description": "SEP community ID to fetch entries for"},
                "limit":        {"type": "integer", "description": "Max entries to return (default 10, max 20)"},
                "tenant_id":    {"type": "string"},
            },
            "required": ["community_id"],
        },
    },
    {
        "name": "share_obsidian_note",
        "description": (
            "Share a scanned Obsidian note to the SEP community hub under a given display_name. "
            "Runs SecretRedactor first — if secrets are detected the share is aborted with an error. "
            "On success returns the UECIID and sends a Slack confirmation. "
            "Always call scan_obsidian_note first and confirm risk is ALLOW or LOW before sharing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "content":      {"type": "string", "description": "Full note markdown content to share"},
                "display_name": {"type": "string", "description": "Human-readable title for the community entry"},
                "community_id": {"type": "string", "description": "SEP community ID to publish to"},
                "filename":     {"type": "string", "description": "Original filename (for Slack notification)"},
                "data_class":   {"type": "string", "description": "Data classification override: GENERAL | PII | PHI | FINANCIAL | CLASSIFIED"},
                "tenant_id":    {"type": "string"},
            },
            "required": ["content", "display_name", "community_id"],
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
    "search_community_feed":         search_community_feed,
    "publish_to_community":          publish_to_community,
    "get_community_recommendations": get_community_recommendations,
    "sync_misp_feed":                sync_misp_feed,
    "get_reputation":                get_reputation,
    "scan_obsidian_note":            scan_obsidian_note,
    "get_obsidian_feed":             get_obsidian_feed,
    "share_obsidian_note":           share_obsidian_note,
}
