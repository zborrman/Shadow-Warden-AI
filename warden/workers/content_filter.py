"""
ARQ worker: moderate community posts.

Pipeline:
  1. NVIDIA NIM (Nemotron) → SAFE / WARN / BLOCK verdict + score
  2. Fallback: SemanticGuard.analyse() if NIM unavailable
  3. Update post status in DB
  4. Slack alert on BLOCK
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("warden.workers.content_filter")

_MODERATION_PROMPT = """You are a content moderation assistant for a professional cybersecurity community.
Classify the following community post into exactly one category:
- SAFE   — professional, constructive, on-topic
- WARN   — borderline; off-topic, promotional, or mildly inappropriate
- BLOCK  — spam, hate speech, illegal content, credential leaks, or social engineering

Respond with JSON only: {{"verdict": "SAFE"|"WARN"|"BLOCK", "score": 0.0-1.0, "reason": "..."}}

Post:
{content}"""


async def _nim_moderate(content: str) -> tuple[str, float, str]:
    """Returns (verdict, score, reason). Raises on failure so caller can fallback."""
    from warden.brain.nemotron_client import NimClient
    client = NimClient()
    import json
    answer, _ = await client.chat([
        {"role": "user", "content": _MODERATION_PROMPT.format(content=content[:2000])}
    ])
    # strip <think>...</think> if present
    import re
    raw = re.sub(r"<think>.*?</think>", "", answer, flags=re.DOTALL).strip()
    data = json.loads(raw)
    return data["verdict"], float(data.get("score", 0.5)), data.get("reason", "")


async def _semantic_fallback(content: str) -> tuple[str, float, str]:
    """Fallback: SemanticGuard.analyse() → map HIGH/BLOCK → BLOCK, MEDIUM → WARN, LOW → SAFE."""
    try:
        from warden.semantic_guard import SemanticGuard
        guard = SemanticGuard()
        result = guard.analyse(content)
        level = result.risk_level.name
        score = result.top_flag.score if result.top_flag else 0.0
        mapping = {"LOW": "SAFE", "MEDIUM": "WARN", "HIGH": "BLOCK", "BLOCK": "BLOCK"}
        return mapping.get(level, "SAFE"), score, f"semantic_guard:{level}"
    except Exception as e:
        log.warning("Semantic fallback failed (fail-open): %s", e)
        return "SAFE", 0.0, "fallback_error"


async def _slack_alert(post_id: str, verdict: str, reason: str) -> None:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    try:
        import httpx
        msg = {
            "text": (
                f":no_entry: *Community post blocked*\n"
                f"Post: `{post_id}`\n"
                f"Verdict: `{verdict}`\n"
                f"Reason: {reason}"
            )
        }
        async with httpx.AsyncClient(timeout=5) as c:
            await c.post(webhook, json=msg)
    except Exception as e:
        log.warning("Slack alert failed (fail-open): %s", e)


async def moderate_post(ctx: dict[str, Any], post_id: str) -> dict[str, Any]:
    """
    ARQ job entrypoint.
    ctx: ARQ context (unused here but required by ARQ signature).
    """
    from warden.models.community import get_post, update_post_status

    post = get_post(post_id)
    if not post:
        log.warning("moderate_post: post %s not found", post_id)
        return {"error": "not_found"}

    nim_available = bool(os.getenv("NVIDIA_API_KEY"))
    verdict, score, reason = "SAFE", 0.0, ""

    if nim_available:
        try:
            verdict, score, reason = await _nim_moderate(post.content)
            log.info("NIM verdict for %s: %s (%.2f)", post_id, verdict, score)
        except Exception as e:
            log.warning("NIM moderation failed, falling back to SemanticGuard: %s", e)
            verdict, score, reason = await _semantic_fallback(post.content)
    else:
        verdict, score, reason = await _semantic_fallback(post.content)

    status = "approved" if verdict == "SAFE" else ("pending" if verdict == "WARN" else "blocked")
    update_post_status(post_id, status, verdict, score)

    if verdict == "BLOCK":
        await _slack_alert(post_id, verdict, reason)

    log.info("Post %s → status=%s nim=%s score=%.2f", post_id, status, verdict, score)
    return {"post_id": post_id, "status": status, "verdict": verdict, "score": score}
