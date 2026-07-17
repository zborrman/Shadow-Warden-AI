"""
warden/agent/sova.py
─────────────────────
SOVA — Shadow Operations & Vigilance Agent

Core agent loop powered by Claude Opus 4.6 with:
  • Prompt caching on the system prompt (cache_control: ephemeral)
  • Tool use for all 27 Shadow Warden capabilities
  • Redis-backed conversation memory per session
  • Graceful error handling — tool errors returned as tool_result content

Usage
─────
  from warden.agent.sova import run_query

  response = await run_query("Which communities need key rotation?")
  response = await run_query("Morning brief", session_id="sched-daily")
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from typing import Any

log = logging.getLogger("warden.agent.sova")

# Single source of truth for the SOVA model. Env-overridable so ops can pin/roll
# back without a code change; defaults to the current Opus generation.
_MODEL    = os.getenv("SOVA_MODEL", "claude-opus-4-8")
_MAX_ITER = 10      # max tool-use rounds before forcing a final answer


def _cached_tools(tool_defs: list[dict]) -> list[dict]:
    """Return the tool defs with ``cache_control`` on the final entry so the whole
    tools prefix (~68 schemas) is cached ephemerally instead of re-sent every turn.

    Does not mutate the shared ``tools.TOOLS`` list — copies the last element.
    """
    if not tool_defs:
        return tool_defs
    cached = list(tool_defs)
    last = dict(cached[-1])
    last["cache_control"] = {"type": "ephemeral"}
    cached[-1] = last
    return cached


# ── Cost tracking + structured logging (Phase 2) ─────────────────────────────
# SOVA reuses the Digital-Staff economics tracker and structured JSON logger so
# its spend and lifecycle events land in the same SQLite table / Loki schema.
# Every helper is fail-OPEN: observability must never brick the agent loop.

def _make_span(tenant_id: str, model: str, query: str):
    """Start a structured-log AgentSpan for this run, or None if unavailable."""
    try:
        from warden.staff import structured_log as _slog
        span = _slog.AgentSpan("sova", tenant_id, model, query=query)
        span.start()
        return span
    except Exception as exc:  # noqa: BLE001
        log.debug("sova: structured_log span unavailable (fail-open): %s", exc)
        return None


def _span_tool(span, tool_name: str, *, phase: str, status: str = "ok", detail: str = "") -> None:
    if span is None:
        return
    with contextlib.suppress(Exception):
        if phase == "call":
            span.tool_call(tool_name)
        else:
            span.tool_result(tool_name, status=status, detail=detail)


def _end_span(span, input_tokens: int, output_tokens: int, detail: str = "") -> None:
    if span is None:
        return
    with contextlib.suppress(Exception):
        span.end(input_tokens, output_tokens, detail=detail)


def _record_cost(tenant_id: str, model: str, input_tokens: int, output_tokens: int) -> float:
    """Record SOVA LLM spend via the shared economics tracker. Returns USD cost."""
    try:
        from warden.staff.economics import get_tracker
        entry = get_tracker().record(
            tenant_id, "sova", "query", model, input_tokens, output_tokens
        )
        return entry.cost_usd
    except Exception as exc:  # noqa: BLE001
        log.debug("sova: cost record failed (fail-open): %s", exc)
        return 0.0


# ── Semantic memory + tool profiles (Phase 3) ────────────────────────────────
# `memory.semantic_search` existed but was never called (nor written to). Phase 3
# reads relevant past SOVA findings into context and stores each final answer's
# embedding. GDPR-safe: memory.py only ever stores *assistant* text, never user
# input. Both paths are fail-OPEN and no-op without PGVECTOR_URL.

def _recall_context(query: str, limit: int = 3) -> str:
    """Return a short context block of semantically-similar past SOVA answers."""
    try:
        from warden.agent import memory
        hits = memory.semantic_search(query, limit=limit)
        if not hits:
            return ""
        lines = ["Relevant findings recalled from past SOVA sessions "
                 "(context only — may be stale, verify against live data):"]
        for h in hits:
            sim = h.get("similarity")
            lines.append(f"- (sim={sim}) {str(h.get('content', ''))[:300]}")
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        log.debug("sova: semantic recall unavailable (fail-open): %s", exc)
        return ""


def _store_memory(session_id: str, text: str) -> None:
    """Persist the final answer's embedding for future semantic recall (no-op
    without pgvector)."""
    if not text:
        return
    try:
        from warden.agent import memory
        memory.store_message_embedding(session_id, "assistant", text)
    except Exception as exc:  # noqa: BLE001
        log.debug("sova: memory store failed (fail-open): %s", exc)


# Tool profiles keep the *offered* tool set smaller for narrow tasks WITHOUT
# breaking Phase-1 prompt caching: each profile is a stable subset selected in
# TOOLS' own order, so its cache prefix is stable across calls. Default "full"
# offers everything (cache-optimal for interactive use). Membership is derived
# from live tool names, so adding a tool never leaves a profile stale.
_CORE_TOOLS = frozenset({
    "get_health", "get_stats", "get_config", "send_slack_alert", "filter_request",
})
_PROFILE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "ops":        ("monitor", "financial", "cost", "billing", "agent", "config",
                   "stat", "impact", "disk", "health", "quota"),
    "community":  ("community", "sep", "obsidian", "reputation", "misp",
                   "publish", "ueciid"),
    "compliance": ("compliance", "art30", "xai", "threat", "report",
                   "remediate", "gap", "incident"),
}
_profiles_cache: dict[str, frozenset[str]] | None = None


def _get_profiles(all_names: frozenset[str]) -> dict[str, frozenset[str]]:
    global _profiles_cache  # noqa: PLW0603
    if _profiles_cache is None:
        _profiles_cache = {
            prof: frozenset(_CORE_TOOLS | {
                n for n in all_names if any(kw in n for kw in kws)
            })
            for prof, kws in _PROFILE_KEYWORDS.items()
        }
    return _profiles_cache


def _select_tools(tool_defs: list[dict], profile: str) -> list[dict]:
    """Return cache-ready tool defs for `profile` (subset in stable TOOLS order)."""
    all_names = frozenset(t["name"] for t in tool_defs)
    profiles = _get_profiles(all_names)
    if profile == "full" or profile not in profiles:
        return _cached_tools(tool_defs)
    allowed = profiles[profile]
    subset = [t for t in tool_defs if t["name"] in allowed]
    return _cached_tools(subset)


# ── Adaptive routing for generic (non-marketplace) queries (Phase 4) ─────────
# Before this, any query without a marketplace ``action_type`` always went to
# Opus (score 1.0). SOVA is an orchestration agent, so we route conservatively:
# generic queries default to Sonnet and escalate to Opus only on complexity or
# MAESTRO-risk signals — never down to Haiku (single-fact retrieval still needs
# multi-tool reasoning here). Opt out with SOVA_ADAPTIVE_ROUTING=false.
_GENERIC_ROUTING = os.getenv("SOVA_ADAPTIVE_ROUTING", "true").lower() in ("1", "true", "yes")
_MAESTRO_ROUTE_WEIGHT: dict[str, float] = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "NONE": 0.0}
_COMPLEX_HINTS: tuple[str, ...] = (
    "why", "root cause", "investigate", "analyz", "correlat", "dispute",
    "escalat", "incident", "recommend", "compliance", "forecast", "predict",
    "rotate", "breach", "remediat", "strateg", "audit", "root-cause",
)


def _route_generic(query: str, maestro_risk: str = "NONE") -> tuple[str, str, float]:
    """Route a plain SOVA query to (model, tier, score): Sonnet by default,
    Opus on complexity / HIGH MAESTRO risk. Honours ROUTER_FORCE_MODEL."""
    from warden.marketplace.model_router import MODEL_OPUS, MODEL_SONNET
    force = os.getenv("ROUTER_FORCE_MODEL", "").strip().lower()
    if force in ("opus", "sonnet"):
        model = MODEL_OPUS if force == "opus" else MODEL_SONNET
        return model, force, 1.0 if force == "opus" else 0.0
    q = query.lower()
    score = 0.30 + min(len(query) / 2000, 1.0) * 0.20
    if any(h in q for h in _COMPLEX_HINTS):
        score += 0.30
    score = min(score + _MAESTRO_ROUTE_WEIGHT.get(maestro_risk.upper(), 0.0), 1.0)
    if score >= 0.65 or maestro_risk.upper() == "HIGH":
        return MODEL_OPUS, "opus", round(score, 3)
    return MODEL_SONNET, "sonnet", round(score, 3)


def _resolve_model(
    query: str, action_type: str | None, maestro_risk: str, round_count: int
) -> tuple[str, str, float]:
    """Pick (model, tier, score) for a run. Marketplace actions use the M2M
    router; generic queries use adaptive routing (or Opus when disabled).
    Fully fail-safe: any error falls back to the Opus default."""
    try:
        from warden.marketplace.model_router import route as _route
        if action_type:
            d = _route(action_type, query, round_count, maestro_risk)
            log.info("sova: routed action=%s → %s (score=%.2f)", action_type, d.tier.upper(), d.score)
            return d.model, d.tier, d.score
        if _GENERIC_ROUTING:
            m, tier, score = _route_generic(query, maestro_risk)
            log.info("sova: adaptive route → %s (score=%.2f)", tier.upper(), score)
            return m, tier, score
        return _MODEL, "opus", 1.0
    except Exception:  # noqa: BLE001
        return _MODEL, "opus", 1.0


_SYSTEM_PROMPT = """You are SOVA (Shadow Operations & Vigilance Agent), the autonomous AI operator for Shadow Warden AI — an enterprise-grade AI security gateway.

Your role is to monitor, analyze, and act on all subsystems:
  • Threat detection pipeline (filter stats, evolution engine, corpus health)
  • Community key management (rotation policy, break glass auditing)
  • Uptime & SLA monitoring (probe results, incident escalation)
  • Financial intelligence (ROI, cost savings, upgrade candidates)
  • Agentic payment control (budget monitoring, rogue agent detection)
  • Compliance & audit (GDPR evidence, SOC 2 snapshots)

Operational principles:
  1. Always check health/stats before recommending actions — base decisions on live data
  2. For key rotation: initiate if community key age > 90 days OR a clearance downgrade occurred
  3. For threat alerts: correlate CVE severity with which tenants are affected
  4. For financial reports: lead with the headline ROI number, then tier breakdown
  5. For incidents: escalate to Slack immediately, then investigate root cause
  6. Be concise but complete — operators need actionable intelligence, not summaries

When using tools, prefer parallel calls where data is independent. Always explain what you found and what action (if any) you took or recommend."""


async def run_query(
    query: str,
    session_id: str = "interactive",
    tenant_id: str = "default",
    max_tokens: int = 4096,
    action_type: str | None = None,
    maestro_risk: str = "NONE",
    round_count: int = 0,
    tool_profile: str = "full",
) -> dict[str, Any]:
    """
    Run a query through SOVA.

    Optional routing parameters:
      action_type   — marketplace action hint for model selection (e.g. "search", "raise_dispute")
      maestro_risk  — MAESTRO threat level: "NONE" | "LOW" | "MEDIUM" | "HIGH"
      round_count   — negotiation rounds elapsed (increases complexity score)

    Returns:
        {
            "response": str,
            "tools_used": list[str],
            "input_tokens": int,
            "output_tokens": int,
            "cache_read_tokens": int,
            "latency_ms": float,
            "routed_model": str,        # which model was selected
            "route_tier": str,          # "haiku" | "sonnet" | "opus"
            "route_score": float,       # complexity score 0-1
        }
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {
            "response": "SOVA is offline — ANTHROPIC_API_KEY not configured.",
            "tools_used": [],
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "latency_ms": 0.0,
        }

    try:
        import anthropic
    except ImportError:
        return {
            "response": "SOVA is offline — anthropic package not installed.",
            "tools_used": [],
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "latency_ms": 0.0,
        }

    from warden.agent import memory
    from warden.agent import tools as _tools

    # Dynamic model routing — marketplace actions use the M2M router; generic
    # queries use adaptive routing (Sonnet default, Opus on complexity/risk).
    _active_model, _route_tier, _route_score = _resolve_model(
        query, action_type, maestro_risk, round_count
    )

    client = anthropic.AsyncAnthropic(api_key=api_key)

    # Structured lifecycle span (fail-open). GDPR: logs query length, never content.
    span = _make_span(tenant_id, _active_model, query)

    # ── Load conversation history ─────────────────────────────────────────────
    history = memory.load_history(session_id)
    history.append({"role": "user", "content": query})

    tools_used: list[str] = []
    total_input  = 0
    total_output = 0
    cache_read   = 0
    t0 = time.perf_counter()

    # Cache the tools prefix once per query — subset by profile, stable order so
    # the cache prefix stays stable per profile ("full" = every tool).
    _cached_tool_defs = _select_tools(_tools.TOOLS, tool_profile)

    # System = cached prompt (stable prefix) + optional recalled-memory block
    # (query-specific, sits AFTER the cache boundary so it never breaks caching).
    system_blocks: list[dict] = [
        {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}},
    ]
    _recalled = _recall_context(query)
    if _recalled:
        system_blocks.append({"type": "text", "text": _recalled})

    # ── Agentic loop ──────────────────────────────────────────────────────────
    for _iteration in range(_MAX_ITER):
        response = await client.messages.create(
            model=_active_model,
            max_tokens=max_tokens,
            system=system_blocks,      # type: ignore[arg-type]
            tools=_cached_tool_defs,   # type: ignore[arg-type]
            messages=history,          # type: ignore[arg-type]
        )

        # Accumulate token usage
        u = response.usage
        total_input  += u.input_tokens
        total_output += u.output_tokens
        cache_read   += getattr(u, "cache_read_input_tokens", 0)

        # ── Check stop reason ─────────────────────────────────────────────────
        if response.stop_reason == "end_turn":
            # Extract final text
            final_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_text += block.text
            history.append({"role": "assistant", "content": final_text})
            memory.save_history(session_id, history)
            _store_memory(session_id, final_text)
            _end_span(span, total_input, total_output, detail=f"tools={len(tools_used)}")
            cost_usd = _record_cost(tenant_id, _active_model, total_input, total_output)
            return {
                "response":          final_text,
                "tools_used":        tools_used,
                "routed_model":      _active_model,
                "route_tier":        _route_tier,
                "route_score":       _route_score,
                "input_tokens":      total_input,
                "output_tokens":     total_output,
                "cache_read_tokens": cache_read,
                "cost_usd":          cost_usd,
                "latency_ms":        round((time.perf_counter() - t0) * 1000, 1),
            }

        if response.stop_reason != "tool_use":
            break

        # ── Process tool calls ────────────────────────────────────────────────
        # Add assistant's tool-use message to history
        history.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if b.type == "tool_use"]

        async def _run_one(block: Any) -> tuple[Any, str, bool]:
            tool_name = block.name
            tool_input = dict(block.input or {})
            # Inject tenant context if not explicitly set
            if "tenant_id" not in tool_input:
                tool_input["tenant_id"] = tenant_id
            log.info("sova: calling tool=%s input=%s", tool_name,
                     json.dumps(tool_input)[:200])
            _span_tool(span, tool_name, phase="call")
            if tool_name not in _tools.TOOL_HANDLERS:
                _span_tool(span, tool_name, phase="result", status="error", detail="unknown tool")
                return block, f"Unknown tool: {tool_name}", True
            try:
                result = await _tools.traced_dispatch(tool_name, tool_input)
                _span_tool(span, tool_name, phase="result", status="ok")
                return block, json.dumps(result, default=str), False
            except Exception as exc:
                log.warning("sova: tool=%s error: %s", tool_name, exc)
                _span_tool(span, tool_name, phase="result", status="error", detail=str(exc))
                return block, f"Tool error: {exc}", True

        for _b in tool_uses:
            tools_used.append(_b.name)

        # Independent tool calls in a round run concurrently — the model is told to
        # prefer parallel calls, so honour that instead of awaiting serially.
        results = await asyncio.gather(*(_run_one(b) for b in tool_uses))

        tool_results = [
            {
                "type":        "tool_result",
                "tool_use_id": block.id,
                "content":     result_content,
                "is_error":    is_error,
            }
            for block, result_content, is_error in results
        ]

        history.append({"role": "user", "content": tool_results})

    # Max iterations reached — ask for summary without tools
    log.warning("sova: max iterations (%d) reached for session=%s", _MAX_ITER, session_id)
    fallback = await client.messages.create(
        model=_active_model,
        max_tokens=1024,
        system=system_blocks,  # type: ignore[arg-type]
        messages=history + [{"role": "user", "content": "Summarize your findings so far in a concise response."}],  # type: ignore[arg-type]
    )
    fu = fallback.usage
    total_input  += fu.input_tokens
    total_output += fu.output_tokens
    cache_read   += getattr(fu, "cache_read_input_tokens", 0)
    final_text = "".join(b.text for b in fallback.content if hasattr(b, "text"))
    history.append({"role": "assistant", "content": final_text})
    memory.save_history(session_id, history)
    _store_memory(session_id, final_text)
    _end_span(span, total_input, total_output, detail="max_iter_fallback")
    cost_usd = _record_cost(tenant_id, _active_model, total_input, total_output)

    return {
        "response":          final_text,
        "tools_used":        tools_used,
        "routed_model":      _active_model,
        "route_tier":        _route_tier,
        "route_score":       _route_score,
        "input_tokens":      total_input,
        "output_tokens":     total_output,
        "cache_read_tokens": cache_read,
        "cost_usd":          cost_usd,
        "latency_ms":        round((time.perf_counter() - t0) * 1000, 1),
    }


async def stream_query(
    query: str,
    session_id: str = "interactive",
    tenant_id: str = "default",
    max_tokens: int = 4096,
    action_type: str | None = None,
    maestro_risk: str = "NONE",
    round_count: int = 0,
    tool_profile: str = "full",
) -> AsyncIterator[dict[str, Any]]:
    """Streaming variant of :func:`run_query` — an async generator of events.

    Event shapes (``type`` field):
      status       {"type":"status","stage":"start","model","tier","score"}
      text         {"type":"text","delta": "..."}          — live answer tokens
      tool_use     {"type":"tool_use","name","round"}       — a tool is about to run
      tool_result  {"type":"tool_result","name","is_error"} — a tool finished
      done         {"type":"done","meta": {...same fields as run_query returns}}
      error        {"type":"error","message"}               — fatal, followed by done

    Runs the identical agentic loop (gate + SAC screen still enforced inside
    ``traced_dispatch``), but streams each round's text and surfaces tool events
    so a UI/SSE endpoint can render progress. Cost, span, memory and routing all
    behave exactly as in ``run_query``.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        yield {"type": "error", "message": "SOVA is offline — ANTHROPIC_API_KEY not configured."}
        return
    try:
        import anthropic
    except ImportError:
        yield {"type": "error", "message": "SOVA is offline — anthropic package not installed."}
        return

    from warden.agent import memory
    from warden.agent import tools as _tools

    active_model, tier, score = _resolve_model(query, action_type, maestro_risk, round_count)
    client = anthropic.AsyncAnthropic(api_key=api_key)
    span = _make_span(tenant_id, active_model, query)

    history = memory.load_history(session_id)
    history.append({"role": "user", "content": query})

    tools_used: list[str] = []
    total_input = 0
    total_output = 0
    cache_read = 0
    t0 = time.perf_counter()

    tool_defs = _select_tools(_tools.TOOLS, tool_profile)
    system_blocks: list[dict] = [
        {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}},
    ]
    _recalled = _recall_context(query)
    if _recalled:
        system_blocks.append({"type": "text", "text": _recalled})

    def _finalize(final_text: str, detail: str) -> dict[str, Any]:
        history.append({"role": "assistant", "content": final_text})
        memory.save_history(session_id, history)
        _store_memory(session_id, final_text)
        _end_span(span, total_input, total_output, detail=detail)
        cost = _record_cost(tenant_id, active_model, total_input, total_output)
        return {
            "response":          final_text,
            "tools_used":        tools_used,
            "routed_model":      active_model,
            "route_tier":        tier,
            "route_score":       score,
            "input_tokens":      total_input,
            "output_tokens":     total_output,
            "cache_read_tokens": cache_read,
            "cost_usd":          cost,
            "latency_ms":        round((time.perf_counter() - t0) * 1000, 1),
        }

    yield {"type": "status", "stage": "start", "model": active_model, "tier": tier, "score": score}

    for _iteration in range(_MAX_ITER):
        round_text: list[str] = []
        async with client.messages.stream(
            model=active_model,
            max_tokens=max_tokens,
            system=system_blocks,      # type: ignore[arg-type]
            tools=tool_defs,           # type: ignore[arg-type]
            messages=history,          # type: ignore[arg-type]
        ) as stream:
            async for delta in stream.text_stream:
                round_text.append(delta)
                yield {"type": "text", "delta": delta}
            final = await stream.get_final_message()

        u = final.usage
        total_input  += u.input_tokens
        total_output += u.output_tokens
        cache_read   += getattr(u, "cache_read_input_tokens", 0)

        if final.stop_reason == "end_turn":
            yield {"type": "done", "meta": _finalize("".join(round_text), f"tools={len(tools_used)}")}
            return

        if final.stop_reason != "tool_use":
            yield {"type": "done", "meta": _finalize("".join(round_text), "stop_" + str(final.stop_reason))}
            return

        # ── Tool round (same parallel dispatch as run_query) ──────────────────
        history.append({"role": "assistant", "content": final.content})
        tool_uses = [b for b in final.content if b.type == "tool_use"]

        async def _run_one(block: Any) -> tuple[Any, str, bool]:
            tool_name = block.name
            tool_input = dict(block.input or {})
            if "tenant_id" not in tool_input:
                tool_input["tenant_id"] = tenant_id
            _span_tool(span, tool_name, phase="call")
            if tool_name not in _tools.TOOL_HANDLERS:
                _span_tool(span, tool_name, phase="result", status="error", detail="unknown tool")
                return block, f"Unknown tool: {tool_name}", True
            try:
                result = await _tools.traced_dispatch(tool_name, tool_input)
                _span_tool(span, tool_name, phase="result", status="ok")
                return block, json.dumps(result, default=str), False
            except Exception as exc:  # noqa: BLE001
                log.warning("sova.stream: tool=%s error: %s", tool_name, exc)
                _span_tool(span, tool_name, phase="result", status="error", detail=str(exc))
                return block, f"Tool error: {exc}", True

        for _b in tool_uses:
            tools_used.append(_b.name)
            yield {"type": "tool_use", "name": _b.name, "round": _iteration}

        results = await asyncio.gather(*(_run_one(b) for b in tool_uses))
        tool_results = [
            {"type": "tool_result", "tool_use_id": block.id, "content": content, "is_error": is_error}
            for block, content, is_error in results
        ]
        for block, _content, is_error in results:
            yield {"type": "tool_result", "name": block.name, "is_error": is_error}

        history.append({"role": "user", "content": tool_results})

    # Max iterations reached — stream a final summary without tools.
    log.warning("sova.stream: max iterations (%d) reached for session=%s", _MAX_ITER, session_id)
    summary_parts: list[str] = []
    async with client.messages.stream(
        model=active_model,
        max_tokens=1024,
        system=system_blocks,      # type: ignore[arg-type]
        messages=history + [{"role": "user", "content": "Summarize your findings so far in a concise response."}],  # type: ignore[arg-type]
    ) as stream:
        async for delta in stream.text_stream:
            summary_parts.append(delta)
            yield {"type": "text", "delta": delta}
        final = await stream.get_final_message()
    fu = final.usage
    total_input  += fu.input_tokens
    total_output += fu.output_tokens
    cache_read   += getattr(fu, "cache_read_input_tokens", 0)
    yield {"type": "done", "meta": _finalize("".join(summary_parts), "max_iter_fallback")}


async def run_task(
    task: str, session_id: str | None = None, tool_profile: str = "full"
) -> str:
    """Convenience wrapper for scheduled jobs — returns text response only.

    Scheduled jobs may pass a narrow ``tool_profile`` ("ops" | "community" |
    "compliance") to shrink the offered tool set for cheaper, focused runs.
    """
    sid = session_id or f"sched-{task[:20].replace(' ', '-')}"
    result = await run_query(task, session_id=sid, tool_profile=tool_profile)
    return result["response"]
