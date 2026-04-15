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

import json
import logging
import os
import time
from typing import Any

log = logging.getLogger("warden.agent.sova")

_MODEL    = "claude-opus-4-6"
_MAX_ITER = 10      # max tool-use rounds before forcing a final answer

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
) -> dict[str, Any]:
    """
    Run a query through SOVA.

    Returns:
        {
            "response": str,          # final text answer
            "tools_used": list[str],  # names of tools called
            "input_tokens": int,
            "output_tokens": int,
            "cache_read_tokens": int,
            "latency_ms": float,
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

    client = anthropic.AsyncAnthropic(api_key=api_key)

    # ── Load conversation history ─────────────────────────────────────────────
    history = memory.load_history(session_id)
    history.append({"role": "user", "content": query})

    tools_used: list[str] = []
    total_input  = 0
    total_output = 0
    cache_read   = 0
    t0 = time.perf_counter()

    # ── Agentic loop ──────────────────────────────────────────────────────────
    for _iteration in range(_MAX_ITER):
        response = await client.messages.create(
            model=_MODEL,
            max_tokens=max_tokens,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},   # cache system prompt
                }
            ],
            tools=_tools.TOOLS,      # type: ignore[arg-type]
            messages=history,         # type: ignore[arg-type]
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
            return {
                "response":          final_text,
                "tools_used":        tools_used,
                "input_tokens":      total_input,
                "output_tokens":     total_output,
                "cache_read_tokens": cache_read,
                "latency_ms":        round((time.perf_counter() - t0) * 1000, 1),
            }

        if response.stop_reason != "tool_use":
            break

        # ── Process tool calls ────────────────────────────────────────────────
        # Add assistant's tool-use message to history
        history.append({"role": "assistant", "content": response.content})

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name = block.name
            tool_input = block.input or {}
            # Inject tenant context if not explicitly set
            if "tenant_id" not in tool_input:
                tool_input["tenant_id"] = tenant_id

            tools_used.append(tool_name)
            log.info("sova: calling tool=%s input=%s", tool_name,
                     json.dumps(tool_input)[:200])

            handler = _tools.TOOL_HANDLERS.get(tool_name)
            if handler is None:
                result_content = f"Unknown tool: {tool_name}"
                is_error = True
            else:
                try:
                    result = await handler(**tool_input)
                    result_content = json.dumps(result, default=str)
                    is_error = False
                except Exception as exc:
                    log.warning("sova: tool=%s error: %s", tool_name, exc)
                    result_content = f"Tool error: {exc}"
                    is_error = True

            tool_results.append({
                "type":        "tool_result",
                "tool_use_id": block.id,
                "content":     result_content,
                "is_error":    is_error,
            })

        history.append({"role": "user", "content": tool_results})

    # Max iterations reached — ask for summary without tools
    log.warning("sova: max iterations (%d) reached for session=%s", _MAX_ITER, session_id)
    fallback = await client.messages.create(
        model=_MODEL,
        max_tokens=1024,
        system=[{"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        messages=history + [{"role": "user", "content": "Summarize your findings so far in a concise response."}],  # type: ignore[arg-type]
    )
    final_text = "".join(b.text for b in fallback.content if hasattr(b, "text"))
    history.append({"role": "assistant", "content": final_text})
    memory.save_history(session_id, history)

    return {
        "response":          final_text,
        "tools_used":        tools_used,
        "input_tokens":      total_input,
        "output_tokens":     total_output,
        "cache_read_tokens": cache_read,
        "latency_ms":        round((time.perf_counter() - t0) * 1000, 1),
    }


async def run_task(task: str, session_id: str | None = None) -> str:
    """Convenience wrapper for scheduled jobs — returns text response only."""
    sid = session_id or f"sched-{task[:20].replace(' ', '-')}"
    result = await run_query(task, session_id=sid)
    return result["response"]
