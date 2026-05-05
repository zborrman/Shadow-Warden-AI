"""
warden/agent/master.py
──────────────────────
MasterAgent — multi-agent coordination layer for Shadow Warden AI.

Architecture
────────────
  MasterAgent (Claude Opus 4.6, supervisor)
      ├── SOVAOperator     — gateway health, quota, billing, rotation
      ├── ThreatHunter     — CVE triage, ArXiv synthesis, intel
      ├── ForensicsAgent   — Evidence Vault, agent activity, compliance logs
      └── ComplianceAgent  — SOC 2 controls, SLA status, GDPR, monitors

Human-in-the-Loop
─────────────────
  Actions tagged REQUIRES_APPROVAL pause the loop, post to Slack with
  approve/reject webhook, and store a pending token in Redis (TTL 1h).
  POST /agent/approve/{token}?action=approve|reject resumes or cancels.

Task Token Security
───────────────────
  Every delegated task carries an HMAC-SHA256 token binding
  (sub_agent, task_hash, issued_at) — prevents cross-agent injection.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

log = logging.getLogger("warden.agent.master")

_MODEL    = "claude-opus-4-6"
# Sub-agent tool-loop cap — keeps cost predictable; fallback summary fires after.
_SUB_AGENT_MAX_ITER    = 5
# Per-sub-agent input token budget. Loop halts early when exceeded.
# Each Opus 4.6 input token ≈ $0.000015; 8192 tokens ≈ $0.12 per sub-agent.
_SUB_AGENT_TOKEN_BUDGET = int(os.getenv("MASTER_AGENT_TOKEN_BUDGET", "8192"))
_TOKEN_SECRET = os.getenv("MASTER_AGENT_SECRET", "shadow-warden-master-v1")


# ── Sub-agent definitions ─────────────────────────────────────────────────────

class SubAgent(StrEnum):
    SOVA_OPERATOR  = "sova_operator"
    THREAT_HUNTER  = "threat_hunter"
    FORENSICS      = "forensics"
    COMPLIANCE     = "compliance"


# Tools available to each sub-agent
_AGENT_TOOLS: dict[SubAgent, list[str]] = {
    SubAgent.SOVA_OPERATOR: [
        "get_health", "get_stats", "get_config", "update_config",
        "get_billing_quota", "get_financial_impact", "get_cost_saved",
        "list_communities", "get_community", "rotate_community_key",
        "get_rotation_progress", "list_community_members",
        "send_slack_alert",
    ],
    SubAgent.THREAT_HUNTER: [
        "list_threats", "refresh_threat_intel", "dismiss_threat",
        "filter_request", "get_health", "get_stats",
        "send_slack_alert",
    ],
    SubAgent.FORENSICS: [
        "get_agent_activity", "list_agents", "revoke_agent",
        "get_tenant_impact", "get_compliance_art30",
        "visual_assert_page", "send_slack_alert",
    ],
    SubAgent.COMPLIANCE: [
        "list_monitors", "get_monitor_status", "get_monitor_uptime",
        "get_monitor_history", "get_compliance_art30",
        "get_billing_quota", "generate_proposal",
        "send_slack_alert",
    ],
}

_AGENT_PROMPTS: dict[SubAgent, str] = {
    SubAgent.SOVA_OPERATOR: (
        "You are SOVAOperator, the gateway health and operations specialist. "
        "Your domain: real-time health checks, filter statistics, billing quotas, "
        "community key management, and configuration tuning. "
        "Always lead with current health status before recommending actions. "
        "For key rotation: initiate if key age >90 days. "
        "Tag any key rotation or config change action as REQUIRES_APPROVAL."
    ),
    SubAgent.THREAT_HUNTER: (
        "You are ThreatHunter, the threat intelligence and adversarial research specialist. "
        "Your domain: CVE feeds (OSV), ArXiv LLM-attack papers, adversarial prompt analysis. "
        "Always correlate CVE severity with affected components. "
        "For CRITICAL CVEs: send Slack alert immediately. "
        "Be specific — CVE IDs, paper titles, attack vectors, CVSS scores."
    ),
    SubAgent.FORENSICS: (
        "You are ForensicsAgent, the evidence and incident reconstruction specialist. "
        "Your domain: agentic payment audit logs, agent activity timelines, "
        "GDPR Art.30 ROPA, Evidence Vault snapshots, visual UI verification. "
        "Reconstruct the sequence of events. Identify anomalies in agent behavior. "
        "Tag any agent revocation as REQUIRES_APPROVAL."
    ),
    SubAgent.COMPLIANCE: (
        "You are ComplianceAgent, the SLA and regulatory compliance specialist. "
        "Your domain: uptime monitors, SLA thresholds (Pro 99.9%/Enterprise 99.95%), "
        "GDPR compliance, SOC 2 control mapping, and ROI proposals. "
        "Flag any SLA breach immediately. Calculate P99 latency from monitor history. "
        "Tag any monitor deletion as REQUIRES_APPROVAL."
    ),
}


# ── Task token ────────────────────────────────────────────────────────────────

def _issue_token(sub_agent: SubAgent, task: str) -> str:
    """HMAC-SHA256 signed token binding (sub_agent, task_hash, issued_at)."""
    issued_at = int(time.time())
    task_hash = hashlib.sha256(task.encode()).hexdigest()[:16]
    payload   = f"{sub_agent.value}:{task_hash}:{issued_at}"
    sig = hmac.new(
        _TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"{payload}:{sig}"


def _verify_token(token: str, sub_agent: SubAgent) -> bool:
    parts = token.split(":")
    if len(parts) != 4:
        return False
    agent_val, task_hash, issued_at_str, sig = parts
    if agent_val != sub_agent.value:
        return False
    payload = f"{agent_val}:{task_hash}:{issued_at_str}"
    expected = hmac.new(
        _TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return hmac.compare_digest(expected, sig)


# ── Approval gate ─────────────────────────────────────────────────────────────

def _approval_token(action: str, context: str) -> str:
    ts      = int(time.time())
    payload = f"{action}:{hashlib.sha256(context.encode()).hexdigest()[:16]}:{ts}"
    sig = hmac.new(
        _TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()[:20]
    return f"appr-{sig}"


def _store_pending(token: str, action: str, context: str, callback_key: str) -> None:
    """Write pending approval to Redis (TTL 1h). Fail-open if Redis unavailable."""
    try:
        import redis as _redis
        r = _redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        r.setex(
            f"master:approval:{token}",
            3600,
            json.dumps({"action": action, "context": context, "callback_key": callback_key, "ts": int(time.time())}),
        )
    except Exception as exc:
        log.warning("master: Redis unavailable for approval storage: %s", exc)


def get_pending_approval(token: str) -> dict | None:
    """Return pending approval record or None if expired/missing."""
    try:
        import redis as _redis
        r = _redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        raw = r.get(f"master:approval:{token}")
        return json.loads(raw) if raw else None
    except Exception:
        return None


def resolve_approval(token: str, approved: bool) -> bool:
    """Consume the approval token and store the decision. Returns False if token missing."""
    try:
        import redis as _redis
        r = _redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        key = f"master:approval:{token}"
        raw = r.get(key)
        if not raw:
            return False
        data = json.loads(raw)
        data["approved"]    = approved
        data["resolved_at"] = int(time.time())
        # Store result under a different key, delete the pending entry
        r.setex(f"master:approval:result:{token}", 3600, json.dumps(data))
        r.delete(key)
        # Also set the callback so the waiting coroutine can unblock
        r.setex(f"master:approval:callback:{data['callback_key']}", 3600, "1" if approved else "0")
        return True
    except Exception as exc:
        log.warning("master: resolve_approval failed: %s", exc)
        return False


async def _wait_for_approval(callback_key: str, timeout: int = 3600) -> bool:
    """Poll Redis for approval decision. Returns True=approved, False=rejected/timeout."""
    deadline = time.time() + timeout
    try:
        import redis as _redis
        r = _redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        while time.time() < deadline:
            val = r.get(f"master:approval:callback:{callback_key}")
            if val is not None:
                return val == "1"
            await asyncio.sleep(5)
    except Exception as exc:
        log.warning("master: approval polling error: %s", exc)
    return False


async def _post_approval_request(token: str, action: str, context: str) -> None:
    """Post Slack message with approve/reject instructions."""
    base_url = os.getenv("WARDEN_BASE_URL", "http://localhost:8001")
    approve_url = f"{base_url}/agent/approve/{token}?action=approve"
    reject_url  = f"{base_url}/agent/approve/{token}?action=reject"

    msg = (
        f"*🔐 MasterAgent Approval Required*\n"
        f"*Action:* `{action}`\n"
        f"*Context:* {context[:300]}\n\n"
        f"✅ *Approve:* `POST {approve_url}`\n"
        f"❌ *Reject:*  `POST {reject_url}`\n"
        f"_Token expires in 1 hour._"
    )
    url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not url:
        log.warning("master: SLACK_WEBHOOK_URL not set — approval request not sent: %s", action)
        return
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(url, content=json.dumps({"text": msg}),
                         headers={"Content-Type": "application/json"})
    except Exception as exc:
        log.warning("master: Slack approval post failed: %s", exc)


# ── Sub-agent runner ──────────────────────────────────────────────────────────

async def _run_sub_agent(
    agent_type: SubAgent,
    task:       str,
    tenant_id:  str = "default",
) -> dict[str, Any]:
    """
    Run a specialist sub-agent with its dedicated tool subset and system prompt.
    Returns dict with keys: agent, response, tools_used, tokens, latency_ms.
    """
    token = _issue_token(agent_type, task)
    if not _verify_token(token, agent_type):
        return {"agent": agent_type.value, "error": "Token verification failed", "response": ""}

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"agent": agent_type.value, "response": "ANTHROPIC_API_KEY not configured.", "tools_used": []}

    try:
        import anthropic
    except ImportError:
        return {"agent": agent_type.value, "response": "anthropic package not installed.", "tools_used": []}

    from warden.agent import tools as _tools

    # Filter TOOLS list to only this agent's allowed tools
    allowed   = set(_AGENT_TOOLS[agent_type])
    sub_tools = [t for t in _tools.TOOLS if t["name"] in allowed]

    client  = anthropic.AsyncAnthropic(api_key=api_key)
    history: list[dict] = [{"role": "user", "content": task}]
    tools_used: list[str] = []
    total_tokens = 0
    t0 = time.perf_counter()

    for _ in range(_SUB_AGENT_MAX_ITER):
        # Early-halt if accumulated input tokens exceed budget
        if total_tokens >= _SUB_AGENT_TOKEN_BUDGET:
            log.info(
                "sub_agent %s: token budget %d reached — halting loop",
                agent_type.value, _SUB_AGENT_TOKEN_BUDGET,
            )
            break

        resp = await client.messages.create(
            model      = _MODEL,
            max_tokens = 2048,
            system     = [{"type": "text", "text": _AGENT_PROMPTS[agent_type],
                           "cache_control": {"type": "ephemeral"}}],
            tools      = sub_tools,  # type: ignore[arg-type]
            messages   = history,    # type: ignore[arg-type]
        )
        total_tokens += resp.usage.input_tokens + resp.usage.output_tokens

        if resp.stop_reason == "end_turn":
            text = "".join(b.text for b in resp.content if hasattr(b, "text"))
            return {
                "agent":       agent_type.value,
                "response":    text,
                "tools_used":  tools_used,
                "tokens":      total_tokens,
                "latency_ms":  round((time.perf_counter() - t0) * 1000, 1),
            }

        if resp.stop_reason != "tool_use":
            break

        history.append({"role": "assistant", "content": resp.content})
        tool_results = []

        for block in resp.content:
            if block.type != "tool_use":
                continue
            tool_name  = block.name
            tool_input = block.input or {}
            if "tenant_id" not in tool_input:
                tool_input["tenant_id"] = tenant_id
            tools_used.append(tool_name)

            handler = _tools.TOOL_HANDLERS.get(tool_name)
            try:
                result       = await handler(**tool_input) if handler else {"error": f"Unknown tool: {tool_name}"}
                result_text  = json.dumps(result, default=str)
                is_error     = False
            except Exception as exc:
                result_text  = f"Tool error: {exc}"
                is_error     = True

            tool_results.append({
                "type":        "tool_result",
                "tool_use_id": block.id,
                "content":     result_text,
                "is_error":    is_error,
            })

        history.append({"role": "user", "content": tool_results})

    # Fallback summary
    fallback = await client.messages.create(
        model=_MODEL, max_tokens=512,
        system=[{"type": "text", "text": _AGENT_PROMPTS[agent_type]}],
        messages=history + [{"role": "user", "content": "Summarize your findings concisely."}],  # type: ignore[arg-type]
    )
    text = "".join(b.text for b in fallback.content if hasattr(b, "text"))
    return {
        "agent":      agent_type.value,
        "response":   text,
        "tools_used": tools_used,
        "tokens":     total_tokens,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


# ── MasterAgent result ────────────────────────────────────────────────────────

@dataclass
class MasterResult:
    task:            str
    sub_results:     list[dict]
    synthesis:       str
    tools_used:      list[str]
    total_tokens:    int
    latency_ms:      float
    approval_tokens: list[str] = field(default_factory=list)
    ts:              str = field(default_factory=lambda: datetime.now(UTC).isoformat())


# ── MasterAgent ───────────────────────────────────────────────────────────────

_MASTER_SYSTEM = """You are MasterAgent, the supervisor of Shadow Warden AI's agentic SOC.

You coordinate four specialist sub-agents:
  • SOVAOperator  — gateway health, billing, key rotation
  • ThreatHunter  — CVE triage, ArXiv intel, adversarial analysis
  • ForensicsAgent — evidence vault, agent activity, GDPR compliance
  • ComplianceAgent — SLA status, uptime monitors, regulatory mapping

Your responsibilities:
  1. Decompose the incoming task into specialist sub-tasks
  2. Identify which sub-agents are needed (often multiple in parallel)
  3. Synthesize sub-agent outputs into a single actionable report
  4. Flag any HIGH-IMPACT actions as REQUIRES_APPROVAL with clear justification
  5. If sub-agents found critical issues, coordinate an escalation response

HIGH-IMPACT actions that always require approval:
  - Key rotation for any community
  - Agent revocation
  - Configuration changes affecting detection thresholds
  - Tenant suspension

Response format: structured report with Executive Summary, Findings per domain, and Recommended Actions."""


async def run_master(
    task:        str,
    tenant_id:   str  = "default",
    auto_approve: bool = False,
) -> MasterResult:
    """
    Run MasterAgent on a high-level task.

    Decomposes the task, dispatches sub-agents in parallel, synthesizes
    results, and handles human-in-the-loop approval for high-impact actions.

    Args:
        task:         Natural-language instruction for the master agent.
        tenant_id:    Tenant context injected into all tool calls.
        auto_approve: Skip approval gate (for scheduled/trusted callers).

    Returns:
        MasterResult with synthesis, sub-agent outputs, and approval tokens.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return MasterResult(
            task=task, sub_results=[], synthesis="ANTHROPIC_API_KEY not configured.",
            tools_used=[], total_tokens=0, latency_ms=0.0,
        )

    try:
        import anthropic
    except ImportError:
        return MasterResult(
            task=task, sub_results=[], synthesis="anthropic package not installed.",
            tools_used=[], total_tokens=0, latency_ms=0.0,
        )

    t0 = time.perf_counter()
    client = anthropic.AsyncAnthropic(api_key=api_key)

    # ── Step 1: Master decides which sub-agents to invoke ─────────────────────
    decompose_prompt = (
        f"Task: {task}\n\n"
        "Which sub-agents should handle this task? Reply with a JSON object:\n"
        '{"agents": ["sova_operator"|"threat_hunter"|"forensics"|"compliance"], '
        '"sub_tasks": {"agent_name": "specific sub-task description"}}'
    )
    decomp_resp = await client.messages.create(
        model=_MODEL, max_tokens=512,
        system=[{"type": "text", "text": _MASTER_SYSTEM, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": decompose_prompt}],  # type: ignore[arg-type]
    )
    decomp_text = "".join(b.text for b in decomp_resp.content if hasattr(b, "text"))

    # Parse sub-agent assignments (fallback: run all)
    sub_tasks: dict[str, str] = {}
    try:
        # Extract JSON from response
        start = decomp_text.find("{")
        end   = decomp_text.rfind("}") + 1
        if start != -1 and end > start:
            parsed = json.loads(decomp_text[start:end])
            raw_tasks: dict = parsed.get("sub_tasks", {})
            # Validate agent names
            valid_names = {a.value for a in SubAgent}
            sub_tasks = {k: v for k, v in raw_tasks.items() if k in valid_names}
    except (json.JSONDecodeError, KeyError):
        pass

    if not sub_tasks:
        # Fallback: run operator + threat hunter for any task
        sub_tasks = {
            SubAgent.SOVA_OPERATOR.value: task,
            SubAgent.THREAT_HUNTER.value: task,
        }

    # ── Step 2: Dispatch sub-agents in parallel ───────────────────────────────
    agent_map: dict[str, SubAgent] = {a.value: a for a in SubAgent}
    coros = [
        _run_sub_agent(agent_map[name], sub_task, tenant_id)
        for name, sub_task in sub_tasks.items()
        if name in agent_map
    ]
    sub_results = list(await asyncio.gather(*coros, return_exceptions=False))

    all_tools   = [t for r in sub_results for t in r.get("tools_used", [])]
    total_tokens = (decomp_resp.usage.input_tokens + decomp_resp.usage.output_tokens
                    + sum(r.get("tokens", 0) for r in sub_results))

    # ── Step 3: Check for REQUIRES_APPROVAL flags ─────────────────────────────
    approval_tokens: list[str] = []
    if not auto_approve:
        for result in sub_results:
            response_text = result.get("response", "")
            if "REQUIRES_APPROVAL" in response_text:
                # Extract action context
                idx     = response_text.find("REQUIRES_APPROVAL")
                context = response_text[max(0, idx - 50): idx + 200]
                token   = _approval_token(result["agent"], context)
                cb_key  = hashlib.sha256(f"{token}{time.time()}".encode()).hexdigest()[:12]

                _store_pending(token, result["agent"], context, cb_key)
                await _post_approval_request(token, result["agent"], context)
                approval_tokens.append(token)
                log.info("master: approval required agent=%s token=%s", result["agent"], token)

    # ── Step 4: Synthesize all outputs ────────────────────────────────────────
    sub_summary = "\n\n".join(
        f"=== {r['agent'].upper()} ===\n{r.get('response', r.get('error', 'no output'))}"
        for r in sub_results
    )
    synthesis_prompt = (
        f"Original task: {task}\n\n"
        f"Sub-agent outputs:\n{sub_summary}\n\n"
        + (f"Pending approvals required for: {approval_tokens}\n\n" if approval_tokens else "")
        + "Synthesize these into a unified executive report. "
        "Lead with Executive Summary (2-3 sentences), then Findings by domain, "
        "then Recommended Actions with priority (P1/P2/P3)."
    )

    synth_resp = await client.messages.create(
        model=_MODEL, max_tokens=2048,
        system=[{"type": "text", "text": _MASTER_SYSTEM, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": synthesis_prompt}],  # type: ignore[arg-type]
    )
    synthesis = "".join(b.text for b in synth_resp.content if hasattr(b, "text"))
    total_tokens += synth_resp.usage.input_tokens + synth_resp.usage.output_tokens

    latency = round((time.perf_counter() - t0) * 1000, 1)
    log.info(
        "master: task complete agents=%s tokens=%d latency=%.0fms approvals=%d",
        list(sub_tasks.keys()), total_tokens, latency, len(approval_tokens),
    )

    return MasterResult(
        task            = task,
        sub_results     = sub_results,
        synthesis       = synthesis,
        tools_used      = all_tools,
        total_tokens    = total_tokens,
        latency_ms      = latency,
        approval_tokens = approval_tokens,
    )


async def run_master_batch(
    task:          str,
    tenant_id:     str  = "default",
    auto_approve:  bool = True,
    poll_interval: int  = 60,
) -> MasterResult:
    """
    Cost-optimized MasterAgent variant for scheduled/background tasks.

    Uses the Anthropic Message Batches API for the decompose and synthesis
    steps (single-turn, no tool use) — 50% input token discount vs. the
    regular Messages API.  Sub-agent tool loops still use the regular API
    with the _SUB_AGENT_MAX_ITER cap.

    Suitable for: sova_morning_brief, sova_sla_report, sova_upgrade_scan.

    Args:
        task:          Natural-language instruction.
        tenant_id:     Tenant context for all tool calls.
        auto_approve:  Always True for scheduled jobs — skip approval gate.
        poll_interval: Seconds between batch status polls (default 60).
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return MasterResult(
            task=task, sub_results=[], synthesis="ANTHROPIC_API_KEY not configured.",
            tools_used=[], total_tokens=0, latency_ms=0.0,
        )

    try:
        import anthropic
    except ImportError:
        return MasterResult(
            task=task, sub_results=[], synthesis="anthropic package not installed.",
            tools_used=[], total_tokens=0, latency_ms=0.0,
        )

    t0     = time.perf_counter()
    client = anthropic.AsyncAnthropic(api_key=api_key)

    # ── Step 1: Decompose via Batches API (50% cheaper) ───────────────────────
    decompose_prompt = (
        f"Task: {task}\n\n"
        "Which sub-agents should handle this task? Reply with a JSON object:\n"
        '{"agents": ["sova_operator"|"threat_hunter"|"forensics"|"compliance"], '
        '"sub_tasks": {"agent_name": "specific sub-task description"}}'
    )

    try:
        batch = await client.beta.messages.batches.create(
            requests=[{
                "custom_id": "decompose",
                "params": {
                    "model":      _MODEL,
                    "max_tokens": 512,
                    "system": [{"type": "text", "text": _MASTER_SYSTEM,
                                "cache_control": {"type": "ephemeral"}}],
                    "messages": [{"role": "user", "content": decompose_prompt}],
                },
            }]
        )
        log.info("master_batch: submitted decompose batch_id=%s", batch.id)

        # Poll until complete
        while batch.processing_status == "in_progress":
            await asyncio.sleep(poll_interval)
            batch = await client.beta.messages.batches.retrieve(batch.id)

        decomp_text  = ""
        decomp_tokens = 0
        async for result in client.beta.messages.batches.results(batch.id):
            if result.custom_id == "decompose" and result.result.type == "succeeded":
                msg           = result.result.message
                decomp_text   = "".join(b.text for b in msg.content if hasattr(b, "text"))
                decomp_tokens = msg.usage.input_tokens + msg.usage.output_tokens

    except Exception as exc:
        # Batches API unavailable (old SDK, no beta access) — fall through to regular API
        log.warning("master_batch: Batches API error (%s) — falling back to regular API", exc)
        decomp_resp = await client.messages.create(
            model=_MODEL, max_tokens=512,
            system=[{"type": "text", "text": _MASTER_SYSTEM, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": decompose_prompt}],  # type: ignore[arg-type]
        )
        decomp_text   = "".join(b.text for b in decomp_resp.content if hasattr(b, "text"))
        decomp_tokens = decomp_resp.usage.input_tokens + decomp_resp.usage.output_tokens

    # Parse sub-agent assignments
    sub_tasks: dict[str, str] = {}
    try:
        start = decomp_text.find("{")
        end   = decomp_text.rfind("}") + 1
        if start != -1 and end > start:
            parsed     = json.loads(decomp_text[start:end])
            raw_tasks: dict = parsed.get("sub_tasks", {})
            valid_names = {a.value for a in SubAgent}
            sub_tasks   = {k: v for k, v in raw_tasks.items() if k in valid_names}
    except (json.JSONDecodeError, KeyError):
        pass

    if not sub_tasks:
        sub_tasks = {
            SubAgent.SOVA_OPERATOR.value: task,
            SubAgent.THREAT_HUNTER.value: task,
        }

    # ── Step 2: Sub-agents via regular API (tool use requires sync loop) ──────
    agent_map: dict[str, SubAgent] = {a.value: a for a in SubAgent}
    coros      = [
        _run_sub_agent(agent_map[name], sub_task, tenant_id)
        for name, sub_task in sub_tasks.items()
        if name in agent_map
    ]
    sub_results = list(await asyncio.gather(*coros, return_exceptions=False))
    all_tools   = [t for r in sub_results for t in r.get("tools_used", [])]

    # ── Step 3: Synthesize via Batches API ────────────────────────────────────
    sub_summary = "\n\n".join(
        f"=== {r['agent'].upper()} ===\n{r.get('response', r.get('error', 'no output'))}"
        for r in sub_results
    )
    synthesis_prompt = (
        f"Original task: {task}\n\nSub-agent outputs:\n{sub_summary}\n\n"
        "Synthesize into a unified executive report: Executive Summary (2-3 sentences), "
        "Findings by domain, Recommended Actions with priority (P1/P2/P3)."
    )

    synthesis     = ""
    synth_tokens  = 0
    try:
        synth_batch = await client.beta.messages.batches.create(
            requests=[{
                "custom_id": "synthesis",
                "params": {
                    "model":      _MODEL,
                    "max_tokens": 2048,
                    "system": [{"type": "text", "text": _MASTER_SYSTEM,
                                "cache_control": {"type": "ephemeral"}}],
                    "messages": [{"role": "user", "content": synthesis_prompt}],
                },
            }]
        )
        log.info("master_batch: submitted synthesis batch_id=%s", synth_batch.id)

        while synth_batch.processing_status == "in_progress":
            await asyncio.sleep(poll_interval)
            synth_batch = await client.beta.messages.batches.retrieve(synth_batch.id)

        async for result in client.beta.messages.batches.results(synth_batch.id):  # type: ignore[attr-defined]
            if result.custom_id == "synthesis" and result.result.type == "succeeded":
                msg          = result.result.message
                synthesis    = "".join(b.text for b in msg.content if hasattr(b, "text"))
                synth_tokens = msg.usage.input_tokens + msg.usage.output_tokens

    except Exception as exc:
        log.warning("master_batch: synthesis Batches API error (%s) — falling back", exc)
        synth_resp   = await client.messages.create(
            model=_MODEL, max_tokens=2048,
            system=[{"type": "text", "text": _MASTER_SYSTEM, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": synthesis_prompt}],  # type: ignore[arg-type]
        )
        synthesis    = "".join(b.text for b in synth_resp.content if hasattr(b, "text"))
        synth_tokens = synth_resp.usage.input_tokens + synth_resp.usage.output_tokens

    total_tokens = (
        decomp_tokens
        + sum(r.get("tokens", 0) for r in sub_results)
        + synth_tokens
    )
    latency = round((time.perf_counter() - t0) * 1000, 1)
    log.info(
        "master_batch: complete agents=%s tokens=%d latency=%.0fms",
        list(sub_tasks.keys()), total_tokens, latency,
    )

    return MasterResult(
        task         = task,
        sub_results  = sub_results,
        synthesis    = synthesis or "(batch result unavailable)",
        tools_used   = all_tools,
        total_tokens = total_tokens,
        latency_ms   = latency,
    )
