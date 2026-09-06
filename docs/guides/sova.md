# SOVA Agent Guide

SOVA (Shadow Operations & Vigilance Agent) is an autonomous Claude Opus 4.6
agentic loop. It runs both on-demand (REST API) and on schedule (ARQ cron jobs).

**Tool surface:** 50 handlers — 38 read-only (default) + 12 state-changing
("operator") tools. The read set is all that `POST /agent/sova` exposes unless
the request sets `operator_mode: true` (Pro+). Every operator tool is
additionally approval-gated (see *Approval gate* below).

**Tenant binding:** `tenant_id` is taken from the API key — it is never read
from the request body and the model cannot choose it.

**Cost guards:** per-call timeout (`SOVA_CALL_TIMEOUT_S`, 90s), overall deadline
(`SOVA_DEADLINE_S`, 240s), token budget (`SOVA_TOKEN_BUDGET`, 60k). Every SOVA /
MasterAgent / Healer LLM call is costed and written to the cost-allocation
ledger (`vendor=anthropic`, `department=ai-agents`).

---

## How It Works

```mermaid
sequenceDiagram
    participant Caller
    participant API as POST /agent/sova
    participant SOVA as SOVA Core
    participant Tools as 37 Tool Handlers
    participant Memory as Redis Memory

    Caller->>API: { "query": "Check community health" }
    API->>Memory: load session history (6h TTL, 20-turn cap)
    API->>SOVA: run_query(query, session_id)
    loop ≤10 iterations
        SOVA->>Tools: tool_use block
        Tools->>SOVA: tool_result
    end
    SOVA->>Memory: save updated history
    SOVA-->>API: final response
    API-->>Caller: { "response": "...", "session_id": "..." }
```

---

## REST API

### Query SOVA

```bash
POST /agent/sova
Content-Type: application/json

{
  "query":      "What is the current bypass rate and should I be concerned?",
  "session_id": "my-session-01"
}
```

Session memory persists for 6 hours with a 20-turn cap. Omit `session_id`
for a stateless one-shot query.

### Clear session

```bash
DELETE /agent/sova/{session_id}
```

### Trigger a scheduled job manually

```bash
POST /agent/sova/task/{job_name}
```

Available job names (hyphenated — these are the `_MANUAL_TASKS` keys):

| Job | Schedule |
|-----|----------|
| `morning-brief` | Daily 08:00 UTC |
| `threat-sync` | Every 6 hours |
| `rotation-check` | Daily 02:00 UTC (runs in operator mode) |
| `sla-report` | Monday 09:00 UTC |
| `upgrade-scan` | Sunday 10:00 UTC |
| `corpus-watchdog` | Every 30 min |
| `visual-patrol` | Daily 03:00 UTC |
| `community-lookup` | maps to `sova_community_watchdog` |

---

## Approval gate

When `operator_mode: true`, a state-changing tool (`update_config`,
`rotate_community_key`, `revoke_agent`, `block_ip_range`, `dismiss_threat`,
`moderate_community_post`, `publish_to_community`, `post_community_announcement`,
`smb_provision_suite`, `share_obsidian_note`, `sync_misp_feed`) does **not**
execute. It returns `{"status": "approval_required", "token": "appr-…"}`.

```bash
# 1. Human approves
POST /agent/approve/{token}?action=approve

# 2. Run the pending action (once; token is then consumed)
POST /agent/execute/{token}
```

Fail-closed: if the approval store (Redis) is unreachable, `issue()` raises and
the caller gets a 503 — a mutation is never performed unattended. Scheduled
cron jobs run with `auto_approve` (trusted, fixed-prompt) and skip the gate.

---

## Tool Categories

### System & Config
`get_health` · `get_stats` · `get_config` · `update_config`

### Threat Intelligence
`list_threats` · `refresh_threat_intel` · `dismiss_threat`

### Communities (key rotation)
`list_communities` · `get_community` · `rotate_community_key` ·
`get_rotation_progress` · `list_community_members`

### Business Community (moderation — tools #32–#37)
`get_community_feed` · `get_community_post` · `moderate_community_post` ·
`list_community_posts_members` · `community_moderation_report` ·
`post_community_announcement`

### Uptime Monitoring
`list_monitors` · `get_monitor_status` · `get_monitor_uptime` ·
`get_monitor_history`

### Financial
`get_financial_impact` · `get_cost_saved` · `get_billing_quota` ·
`generate_proposal` · `get_tenant_impact`

### Agent Activity
`list_agents` · `get_agent_activity` · `revoke_agent`

### Security & XAI
`filter_request` · `get_compliance_art30` · `scan_shadow_ai` ·
`explain_decision`

### Visual (tools #28, #31)
`visual_assert_page` · `visual_diff`

### Notifications
`send_slack_alert`

---

## Scheduled Jobs

### Morning Brief (daily 08:00 UTC)

SOVA calls 6+ tools and posts a structured Slack message covering:

1. Gateway health + 24h block rate
2. Top 3 threat intelligence items
3. Uptime monitor incidents
4. Financial ROI snapshot
5. Key rotation overdue warnings
6. **Business Community health digest** (NIM verdict breakdown, member count, BLOCK alerts)
7. Recommended actions

### Community Watchdog (every hour :20 UTC)

- Fetches the approved feed
- Auto-blocks WARN posts with `nim_score ≥ 0.85`
- Sends Slack alert if any BLOCK verdicts found
- **No LLM calls on the happy path** — pure HTTP

### Visual Patrol (daily 03:00 UTC)

Playwright screenshots + Claude Vision assertion on production endpoints.
Targets sorted by failure weight (`_PatrolWeights`, Redis-backed) so
frequently-failing routes run first.

---

## WardenHealer

The autonomous self-healing sub-system. SOVA delegates the corpus watchdog to
`WardenHealer`, which runs 4 checks directly over HTTP (no LLM):

1. **Circuit breaker** — alerts if open or half-open
2. **Bypass rate** — alerts if `bypass_rate_1m > HEALER_BYPASS_THRESHOLD` (default 15%)
3. **Corpus canary** — probes `/filter` with a known-bad payload; alerts if not blocked
4. **Trend prediction** — OLS extrapolation over 12 bypass samples; warns if predicted rate > threshold

On anomaly, Haiku is called once per unique incident fingerprint and the remedy
is cached in SQLite `incident_recipes`.

---

## Memory & Isolation

- Redis key: `sova:conv:{session_id}` (JSON, 6h TTL)
- 20-turn cap — oldest turns are dropped when exceeded
- Session IDs from cron jobs use fixed names (`sched-morning-brief`, etc.)
  so each job has isolated history that persists across runs

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Required for SOVA agentic loop |
| `REDIS_URL` | Session memory store |
| `SLACK_WEBHOOK_URL` | Alert destination |
| `WARDEN_API_KEY` | Used by tools to call internal API |
| `PATROL_URLS` | Comma-separated extra URLs for visual patrol |
| `DASHBOARD_URL` | Streamlit dashboard URL for visual patrol |
