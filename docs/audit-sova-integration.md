# SOVA Integration Audit — Shadow Warden AI

**Date:** 2026-09-06
**Scope:** `warden/agent/` (sova, master, healer, scheduler, memory, tools), `warden/api/agent.py`,
ARQ cron wiring (`warden/workers/settings.py`), and the SOVA ↔ Agentic Commerce boundary
(`warden/business_community/agentic_commerce/`, `warden/agentic/`).
**Method:** static read of the integration surface. Findings are rated by severity and
carry file references. Claims about runtime authz behaviour are marked *plausible* where
they depend on middleware not read in full.

---

## 1. Architecture as built

```
POST /agent/sova ──► run_query()  (Claude Opus 4.6, ≤10 tool rounds)
                       ├─ memory.load_history()  Redis sova:conv:{sid} (6h TTL, 20 turns)
                       ├─ tools.TOOLS  (49 defs sent in full every call)
                       └─ tools.TOOL_HANDLERS  ──HTTP──► http://localhost:8001  (X-API-Key + X-Tenant-ID)

POST /agent/master ──► run_master()  (supervisor Opus 4.6)
                       ├─ decompose ─► sub_tasks{}
                       ├─ asyncio.gather(_run_sub_agent × N)   ← each gets _AGENT_TOOLS[agent] subset
                       └─ synthesise ─► MasterResult

ARQ cron ──► scheduler.sova_*  ──► run_task() ──► run_query()   (fixed session ids)
             sova_corpus_watchdog ──► WardenHealer.run()  (LLM-free happy path, Haiku on anomaly)
```

Key facts:

- SOVA main loop sends **all 49 tools** on every turn; only MasterAgent sub-agents get a
  least-privilege subset (`_AGENT_TOOLS`, `warden/agent/master.py:62`).
- Mutating tools reachable from the plain SOVA loop: `update_config`, `rotate_community_key`,
  `revoke_agent`, `block_ip_range`, `moderate_community_post`, `dismiss_threat`,
  `publish_to_community`, `post_community_announcement`, `send_slack_alert`,
  `smb_provision_suite`.
- `run_query` returns token counts but nothing persists them to a cost ledger.
- No `sova_enabled` feature key exists (`warden/billing/feature_gate.py` — only
  `master_agent_enabled`).

---

## 2. Strengths

| # | Strength | Evidence |
|---|----------|----------|
| S1 | Clean agentic loop: prompt-cache on system prompt, graceful tool-error capture as `tool_result` with `is_error`, deterministic max-iter fallback. | `warden/agent/sova.py:111-214` |
| S2 | Tools exercise the **real** pipeline (auth, rate-limit, audit) via `localhost:8001` rather than importing internals — identical treatment to external callers. | `warden/agent/tools.py:1-67` |
| S3 | MasterAgent least-privilege: per-sub-agent tool subset + system prompt + HMAC-SHA256 task token binding `(sub_agent, task_hash, issued_at)`. | `warden/agent/master.py:62-166` |
| S4 | WardenHealer is LLM-free on the happy path; Haiku only on a unique incident fingerprint, with a SQLite recipe cache and OLS trend pre-alerting. Cost-disciplined. | `warden/agent/healer.py:218-467` |
| S5 | `run_master_batch` uses the Message Batches API for decompose + synthesis (50% input discount) for scheduled jobs, with graceful fallback. | `warden/agent/master.py:567-749` |
| S6 | GDPR-aware memory: pgvector stores **assistant** messages only, never user content. | `warden/agent/memory.py:157-184` |
| S7 | Patrol prioritisation: Redis-backed per-URL failure weights, decay/boost, targets sorted so flaky routes run first. | `warden/agent/scheduler.py:330-393` |
| S8 | `visual_diff` runs an OCR pre-check through `/filter` before sending screenshots to Vision — screenshot-embedded prompt injection is considered. | `warden/agent/tools.py:398-414` |
| S9 | Router mounted fail-open (try/except) so a missing `anthropic` package degrades gracefully rather than crashing startup. | `warden/main.py:1119-1123` |

---

## 3. Weaknesses & defects

Severity: **P0** exploit / cross-tenant / silent-cost · **P1** control gap · **P2** correctness / hygiene · **P3** cosmetic.

### P0-1 — `tenant_id` is model-controlled, not request-bound
`run_query` and `_run_sub_agent` only *default* the tenant:
```python
if "tenant_id" not in tool_input:
    tool_input["tenant_id"] = tenant_id
```
`warden/agent/sova.py:165`, `warden/agent/master.py:347`. The tool schemas actively advertise
`tenant_id` as a settable property ("Tenant to query"). If the model emits `tenant_id`
itself — through its own reasoning or an **injected tool result** — the caller's tenant is
overridden and the tool hits `/api/...` with `X-Tenant-ID: <attacker choice>`.
Given there is no global auth middleware and several `/communities/*` routers historically
trusted the header (*plausible* it still does for internal calls), this is a cross-tenant
read/write path (`get_stats`, `get_agent_activity`, `rotate_community_key`, `revoke_agent`).
**Fix:** pop `tenant_id` from every `tool_input` and force the authenticated value; drop
`tenant_id` from all tool `input_schema` properties.

### P0-2 — MasterAgent "human-in-the-loop" gate does not gate anything
`run_master` scans sub-agent *responses* for the string `REQUIRES_APPROVAL`, issues a token,
posts to Slack, appends to `approval_tokens`, and **returns**. It never calls
`_wait_for_approval`. Sub-agents call their tools directly inside `_run_sub_agent`
(`warden/agent/master.py:342-367`) with no interception, so `rotate_community_key` /
`revoke_agent` have **already executed** by the time the master sees the flag. Enforcement is
entirely prompt-discretion ("Tag any … as REQUIRES_APPROVAL"). The docstring's "pause the
loop" behaviour is not implemented.
**Fix:** wrap the mutating handlers in a gate that requires a resolved approval token in
Redis before the HTTP call; make the sub-agent loop `await` that resolution (or return a
"pending" proposal the master executes post-approval).

### P0-3 — `apply_community_recommendation` approval gate fails **open**
`warden/api/agent.py:448-461`: "No Redis — apply immediately (dev/test mode)". A Redis
outage silently converts an approval-required corpus mutation into an unattended one that
calls `_brain_guard.add_examples()`. Contradicts the fail-closed posture elsewhere in the
codebase.
**Fix:** fail closed — return `503`/`pending` when the approval store is unavailable.

### P0-4 — `/agent/sova` has no tier / feature / cost gate
Only `require_api_key` (`warden/api/agent.py:113`). MasterAgent is gated by
`master_agent_enabled` (Pro+), but the SOVA Opus-4.6 loop — up to 11 model calls with the
full 49-tool schema — is callable by **any authenticated tenant, including Starter ($0)**.
No `max_tokens`/cost ceiling on the outer loop (sub-agents have `_SUB_AGENT_TOKEN_BUDGET`;
SOVA has only `_MAX_ITER`). Nothing writes the spend to a ledger, so this repeats the FM-7
"MasterAgent + Evolution recorded zero cost" pattern.
**Fix:** add `sova_enabled` (or reuse `master_agent_enabled`), a per-call token budget with
early halt, and record `input/output/cache_read` tokens + $ to the FinOps/AgentSpan sink.

### P1-5 — Confused-deputy: detection kill-switches exposed with no gate
From the plain SOVA loop the model can call `update_config({"strict_mode": false})` or lower
`semantic_threshold` (disabling detection), `block_ip_range` (irreversible per its own
description), `revoke_agent`, `moderate_community_post` block. `POST /api/config` was
hardened in PR #244 after being an unauthenticated kill-switch; SOVA re-opens it to anyone
who can send SOVA a prompt.
**Fix:** split tools into read-only vs operator sets; require an explicit
`operator_mode=true` request flag (itself tier-gated) to expose the mutating set, and route
those through P0-2's gate.

### P1-6 — Lethal-trifecta exposure in one context
SOVA simultaneously has: privileged data access, ingestion of untrusted content
(`filter_request`, `get_community_feed`, `search_community_feed`, `get_obsidian_feed` all
return attacker-authored text into context), and act/exfil tools (`send_slack_alert`,
`post_community_announcement`, `publish_to_community`, `update_config`). No quarantine of
tool output, no separate summariser.
**Fix:** pass untrusted tool results through a constrained sub-call that cannot itself call
tools; strip/escape before re-injection; keep act-tools out of any turn that consumed
untrusted content.

### P1-7 — `visual_assert_page` (tool #28) has **no** OCR pre-check
`visual_diff` guards against screenshot-embedded injection; `visual_assert_page` does not
(`warden/agent/tools.py:187-262`). It is the tool the nightly `sova_visual_patrol` runs
against arbitrary `PATROL_URLS`, feeding raw page pixels to Opus Vision.
**Fix:** apply the same `warden.ocr` + `/filter` pre-check used in `visual_diff`.

### P1-8 — No timeout or cancellation on the agentic loop
`client.messages.create(...)` calls pass no `timeout`; the loop has no wall-clock bound.
`POST /agent/sova` awaits it inline, so a slow run pins a worker (compounds the known p99 /
`BaseHTTPMiddleware` blocking issues). ARQ `timeout=300` cannot cleanly interrupt it.
**Fix:** per-call `timeout=`, wrap the loop in `asyncio.wait_for`, return `504` on breach.

### P1-9 — `WARDEN_API_KEY` captured at import time
`_API_KEY = os.getenv("WARDEN_API_KEY", "")` at module load (`warden/agent/tools.py:27`).
If any worker imports `warden.agent.tools` before the env is populated, **every** SOVA tool
call goes out unauthenticated for the life of the process. This class of bug has recurred
(env-shadow / posture-flag notes).
**Fix:** read per-call, or from the central `Settings` object.

### P1-10 — Zero automated tests for the agent subsystem
No `test_sova*`, `test_scheduler*`, `test_healer*`, `test_agent_router*`. Only
`test_multi_agent.py` (commerce connectors) exists. A subsystem holding production mutating
tools ships untested, and CI does not gate on collection errors.
**Fix:** add `warden/tests/test_agent_*.py` with a mocked Anthropic client covering: tool
dispatch, `tenant_id` binding (P0-1 regression), `stop_reason` branches, approval gating,
healer checks.

### P2-11 — `stop_reason` other than `end_turn`/`tool_use` loses the whole turn
On `max_tokens` the loop `break`s *before* appending the assistant message
(`warden/agent/sova.py:150-155`), discards all generated text, and pays for a fallback call.
A `max_tokens` truncation mid-`tool_use` also yields malformed JSON tool input that the next
iteration would reject.
**Fix:** handle `max_tokens` explicitly — surface partial text, or continue-generation.

### P2-12 — `_embed` bypasses the model singleton
`warden/agent/memory.py:146-154` does `SemanticGuard()._embed(text)` — a fresh instance and
a private method — while CLAUDE.md mandates the `@lru_cache` `_load_model()` path.
`_ensure_schema` also re-runs `CREATE EXTENSION`/`CREATE TABLE` on every reconnect.

### P2-13 — `community_moderation_report` uses `datetime.utcnow()`
`__import__("datetime").datetime.utcnow()` (`warden/agent/tools.py:633`) — naive and
deprecated on 3.12+. Elsewhere the code correctly uses `datetime.now(UTC)`.

### P2-14 — `sova_visual_patrol` coverage metric is near-vacuous
Every target is checked every run (the weight sort drops nothing), so
`critical_coverage_pct` is 100% unless a probe errored. It reports effort, not coverage.

### P2-15 — `send_slack_alert` unbounded
Arbitrary `message`, no rate limit — SOVA (or an injection) can flood or socially-engineer
via the org Slack webhook.

### P3-16 — Doc / route drift
`docs/guides/sova.md` lists job names with underscores (`morning_brief`); the endpoint
`_MANUAL_TASKS` keys are hyphenated (`morning-brief`) — the documented calls 400.
Doc says "37 tools"; registry has 49.

---

## 4. SOVA ↔ Agentic Marketplace: current state

**SOVA is not integrated with the Agentic Commerce module at all.**
`warden/business_community/agentic_commerce/api.py` exposes mandates, orders, MCP purchase
intents, AP2 webhooks, spend analytics, and multi-agent auctions under
`/business-community/commerce` — **no SOVA tool touches any of it**. `list_agents` /
`get_agent_activity` / `revoke_agent` operate on the older `/agentic` AP2 registry, a
different surface.

Consequences:
- No autonomous oversight of spending mandates (budget-cap breaches, expiry, merchant
  allowlist drift).
- No monitoring of auction outcomes — a high-`risk_score` winning vendor settles unseen.
- The `/business-community/commerce/approve/{workflow_id}` human-approval hook has no agent
  driving or surfacing it.
- No reconciliation of orders vs receipts — directly relevant to the known "settled at
  $0.00 for months" ghost-schema class.
- Commerce endpoints take `tenant_id` in the request body with only a feature gate; **verify
  they also carry `require_api_key`** (not listed on the routes).

---

## 5. Proposed features for the Agentic Marketplace

Ordered; each assumes P0-1 and P0-2 are fixed first.

### F1 — Commerce tool pack for SOVA (read-only first)
New handlers in `warden/agent/tools.py`, thin wrappers over `/business-community/commerce`:
`list_mandates`, `get_mandate`, `get_agentic_spend` (→ `/analytics/spend`), `list_auctions`,
`get_auction`, `list_commerce_orders`, `get_commerce_order`. Add to `docs/guides/sova.md`
under a new "Marketplace" category.

### F2 — `sova_commerce_watchdog` scheduled job (hourly, LLM-free happy path)
Model it on `sova_community_watchdog` / WardenHealer:
- mandate spend ≥ 80% of `max_amount` → Slack warn; ≥ 100% → Slack alert.
- mandate past `valid_until` but still referenced by open orders → alert.
- auction winner `risk_score ≥ 0.7` or vendor unseen in prior 30 days → alert.
- **order settled at `$0.00` / receipt total ≠ order total** → alert (ghost-schema canary).
- purchase velocity per agent vs its trailing 7-day mean (z-score) → alert.
Register in `warden/workers/settings.py` alongside the other `sova_*` crons.

### F3 — `CommerceAgent` MasterAgent sub-agent
New `SubAgent.COMMERCE` with `_AGENT_TOOLS` = the F1 read tools + `revoke_mandate`,
`approve_purchase_intent`, `cancel_auction`. System prompt: reconcile spend, flag rogue
agents, tag every mutation `REQUIRES_APPROVAL` — enforced by the P0-2 gate, not the prompt.

### F4 — Procurement co-pilot endpoint
`POST /agent/sova/commerce/negotiate {request, budget_usd, tenant_id}` → SOVA runs
`MultiAgentOrchestrator.run_auction`, enriches with `SupplierRisk`, cross-checks each
finalist vendor against the SEP community feed (`search_community_feed`) for fraud
signatures, and returns a ranked recommendation + rationale. Settlement stays behind
`/approve/{workflow_id}`. Tier-gate to Pro+.

### F5 — Rogue-agent detection in WardenHealer
Add a `_check_commerce_anomalies()` HTTP probe: spend spike, first-purchase-from-new-vendor,
off-hours buying, mandate used from an unexpected agent id. Pure-Python thresholds; Haiku
classification only on trip. Optional HITL auto-revoke of the mandate.

### F6 — Receipt reconciliation tool + canary
`reconcile_orders(tenant_id, hours)` → compares order line-item totals to AP2 receipts,
returns mismatches. Wire a synthetic $1 order canary into `sova_commerce_watchdog` so a
regression to `$0.00` settlement is caught within the hour.

### F7 — Marketplace reputation surface
`get_vendor_reputation(vendor)` — join auction history, `SupplierRisk` composite, and SEP
community hits into one score SOVA can cite before recommending a purchase.

---

## 6. Remediation roadmap

| Phase | Items | Rationale |
|-------|-------|-----------|
| **P0 (blockers)** | P0-1 tenant binding · P0-2 real approval gate · P0-3 fail-closed · P0-4 tier + cost ledger | cross-tenant + unattended-mutation + silent spend |
| **P1** | P1-5 operator-mode split · P1-6 untrusted-output quarantine · P1-7 OCR on `visual_assert_page` · P1-8 loop timeout · P1-9 key at call time · P1-10 test module | control gaps |
| **P2** | P2-11 `max_tokens` handling · P2-12 model singleton · P2-13/14/15 hygiene | correctness |
| **F1–F2** | commerce read tools + watchdog | fastest marketplace value, low risk |
| **F3–F7** | CommerceAgent, co-pilot, healer, reconciliation, reputation | needs P0-2 gate first |

---

## 7. Dissent noted

- **"Prompt-based `REQUIRES_APPROVAL` is acceptable for a v1."** Rejected: the tools are
  irreversible (`block_ip_range`) or detection-disabling (`update_config`); a single
  injected tool result defeats a prompt convention. An architectural gate is the minimum.
- **"`tenant_id` defaulting is fine because callers are trusted."** Rejected: SOVA ingests
  untrusted community/filter content in the same context that builds tool calls; the caller
  is trusted, the context is not.
- **"Gate SOVA behind Enterprise only."** Not recommended — reuse `master_agent_enabled`
  (Pro+) so the SOC-agent story stays coherent with existing pricing; add the cost ledger
  rather than restricting distribution.
