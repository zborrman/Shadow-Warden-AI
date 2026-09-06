# SOVA Remediation & Marketplace Plan

**Companion to:** `docs/audit-sova-integration.md`
**Date:** 2026-09-06
**Shape:** eight stacked PRs. P0 → P1 → P2 land first (security/correctness), then F1 → F5
(marketplace). Each PR is independently revertible and ships with tests.

## Status (branch `sova-hardening-pr1-5`)

| PR | State | Commit |
|----|-------|--------|
| PR-1..5 (security/correctness) | ✅ done | `08d414e0` |
| PR-6 commerce read-tools + commerce-router auth | ✅ done | `3375e833` |
| PR-7 `sova_commerce_watchdog` + `reconcile_orders` | ✅ done | `35403b23` |
| PR-8 CommerceAgent sub-agent + `/agent/sova/commerce/negotiate` | ✅ done | `9c7109e6` |

Deferred (below) not started: F5 healer rogue-agent check, F6 standalone reconciliation
service + $1 canary order, F7 `get_vendor_reputation`, `tool_choice` subsetting,
pub/sub approval wait.

---

## Ground rules

- Every PR adds tests under `warden/tests/test_agent_*.py`; the agent package is currently
  untested (audit P1-10). Target: `warden/agent/` + `warden/api/agent.py` ≥ 70% line
  coverage by end of PR-3, folded into the existing `--cov-fail-under` gate.
- No behaviour change to the `/filter` pipeline. SOVA is a consumer of it.
- Mock the Anthropic client in all tests (`conftest.py` already sets `ANTHROPIC_API_KEY=""`).
- Run `route_inventory`, `counterless_failopen`, `suppressions` ratchets locally before each
  push (per repo convention).

---

## PR-1 — Tenant binding + tool-surface split  *(P0-1, P1-5)*

**Problem.** `tool_input["tenant_id"]` is only defaulted, and mutating tools are on the
plain SOVA loop with no gate.

**Changes**

1. `warden/agent/sova.py` + `warden/agent/master.py`: replace
   ```python
   if "tenant_id" not in tool_input:
       tool_input["tenant_id"] = tenant_id
   ```
   with an unconditional override:
   ```python
   tool_input["tenant_id"] = tenant_id          # request-bound, never model-set
   tool_input.pop("community_id_tenant_override", None)
   ```
2. `warden/agent/tools.py`: delete `tenant_id` from every tool `input_schema.properties`
   and from every `"required"` list. Handlers keep the `tenant_id` kwarg (injected by the
   loop), so no handler signature changes.
3. `warden/agent/tools.py`: introduce `READ_TOOLS` and `OPERATOR_TOOLS` sets. Add
   `def tools_for(operator: bool) -> list[dict]` and `handlers_for(operator)`.
   `OPERATOR_TOOLS` = `{update_config, rotate_community_key, revoke_agent, block_ip_range,
   dismiss_threat, moderate_community_post, publish_to_community,
   post_community_announcement, smb_provision_suite, share_obsidian_note}`.
4. `warden/api/agent.py`: `SovaRequest` gains `operator_mode: bool = False`. `run_query`
   takes `operator_mode` and passes `tools_for(operator_mode)`. Non-operator calls get the
   read set only.
5. `warden/agent/master.py`: `_AGENT_TOOLS` already subsets — no change, but assert every
   name in `_AGENT_TOOLS` exists in `TOOL_HANDLERS` at import (guards typos).

**Tests** — `test_agent_tenant_binding.py`
- model emits `tenant_id="victim"` in a tool call → handler receives the request tenant.
- `operator_mode=False` → `update_config` absent from the tool list passed to the client.
- `_AGENT_TOOLS` ↔ `TOOL_HANDLERS` consistency.

**Acceptance.** A crafted query / injected tool result cannot change the tenant or reach a
mutating tool without `operator_mode=True`.

---

## PR-2 — Real approval gate  *(P0-2, P0-3)*

**Problem.** `run_master` never waits; `apply_community_recommendation` fails open.

**Changes**

1. New `warden/agent/approval.py`:
   - `issue(action: str, context: str, tenant_id: str) -> str` — HMAC token, `SETEX`
     `sova:approval:{token}` (1h) with `status=pending`. **Raises `ApprovalStoreUnavailable`
     if Redis is down** (no fail-open).
   - `async wait(token, timeout=3600) -> bool` — polls `sova:approval:{token}`.
   - `resolve(token, approved) -> bool` — unchanged semantics, migrated from `master.py`.
   - `GATED_ACTIONS` = the `OPERATOR_TOOLS` names from PR-1.
2. `warden/agent/tools.py`: wrap operator handlers in `_gated(handler)`. A gated handler,
   when called with `approval_token=None`, returns
   `{"status": "approval_required", "token": issue(...)}` instead of executing. When called
   again with a resolved token, it executes.
3. `warden/agent/master.py` `_run_sub_agent`: on a tool result of `approval_required`,
   surface the token to the master; **do not** synthesise a "done" report for that action.
   `run_master` collects tokens, posts to Slack (existing `_post_approval_request`), and
   returns `status="pending_approval"` for those items.
4. New endpoint `POST /agent/execute/{token}` in `warden/api/agent.py` — after human
   approval, re-invokes the specific gated handler with the resolved token. Auth:
   `require_api_key` + `X-Admin-Key` for `update_config` / `block_ip_range`.
5. `warden/api/agent.py::apply_community_recommendation`: delete the "No Redis — apply
   immediately" branch; return `503` when `issue()` raises.

**Tests** — `test_agent_approval.py`
- gated tool with no token → `approval_required`, nothing mutated (mock `_post` asserts not
  called).
- Redis down → `apply_community_recommendation` returns 503, `add_examples` not called.
- `resolve(approve)` then `/agent/execute/{token}` → handler runs exactly once; replay →
  404.

**Acceptance.** No operator tool mutates state until a token exists **and** has been
resolved `approve` through the endpoint.

---

## PR-3 — Tier gate + cost ledger + loop budget  *(P0-4, P1-8)*

**Changes**

1. `warden/billing/feature_gate.py`: add `sova_enabled` to the feature matrix —
   `False` for starter/individual, `True` for community_business+ (SOVA read-only is a
   reasonable SMB feature; `operator_mode` additionally requires `master_agent_enabled`,
   i.e. Pro+). Update the docstring matrix + all five `_TIER_*` dicts.
2. `warden/api/agent.py`: add `dependencies=[require_feature("sova_enabled")]` to
   `POST /agent/sova` and the `/sova/task/*`, `/sova/community/*` routes. In `query_sova`,
   if `body.operator_mode` also assert `master_agent_enabled` (403 otherwise).
3. `warden/agent/sova.py`:
   - add `_TOKEN_BUDGET = int(os.getenv("SOVA_TOKEN_BUDGET", "60000"))`; break the loop
     when `total_input + total_output >= _TOKEN_BUDGET` (mirror `_SUB_AGENT_TOKEN_BUDGET`).
   - pass `timeout=90.0` to every `client.messages.create`.
   - wrap the whole loop in `asyncio.wait_for(..., timeout=_DEADLINE)` where
     `_DEADLINE = int(os.getenv("SOVA_DEADLINE_S", "240"))`; on `TimeoutError` return the
     partial with `"status": "deadline_exceeded"`.
4. New `warden/agent/accounting.py::record_llm_spend(tenant_id, agent, model, usage)` —
   converts token counts to USD via `warden/billing/pricing.py` PRICE_BOOK and calls
   `warden.financial.cost_allocation.record_cost(tenant_id, amount, vendor_id="anthropic",
   cost_type="api_usage", notes=f"{agent}:{model}")`. Called at the end of `run_query`,
   `_run_sub_agent`, `run_master`, and `healer._llm_classify_incident`.
5. Add `opus-4-6` + `haiku-4-5` rows to PRICE_BOOK if absent (audit cross-ref: FM-7 found
   opus-4-6 missing → 5× undercount).

**Tests** — `test_agent_cost_gate.py`
- starter tier → `POST /agent/sova` 403.
- `operator_mode=True` on community_business → 403; on pro → allowed.
- `run_query` with a mock that returns 70k-token usage → loop halts after budget, one
  `record_cost` row with non-zero USD.

**Acceptance.** SOVA is tier-gated; every SOVA/Master/Healer LLM call writes a costed row;
no unbounded loop.

---

## PR-4 — Untrusted-output handling + visual OCR  *(P1-6, P1-7)*

**Changes**

1. `warden/agent/tools.py`: tag the return of `filter_request`, `get_community_feed`,
   `get_community_post`, `search_community_feed`, `get_obsidian_feed` with
   `{"_untrusted": True, ...}`.
2. `warden/agent/sova.py`: track `turn_consumed_untrusted`. If a turn's tool results
   contain `_untrusted`, the **next** assistant turn is issued with the read-only tool set
   only (operator tools dropped for that turn) — an act-tool cannot fire in the same
   reasoning step that ingested attacker text.
3. `warden/agent/tools.py::visual_assert_page`: lift the OCR pre-check block verbatim from
   `visual_diff` (lines ~398-414) — extract to `_ocr_gate(b64_png, label) -> dict | None`
   and call it from both.
4. `send_slack_alert`: add a token-bucket (`sova:slack_rl`, 10/hour) — return
   `{"sent": False, "reason": "rate_limited"}` past the cap.

**Tests** — `test_agent_untrusted.py`
- screenshot whose OCR text is a known jailbreak → `visual_assert_page` returns
  `BLOCKED_BY_OCR_PRECHECK`, no Vision call.
- a turn that called `get_community_feed` → operator tools absent from the following
  `messages.create`.

---

## PR-5 — Hygiene  *(P2-11..15, P3-16)*

- `sova.py`: handle `stop_reason == "max_tokens"` — append the partial assistant text to
  history, log, and continue one more iteration with `max_tokens` bumped ×1.5 (cap 8192)
  instead of silently dropping the turn.
- `memory.py::_embed`: use `warden.brain.semantic._load_model()` (the `@lru_cache`
  singleton), not `SemanticGuard()._embed`. Move `_ensure_schema` to a one-time module flag.
- `tools.py`: `_API_KEY` → `def _key(): return os.getenv("WARDEN_API_KEY", "")`, called in
  `_headers`.
- `tools.py:633`: `datetime.now(UTC).isoformat()` instead of `__import__(...).utcnow()`.
- `scheduler.py::sova_visual_patrol`: drop the vacuous `critical_coverage_pct`; report
  `targets_failed / targets_total` instead.
- `docs/guides/sova.md`: fix job names to the hyphenated `_MANUAL_TASKS` keys; correct
  "37 tools" → current count; regenerate the tool-category list from `TOOLS`.

**Tests** — extend `test_agent_*`; add `test_scheduler_patrol.py` for the coverage metric.

---

## PR-6 — Commerce read-tools for SOVA  *(feature F1)*

**Prereq.** PR-1..3 merged.

**Changes**

1. `warden/business_community/agentic_commerce/api.py`: add
   `dependencies=[Depends(require_api_key), _Gate]` to **all** routes — they currently carry
   only the feature gate, no auth (audit note). Bind `tenant_id` from `auth.tenant_id`, not
   the request body, on every handler; keep body field for back-compat but 403 on mismatch.
2. New handlers in `warden/agent/tools.py` (read-only, added to `READ_TOOLS`):
   `list_mandates`, `get_mandate`, `get_agentic_spend` (→ `/analytics/spend`),
   `list_commerce_auctions`, `get_commerce_auction`, `list_commerce_orders`,
   `get_commerce_order`.
3. Tool schemas + `TOOL_HANDLERS` entries; bump the count in `docs/guides/sova.md` and add
   a "Marketplace" category.
4. `warden/agent/master.py`: extend `SubAgent.FORENSICS` tool list with the read handlers
   (Forensics already owns agent-activity/spend forensics).

**Tests** — `test_agent_commerce_tools.py`
- each tool round-trips against a seeded `COMMERCE_DB_PATH`.
- commerce route without `X-API-Key` → 401.
- cross-tenant `tenant_id` in body → 403.

---

## PR-7 — `sova_commerce_watchdog` scheduled job  *(feature F2)*

**Changes**

1. `warden/agent/scheduler.py::sova_commerce_watchdog(ctx)` — LLM-free, modelled on
   `sova_community_watchdog`:
   - `get_agentic_spend` per active tenant → mandate spend ≥ 80% `max_amount` → Slack warn;
     ≥ 100% → alert.
   - mandate past `valid_until` with open orders → alert.
   - `list_commerce_auctions` → any winner with `risk_score ≥ 0.7` or a vendor unseen in the
     prior 30 days → alert.
   - **`reconcile_orders`**: order line-item total ≠ AP2 receipt total, or receipt total
     `== 0.00` → alert (ghost-schema canary; cross-ref `marketplace_money_ghost_schema`).
   - per-agent purchase velocity vs trailing-7-day mean, z-score > 3 → alert.
2. `warden/workers/settings.py`: register `sova_commerce_watchdog`; `cron(...,
   minute=50, timeout=120)` (hourly, offset from the community watchdog's `:20`).
3. New tool `reconcile_orders(hours=24)` in `tools.py` (read-only).
4. `warden/api/agent.py::_MANUAL_TASKS`: add `"commerce-watchdog"`.

**Tests** — `test_scheduler_commerce.py`
- seeded auction with `risk_score=0.9` → `_slack` called with the vendor.
- receipt total 0.00 vs order 12.00 → reconciliation alert.
- clean state → `status="ok"`, no Slack.

---

## PR-8 — CommerceAgent sub-agent + procurement co-pilot  *(features F3, F4)*

**Prereq.** PR-2 approval gate merged (mutations must gate).

**Changes**

1. `warden/agent/master.py`: `SubAgent.COMMERCE = "commerce"`. `_AGENT_TOOLS[COMMERCE]` =
   F1 read tools + `revoke_mandate`, `approve_purchase_intent`, `cancel_auction` (all
   `OPERATOR_TOOLS`, so PR-2-gated). `_AGENT_PROMPTS[COMMERCE]`: reconcile spend, flag rogue
   agents, tag mutations `REQUIRES_APPROVAL` (now enforced, not advisory).
2. New `revoke_mandate`, `approve_purchase_intent`, `cancel_auction` handlers →
   `DELETE /mandates/{id}`, `POST /approve/{workflow_id}`, auction cancel.
3. New endpoint `POST /agent/sova/commerce/negotiate {request, budget_usd}` in
   `warden/api/agent.py`, gated `require_feature("master_agent_enabled")`:
   - runs `MultiAgentOrchestrator.run_auction`,
   - enriches finalists via `warden.communities.supplier_risk.assess_supplier`,
   - cross-checks each finalist vendor against `search_community_feed` for fraud
     signatures,
   - returns a ranked recommendation + rationale; **settlement is not performed** — returns
     the auction id and the `/business-community/commerce/approve/{workflow_id}` link.
4. `warden/agent/master.py` decompose prompt: add `"commerce"` to the agent enum.

**Tests** — `test_agent_commerce_agent.py`
- `/negotiate` with no API keys → deterministic mock auction, ranked list returned, no
  order row written.
- CommerceAgent `revoke_mandate` → `approval_required`, mandate still active until
  `/agent/execute/{token}`.

---

## Deferred (tracked, not in this stack)

| Item | Why deferred |
|------|--------------|
| F5 rogue-agent detection inside `WardenHealer` | wants PR-7's velocity model as a library first |
| F6 standalone reconciliation service + $1 canary order | needs a decision on whether to spend real testnet value on a recurring canary |
| F7 `get_vendor_reputation` unified score | depends on SEP feed schema stabilising |
| SOVA tool-subsetting via `tool_choice` per query intent | optimisation, not correctness |
| Replace Redis-poll approval with a pub/sub wait | `_wait_for_approval` poll is adequate at current volume |

---

## Sequencing & risk

```
PR-1 ─► PR-2 ─► PR-3 ─► PR-4 ─► PR-5        (security / correctness — merge weekly)
                 └► PR-6 ─► PR-7 ─► PR-8    (marketplace — starts after PR-3)
```

- **PR-1 is the highest-risk revert point** (tool-schema change) — ship it alone, watch
  SOVA error rate for 48h before PR-2.
- **PR-3 tier gate** will 403 any existing starter/individual SOVA callers — announce in
  the changelog; grandfather via `SOVA_GATE_GRACE_UNTIL` env date-check if telemetry shows
  live free-tier usage.
- **PR-6 auth addition** on commerce routes is a breaking change for any current
  unauthenticated caller — same grace-flag pattern.

## Definition of done

- [ ] `pytest warden/tests/test_agent_*.py` green; agent-package coverage ≥ 70%.
- [ ] Audit findings P0-1..P0-4, P1-5..P1-9 closed with a test each.
- [ ] `sova_enabled` in the feature matrix + site pricing pages (3 Astro files) updated.
- [ ] `docs/guides/sova.md` regenerated; `docs/audit-sova-integration.md` findings table
      annotated with the closing PR number.
- [ ] `README.md` "What's New" + `CLAUDE.md` architecture block + `MEMORY.md` updated.
