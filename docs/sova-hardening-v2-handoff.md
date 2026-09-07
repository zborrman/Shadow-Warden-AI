# SOVA hardening — re-implementation handoff

**Why v2:** the first pass (`sova-hardening-pr1-5`, PR #447) was built on a checkout
943 commits / ~3 months stale (`166dce80`, 2026-05-29). It cannot merge. This worktree
(`C:/tmp/swa-live`, branch `sova-hardening-v2`) is off live `origin/main` (`084d4038`).

**Reference (do not merge):** PR #447 diff + `docs/audit-sova-integration.md` +
`docs/plan-sova-remediation.md` (all on the old branch) hold the design and the tested code.

## Progress

- **Slice 1 (commit `62ecf7da`, pushed):** P0-1 tenant force (sova.py both loops +
  master `_run_sub_agent`); `sova_agent_enabled` feature key; `/agent/sova` +
  `/sova/stream` tier-gated; tenant bound from `auth.tenant_id` everywhere;
  `MasterRequest.auto_approve` removed (F1); `approval.py` + `accounting.py` dropped in.
  37 tests green, ruff clean.
- **Slice 2 (commit `ea471d04`, pushed):** approval gate lives in `traced_dispatch`
  (`approval_gate=True`), so both SOVA loops, `stream_query` and every MasterAgent
  sub-agent get it from one place. `OPERATOR_TOOLS`/`READ_TOOLS` split; `tools_for()`
  composes with upstream `_select_tools`/`tool_profile`; `operator_mode` + `auto_approve`
  through `run_query`/`stream_query`/`run_task`; sub-agent `pending_approvals` harvested
  into `MasterResult.approval_tokens` + Slack; `POST /agent/execute/{token}` with an
  atomic `try_consume()` single-use claim and exact tenant match. 14 tests.
  **Note:** upstream already has `_record_cost` in `sova.py` and `master.py` — the audit's
  cost-ledger gap is closed there, so `warden/agent/accounting.py` was dropped as dead code.
- **Slice 3a (PR-4):** `warden/ocr.py` gained `extract_text_from_b64_ex()` returning
  `(text, status)` — the old function collapsed "no text in the image" and "OCR
  backend missing" into `""`. `tools._ocr_injection_gate()` is one fail-CLOSED gate
  for both vision tools (`OCR_GATE_FAILOPEN=true` inverts it and counts the bypass).
  **`visual_diff`'s existing OCR pre-check had never run** — it posted `{"text": …}`
  to `/filter`, which requires `content`, and the 422 was swallowed by a broad
  `except` logging at debug. `visual_assert_page` had no gate at all. Plus
  `UNTRUSTED_TOOLS` + `_tag_untrusted()` in `traced_dispatch` (16 tools),
  a 12/hour Slack cap, and `check_commerce_budget` no longer returns
  `{"allowed": true}` when its backend errors.
- **Slice 3b (PR-7):** `warden/finops/commerce_recon.py` — cap breaches,
  expired-but-ACTIVE mandates, spend drift (the $0.00 case named as the
  ghost-schema signature), receipt gaps, $0.00 totals against real line items.
  Same evidence vocabulary as `order_recon`: `not_available` is a failure, never a
  clean pass. `sova_commerce_watchdog` cron hourly at :50, **LLM-free**, alerting
  separately when it could not run. `reconcile_orders` / `list_mandates` /
  `list_commerce_orders` tools. Also: `check_commerce_budget`, `get_spend_summary`,
  `semantic_query` and `list_semantic_models` had handlers but **no schema**, so
  the model could never call them — fixed, with a guard test asserting every
  schema's required params exist in its handler signature.
- **Slice 3c (PR-8):** `SubAgent.COMMERCE` + prompt; `revoke_mandate` /
  `approve_purchase_intent` (auto-gated via `OPERATOR_TOOLS`);
  `POST /agent/sova/commerce/negotiate` (Pro+, `settled: false`, tenant bound from
  the key). `_enrich_with_risk` wrote `p.risk` but persisted `p.raw`, so every
  stored auction carried the **bidding model's self-reported** risk; now written
  where it is persisted with a `risk_source` label. `_AGENT_CHOICES` is derived
  from the enum — `data_privacy` was hand-omitted from both decomposition prompts.
  And AG-23's `DataPrivacyAgent` listed **7 tools that were never implemented**
  (the allowlist intersection silently dropped them, leaving it 4 of 11 while its
  prompt instructed it to use all 11); implemented against the existing
  `/gdpr`, `/retention`, `/secrets` and `/compliance/posture` routes, with the two
  destructive ones approval-gated.

### Ratchets (run locally before pushing)

All four green: `test_route_inventory` (2 routes added to the fixture by hand —
**do not** regenerate here, the local dep set drops `warden.voice.api`),
`test_no_new_counterless_failopen` (back to 200: my OCR comment now names its
`record_failopen`, and the `_tag_untrusted` wrap had pushed the OTel bypass's
counter out of the ±4-line coverage window), `test_no_new_raw_signing_key`
(`approval.py` had `os.getenv("MASTER_AGENT_SECRET", "shadow-warden-master-v1")`
— a repo-readable default makes every approval token forgeable; now
`resolve_key(..., purpose="master_agent")`, the same key master.py uses), and
`test_no_new_suppressions` (838→839; I removed 5 of my own — E402, S608, 3×
BLE001 narrowed to real exception types — and kept 2: the conventional lazy
`import redis` and one HTTP-boundary broad catch).

⚠️ The route-inventory child subprocess imports from `os.getcwd()`. A stray `cd`
into another worktree makes it silently measure *that* tree — it reported my new
routes as ADDED, then REMOVED, from the same code.

## Audit findings re-checked against live `main` (084d4038)

| Finding | Live state | Action |
|---|---|---|
| P0-1 `tenant_id` defaulted not forced (`sova.py` ~417, ~600; `master.py` ~/_run_sub_agent) | **OPEN** | re-apply |
| P0-2 no real approval gate — text `REQUIRES_APPROVAL` + `_wait_for_approval` poll only; no `approval.py`, no `_gated` | **OPEN** | re-apply PR-2 |
| P0-3 `apply_community_recommendation` fail-open on no-Redis | OPEN (verify) | re-apply |
| P0-4 no `sova_agent_enabled` key; no cost ledger (`accounting.py` / `record_llm_spend`) | **OPEN** | re-apply PR-3 |
| Read/OPERATOR tool split (`tools_for`/`handlers_for`/`OPERATOR_TOOLS`) | **OPEN** | re-apply PR-1 |
| `visual_assert_page` has no OCR pre-check | **OPEN** | re-apply PR-4 |
| F1 `/agent/master` `auto_approve` client-settable | **OPEN** | re-apply |
| Commerce routes `require_api_key` | **DONE upstream** | drop PR-6's auth part; keep only the read-tools + `_bound_tenant` refinement if wanted |
| `sova_commerce_watchdog`, CommerceAgent, `/commerce/negotiate` | absent (new) | re-apply PR-7, PR-8 |

## Notes for the re-apply

- `warden/agent/tools.py` on live main is **+1227 lines** vs the old base — do NOT
  cherry-pick; re-write the additions against current structure.
- Upstream already binds tenant in `tools.py` handlers? No — it's `sova.py` that defaults
  it. Confirm both `sova.py` loops AND `master._run_sub_agent`.
- Live `master.py` Step-3 has a `needs_approval` var — read it before re-doing PR-2/F2 so
  the new `_gated` layer composes with it rather than duplicating.
- Port order: PR-1 → PR-2 → PR-3 → PR-4 → PR-7 → PR-8. Skip PR-5 hygiene items that no
  longer apply; skip PR-6 auth.
- Tests from PR #447 (`test_agent_hardening.py`, `test_agent_commerce*.py`,
  `test_scheduler_commerce.py`) port largely as-is.
- Run in a temp worktree, never the OneDrive checkout (standing rule).
