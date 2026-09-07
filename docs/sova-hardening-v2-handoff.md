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
- **Slice 2 (TODO):** wire `_gated` into `tools.py` (READ/OPERATOR split, `tools_for` /
  `handlers_for` — must compose with upstream `_select_tools`/`tool_profile`);
  `operator_mode` param through `run_query`/`stream_query`; `POST /agent/execute/{token}`;
  `record_llm_spend` calls in sova/master/healer; sub-agent `pending_approvals`.
- **Slice 3 (TODO):** PR-4 (`_untrusted` tags + `visual_assert_page` OCR + slack RL),
  PR-7 (`reconcile_orders` + `sova_commerce_watchdog`), PR-8 (`SubAgent.COMMERCE` +
  `/agent/sova/commerce/negotiate`).

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
