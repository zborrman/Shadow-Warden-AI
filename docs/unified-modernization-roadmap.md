# Unified Modernization Roadmap — reconciling the two parallel plans

**Date:** 2026-07-12 · **Purpose:** merge the two concurrently-running modernization efforts into one registry so they stop colliding on shared files and on "Phase N" numbering.

## Why this doc exists

Two plans have been running in parallel, each numbering its work "Phase 1…7/8". In commit messages and reviews "Phase 5" has meant two different things. They also touch overlapping files (`causal_arbiter.py`, `staff_dispatch`, `net_guard`, the data layer). This document is the single source of truth: two **named tracks**, one status table, explicit conflict-ownership.

| Track | Source doc | Scope | Prefix |
|---|---|---|---|
| **A — Security Remediation** | `MODERNIZATION_PLAN.md` | Audit findings: auth, SSRF, IDOR, GDPR, invariants, DB-layer, CI hardening | `SR-*` |
| **B — Deep-Eng / Math** | `docs/modernization-plan-v8.md` | TDA, MAESTRO/reputation, Causal calibration, GSAM, embeddings, data-layer, runtime isolation | `DE-*` |
| **C — FinOps / Monetization** | `docs/fintech-development-plan.md` | Billing math (wallet unification), real-time cost rating, margin-aware routing, capacity/SLO math, reliability-as-revenue, growth accounting | `FM-*` |

> **Rule:** commit messages and PR titles carry the track prefix (`SR-1.4`, `DE-5`), never a bare "Phase N".

---

## Track A — Security Remediation (from `MODERNIZATION_PLAN.md`)

| ID | Item | Status | PR |
|---|---|---|---|
| SR-0 | CRITICAL marketplace SQL | ✅ merged | #148 |
| SR-1.2/1.3 | Router auth (staff/secrets/red-team/doc-intel) + admin fail-closed | ✅ merged | #148 |
| SR-1.1 | Tenant tier from billing plan, not `X-Tenant-Tier` header | ✅ merged | #149 |
| SR-1.4 | `/gdpr` router auth (unauthenticated erasure closed) | ✅ merged | #154 (1c920552) |
| SR-1.4b | GDPR IDOR tenant-ownership match | ✅ done — own-tenant-or-`X-Admin-Key` on `purge_tenant`/`audit`; bulk `purge/before` now admin-only. Policy fork resolved: self-service default + operator override. |
| SR-2 | 8 SSRF sinks through `net_guard` + no-redirect | ✅ merged | #148 |
| SR-2.3 | net_guard validated-IP pinning (TOCTOU/DNS-rebind) | 🟡 primitive done — `resolve_validated_ips()` returns the validated IPs a pinned transport must dial; wiring the pinned httpx transport into live callers (needs real-host TLS-SNI test) remains | — |
| SR-2.4 | CORS `/ext/*` allowlist + refuse `CORS_ORIGINS=*` with credentials | ✅ merged | (SR-7/8 batch) |
| SR-3 | Correctness: Semantic params, STIX race, ZSET, OpenAI URL, stream-unmask, priv-esc, blocking-I/O | ✅ merged | #148 |
| SR-3.8 | Remove dead `_collect_or_emit` | ✅ merged | #154 (1c920552) |
| SR-4 | Invariants: SAR pre-screen, A2A boundary, GDPR-logs, refund key, Settings secrets | ✅ merged | #148 |
| SR-5 | **DB-layer consolidation** | ✅ delivered under DE-6 (`WARDEN_DATA_DIR`/`data_path`, `/tmp` sweep, `db/ddl_registry.py` DDL-once) — C2 as decided |
| SR-6 | Fail-open observability | ✅ done — `record_failopen()` + `warden_stage_failopen_total` + FAILOPEN-01 ratchet (`test_no_new_counterless_failopen`, baseline 200) |
| SR-7 | CI/supply-chain hardening | ✅ gates in — bandit (HIGH), **semgrep** and **gitleaks** all GATING at a verified-clean baseline; SBOM/SLSA/Trivy/pip-audit/ZAP/Nuclei already existed. Coverage→85% (SR-7.2) + mutation testing (SR-7.3) still open |
| SR-8 | Doc-vs-code reconciliation | ✅ done — JIT lease is real (`warden/gsam/jit_lease.py`, fail-CLOSED); this table reconciled against code |

## Track B — Deep-Eng / Math (from `docs/modernization-plan-v8.md`)

| ID | Item | Status | PR |
|---|---|---|---|
| DE-1 | GSAM downstream completion | ✅ merged | #150 (+ GSAM chain #138–#143 open) |
| DE-2 | Two-phase preflight billing (reserve→commit) | ✅ merged | #151 |
| DE-3 | Embedding + hyperbolic model upgrade (TDA H1 slice done) | 🟡 in-flight | #152 (slice) |
| DE-4 | Bayesian MAESTRO & reputation (collusion slice done) | 🟡 in-flight | #153 (slice) |
| DE-5 | Causal Arbiter online Robbins-Monro calibration | ✅ merged | (c946b1f1) |
| DE-6 | **Data-layer consolidation** + ClickHouse | ✅ merged — `WARDEN_DATA_DIR`, /tmp sweep, encrypted nightly backup, DDL registry, `GET /gsam/health` (CH was already on in compose) |
| DE-7 | Runtime isolation & key hygiene | 🟡 2/3 — fail-CLOSED mandate signing (unsigned-mandate bypass fixed, 17a57067) + agentic boundary gate for SOVA/Master (8e12047e). BrowserSandbox process isolation remains |
| DE-8 | SOVA agent runtime modernization | ✅ core shipped (branch `feat/sova-modernization`) — **P1** prompt-cache the 75-tool prefix + parallel tool dispatch + centralized model (`claude-opus-4-8`, `SOVA_MODEL`); **P2** cost tracking via staff economics (`agent_id="sova"`) + `AgentSpan` structured logs; **P3** activated the previously-dead semantic-memory recall/store (pgvector, fail-open) + cache-safe tool profiles (`full`/`ops`/`community`/`compliance`); **P4** adaptive routing (Sonnet default, Opus on complexity/HIGH MAESTRO; `SOVA_ADAPTIVE_ROUTING`) + `stream_query()` + SSE `POST /agent/sova/stream`. 18 unit tests. Reuses `staff/economics.py` + `staff/structured_log.py` read-only — additive `staff_action_costs` rows, no schema/pricing change (C-shared, see Track C note). | _pending_ |

## Track C — FinOps / Monetization (from `docs/fintech-development-plan.md`)

| ID | Item | Status | PR |
|---|---|---|---|
| FM-0 | Quick wins: SARIF export, `cached_tokens` GSAM column, uptime monitors ×4 hostnames | 🟡 2/3 — SARIF + `cached_tokens` merged (4ab0e15f); uptime monitors folded into FM-5 | 4ab0e15f |
| FM-1 | Unified wallet availability math (prepaid+trial+bonus−hold, one `available_usd()`) | ✅ core shipped — `warden/finops/wallet.py`: `available_usd()` single formula (components floored, holds subtracted, micro-precision), `WalletComponents`, `spend_breakdown()` (free money first: bonus→trial→prepaid), `resolve_wallet()`/`resolve_available_usd()` resilient adapters composing prepaid+hold from `sac.preflight` and trial/bonus grants (Redis `finops:grant:*`, default 0). No schema change to the SAC ledger. 15 tests | _pending_ |
| FM-2 | Real-time cost rating — CH `billing_session_ledger` SummingMergeTree + MV, prompt-cache discount | ✅ core shipped — `warden/finops/rating.py` single price-book (90% cache-read discount, `rate_usage`/`blended_input_rate`); `compute_cost_usd` cache-aware; `billing_session_ledger` SummingMergeTree + MV (units-only, rate at read) applied fail-open in `ensure_schema` + init.sql | _pending_ |
| FM-3 | Margin-aware model routing + per-tier pricing floor (additive after security gates) | ✅ core shipped — `warden/finops/margin.py`: `margin_fraction`, `pricing_floor_usd`, `evaluate_margin` (proceed/throttle/block), `pick_model_within_margin` (most-capable model clearing the floor, never routes below the allowed set), `tier_revenue_per_request` (price÷quota from billing, resilient→None=no floor). Pure + advisory, additive after fail-closed gates. 23 tests | _pending_ |
| FM-4 | 4 GB-node efficiency: mem-limit audit, M/G/1 capacity ceiling; MILP archived until ≥2 nodes | ✅ core shipped — `warden/finops/capacity.py`: Pollaczek–Khinchine M/G/1 (`mg1_wait_seconds`/`mg1_response_seconds`/`utilization`), capacity ceilings (`max_rps_for_utilization` ρ-cap + `max_rps_for_latency` closed-form solve + binding `capacity_ceiling`), `audit_mem_limits` (over-commit vs schedulable RAM) + resilient `parse_compose_mem_limits`. MILP left archived (single node). 17 tests | _pending_ |
| FM-5 | Reliability = revenue: 2× cloudflared replicas, error-budget burn-rate alerts | 🟡 in-flight — pure error-budget + multiwindow burn-rate math (`warden/reliability/`) + `GET /monitors/error-budget` + **Slack burn-rate alert wired** (`sova_error_budget_alert` ARQ cron every 30m: reads per-window uptime from `probe_results`, evaluates the SRE multiwindow table, pages/tickets to Slack with per-(monitor,severity) Redis cooldown; 11 tests) landed; cloudflared replicas + creating the 4 uptime monitors remain (operational, needs prod coord) | — |
| FM-6 | Growth accounting: funnel events, viral coefficient K, LTV/NRR dashboard | ✅ core shipped — `warden/finops/growth.py`: `build_funnel` (per-stage + top-of-funnel conversion, worst-leak detection), `viral_coefficient` (factored K = invites/user × acceptance × activation, verdict self_sustaining/healthy/weak/dead + amplification 1/(1−K)), unit economics (`arpa`, `logo_churn`, `net_revenue_retention`, `ltv`, `ltv_cac_ratio`, `payback_months`, `unit_economics` bundle with SMB healthy gate LTV:CAC≥3 & payback≤6mo), `resolve_referral_k` resilient adapter reading `billing/referral.py` redemption counters. Pure + observational, no storage added. 34 tests | _pending_ |

Track C shared-file notes: `staff/economics.py` pricing dict (C-shared with Track B GSAM), GSAM schema (`gsam/schema.py` + `docker/clickhouse/init.sql` must stay in sync), `sac/preflight.py` wallet. FM never weakens a security gate — margin logic is additive after fail-closed checks.

---

## Track F — Fintech / Money Layer (from `docs/fintech-grade-commerce-plan.md`)

Registered 2026-07-18. Sequencing lives in `docs/master-kickoff-plan.md`; target
structure in `docs/fintech-architecture.md`. FT owns **money semantics**
(ledger, authorization posture, settlement, financial compliance); ledger
*storage* is C2-shared with Track B (DE-6 `open_db`/`ddl_registry`); cost/margin
*math* stays Track C (`finops/rating.py` price-book is the only rate table).

| ID | Item | Status | PR |
|---|---|---|---|
| FT-3a | AP2 key hotfix — per-call Fernet resolution, no `Fernet.generate_key()` fallback, fail-closed in prod (pulled forward from FT-3) | ✅ done — `_fernet()` per-call, backward-compatible with `VAULT_MASTER_KEY` ciphertext, `InsecureKeyError` in prod; 6 regression tests (`test_ap2_vault_key.py`). Committed on `deeng/de6-p1-open-db-helper` pending clean rebranch/merge | 83177629 |
| FT-0 | Money foundations: `ledger/money.py` (int micro-USD), money-mutation inventory, float-money `REAL`-column ratchet | 🟡 core done — `warden/ledger/money.py` (`Money` int µUSD, Decimal-only boundary, float rejected, conservation-safe `split_fee`), 26 tests; `docs/money-mutation-inventory.md`; `test_no_new_real_money_columns.py` ratchet (baseline 51, may-only-drop). Float-arithmetic ratchet deferred (needs low-false-positive money-path definition) | — |
| FT-1 | Double-entry ledger core (`warden/ledger/` journal/accounts/holds/rollup, hash-chained, idempotency-keyed) | 🟡 core done — `accounts.py` (closed `ns:owner:leaf` grammar + canonical constructors + normal-side) and `journal.py` (`post()` balanced Σ=0 + `Idempotency-Key` UNIQUE replay-no-op, immutable rows, SHA-256 per-tx chain + `verify_chain`, `balance()` derived from postings, `open_db`+DDL-registry `ledger` key, integer µUSD). 16 tests incl. conservation over 300 txs + tamper detection. ✅ `holds.py` (two-phase reserve→capture/void, journal-backed, idempotent per phase) + `rollup.py` (materialized `ledger_balances` cache, journal-derived `refresh`/`balance`) done — 17 more tests. FT-1 complete; feeds FT-2 | — |
| FT-2 | Migrate balance writers (credits, wallet funding, preflight holds) + trial/bonus as `promo:*` accounts (NF-1) + monetary referral kickback (NF-2) | 🟡 foundation done — `warden/ledger/operations.py`: canonical idempotent journal-backed flows (`topup`, `grant_trial`, `grant_bonus`, `grant_credits`, `purchase` w/ conserving fee-split, + `reserve`/`capture`/`void` re-export) = the target API. 11 tests. ✅ slice 2a: `dual_write.py` (dual-run bridge — `LEDGER_DUAL_WRITE` gate + fail-OPEN `mirror()` + generic `reconcile()`) + `spend_credits` op + `settings.ledger_dual_write` flag; cutover = **dual-run + reconcile** (chosen). ✅ slice 2b: `marketplace/credits.py` grant/deduct now mirror into the ledger (guarded, `record_failopen`-counted, default-off) — first live writer wired; 8 wiring tests + also fixed a latent counterless-failopen ratchet miss from 2a's `mirror()`. ✅ slice 2c: `sac/preflight.py` reserve/commit/release now mirror `operations.reserve`/`capture`/`void` (guarded, `record_failopen`-counted, gated default-OFF; commit capped at held). 7 wiring tests. ✅ slice 2d: `finops/ledger_recon.py::credit_drift()` — the reconciliation keystone; enumerates every tenant's credit balance (`credits.all_balances()`, new) and compares to the ledger via `dual_write.reconcile()`, fail-soft (never blocks, never raises). 5 tests incl. zero-drift-after-mirrored-grants and drift-detection-on-unmirrored-write. Trial/bonus grant writers deferred — no clean single write path exists yet (only a read in `finops/wallet.py`). FM-1 `available_usd()` re-point (the read-cutover) stays deferred until an operator runs `LEDGER_DUAL_WRITE=true` in prod and `credit_drift()` shows zero over a shadow period — genuinely a human go/no-go, not a code slice | — |
| FT-3 | Idempotency-Key on money endpoints + remove financial `INSERT OR REPLACE`. ⚠️ Scope note: the original plan's "fail-closed money-authorization posture flip" (x402/autonomy exception→deny) is **rejected** — contradicts standing invariants (root `CLAUDE.md` "x402 fail-open", `marketplace/CLAUDE.md` #13/#20); confirmed with the project owner 2026-07-20. Remaining FT-3 scope is idempotency-only | ✅ complete — **3a** `marketplace/clearing.py`: `clearing_id` now deterministic (`clear-{winner_neg_id}`, was `uuid.uuid4()` — every retry minted a fresh row); `INSERT OR REPLACE` → `ON CONFLICT DO NOTHING` + read-back; `clear()` returns the existing row on replay instead of re-running auto-reject + fee computation. Consolidated 5 raw `sqlite3.connect` sites → 2. 6 tests. **1b** (#175) `marketplace/api_escrow.py`: transition endpoints now 404 on nonexistent escrow vs 409 on illegal state transition (was undifferentiated 400). **3b** `marketplace/credits.py` + API: `POST /credits/purchase` had **zero** idempotency key — a retried Lemon webhook/double-submit granted credits **twice** (real duplicated spendable balance, not just a log row). `purchase_credits(..., idempotency_key=...)` now records each grant (`marketplace_credit_purchases` table) and returns the cached balance on replay; whole check→grant→record sequence serialized under the module's existing `_db_lock` to close the concurrent-race window; endpoint requires an `Idempotency-Key` header (400 if missing). 7 tests incl. an HTTP-level double-POST-same-key test. **3c** `marketplace/listing.py` + API: `purchase_listing()` (the `buy`/`POST /listings/{id}/purchase` path) had **zero** idempotency key either — a retried call created a SECOND purchase row AND a second escrow for the same buyer intent, a real double-charge. Added a nullable `idempotency_key` column + partial-unique index (`WHERE idempotency_key IS NOT NULL`, so legacy/no-key rows stay unconstrained); check-then-create sequence serialized under the existing `_db_lock`; replay returns the original response (incl. real `escrow_id`, now persisted back onto the purchase row post-creation — previously always `""`); endpoint requires `Idempotency-Key`. 7 tests. Updated 2 pre-existing integration tests (`test_hub_marketplace_flow.py`, `test_production_readiness.py`) that called the now-gated endpoint with no header. **FT-3 idempotency scope is now complete** (clearing, credits, listings — the three money-moving endpoints) | #174, #175 |
| FT-4 | Settlement worker + nightly reconciliation + transactional outbox (absorbs NF-3) | ✅ complete — slice 1 done — `warden/workers/x402_settlement.py::settle_pending_deductions()`: drains `x402_pending_deductions` (`status='pending'` rows, previously accumulated forever with zero settlement) — marks each row `settled` + `settled_at`, gated per-row on `status='pending'` so it's idempotent under a re-run or a concurrent race (lost race ⇒ 0 rows touched, not an error). Returns a per-run `SettlementSummary` (settled count, distinct agents, total USD) for audit/reconciliation. Fail-soft: one bad row is skipped and counted in `errors`, the rest of the batch still settles; a missing DB/table (no x402 activity yet) returns an empty summary rather than raising. Wired as `settle_x402_deductions` ARQ job, cron every 15 min in `warden/workers/settings.py`. Deliberately does not (re)declare the table's own DDL to avoid a duplicate `REAL` money-column ratchet hit — relies on x402_gate.py's existing table, additive `ALTER TABLE` only for the new `settled_at` column. 6 tests; 242 marketplace+x402 tests green; ruff+mypy clean; 4 ratchets green. ✅ slice 2 done — `warden/workers/ledger_recon_job.py::run_ledger_reconciliation()`: wires the pure `finops/ledger_recon.py::credit_drift()` (which existed since FT-2 slice 2d but was never scheduled or observable — its own docstring said "that is FT-4") into the `warden_ledger_recon_drift_usd` Prometheus gauge + a Slack alert on nonzero drift; ok state fires no alert. Wrapper only — `credit_drift()`'s own fail-soft posture (never raises, ok-by-vacuity on read error) is untouched. Cron `nightly_ledger_recon`, daily 04:00 UTC. 10 tests (5 new + 5 pre-existing pure-function tests re-verified); 239 marketplace/x402/recon tests green; ruff+mypy clean; 4 ratchets green. ✅ slice 3 done — `warden/marketplace/clearing.py`: replaced the fire-and-forget async `_write_postgres()` with a transactional outbox. Every `clear_async()` first durably enqueues a `marketplace_clearing_outbox` row (`status='pending'`, idempotent on `clearing_id` — a replay enqueues nothing new), *then* attempts the relay; a failure leaves the row pending (attempts incremented) instead of losing it silently. New `relay_pending()` drains pending rows — wired as `relay_clearing_outbox` ARQ cron, every 5 min. Already-relayed rows are a no-op (no duplicate Postgres write). Full recon (comparing outbox state to what Postgres actually holds) deferred — this slice guarantees nothing diverges *without at least being recorded as owing a retry*. 9 new tests (7 outbox behavior + 2 ARQ wrapper); 238 marketplace/outbox/idempotency tests green; ruff+mypy clean; 4 ratchets green. **Holds reconciliation deferred** — extending the `credit_drift()` pattern to `sac/preflight.py` holds needs a semantics decision (what counts as drift for a hold created before dual-write was enabled: expected absence vs real drift) that wasn't resolved in this pass; asked the user, they chose to prioritize the outbox instead. ✅ outbox retention/cleanup done — `warden/marketplace/clearing.py::purge_relayed_outbox()`: deletes `status='relayed'` outbox rows older than `older_than_days` (default 30); `status='pending'` rows are *never* purged regardless of age, so a stalled relay can't lose its retry record. Fail-soft (read/delete error returns a zero summary, never raises). Wired as `purge_clearing_outbox` ARQ cron, weekly Sunday 05:00 UTC, in `warden/workers/clearing_outbox_relay.py`. 4 new direct unit tests (pending-never-purged, within-window kept, past-window purged, fresh-db noop) + 2 pre-existing ARQ-wrapper tests; 15 outbox tests green; ruff+mypy clean; 4 ratchets green. ✅ holds reconciliation done — resolved the deferred semantics decision: `sac/preflight.py::open_holds()` enumerates every currently-open (`status='HELD'`) hold; `finops/ledger_recon.py::hold_drift()` reconciles each individually against its own `hold:{hold_id}` ledger contra account, since a hold is a per-transaction account (not a per-tenant running balance like credits). A hold that predates dual-write has no mirrored ledger entry and would misreport as drift — but holds are short-lived (reserve → commit/release within one agent run), so any such false positive self-clears the moment the hold resolves and drops out of `open_holds()`, unlike an unbackfilled credit balance that would drift indefinitely. Wired as `nightly_hold_recon` ARQ cron (daily 04:10 UTC) + `warden_ledger_recon_hold_drift_usd` gauge + Slack alert, same wrapper pattern as slice 2. 17 new tests (5 `open_holds()` + 7 `hold_drift()` + 5 job wrapper); ruff+mypy clean; 7 ratchets green. Remaining, deliberately out of scope: full recon comparing outbox status to actual Postgres state (slice 3's at-least-once posture is an accepted permanent tradeoff, not a gap) | — |
| FT-5 | Compliance: KYB behind KYA, sanctions at settlement, AML on journal stream, licensing-posture doc | 🟡 2/4 — `docs/licensing-posture.md` done: full money-flow inventory (subscription billing via Lemon Squeezy MoR, internal service credits, M2M marketplace escrow/clearing, x402 metering) traced to code, concluding the system's money handling is a closed-loop non-redeemable service-credit model (no MSB/money-transmitter registration warranted *as implemented*), conditional on 4 invariants (no redemption path, no third-party payout, fiat-in stays behind the MoR, escrow settles to internal accounts only) — explicitly flagged as a technical review for counsel, not legal advice. Highest-attention item for follow-up counsel review: §2.3 marketplace escrow (tenant-to-tenant, still closed-loop credits not fiat). ✅ KYB behind KYA done — `warden/marketplace/kyb.py` (new): `KYBRecord` per **owner tenant** (not per agent, unlike KYA), draft-only lifecycle `REQUIRED → SUBMITTED → VERIFIED\|REJECTED` — the system never self-verifies, only an explicit `verify_kyb(reviewed_by, approved)` compliance-officer call does. `require_kyb()` is never self-triggered: `kya.py::screen_agent()` calls it when an agent comes back `FLAGGED`, escalating a KYB requirement onto that agent's owning tenant (hence "KYB behind KYA"), guarded (lazy import + broad except, same posture as the ledger dual-write mirrors) so a KYB failure can never break KYA screening. `kyb_blocks_participation()` is a pure read (any status but `VERIFIED`/`NOT_REQUIRED` blocks) — deliberately not yet wired into any enforcement path (clearing/listing), the same incremental-slice pattern FT-4's outbox used before its retention follow-on. 27 new tests (23 `kyb.py` lifecycle + 4 `kya.py` escalation-wiring, the latter fixing a latent `importlib.reload()` module-state leak from a pre-existing threshold test along the way); ruff+mypy clean; 7 ratchets green. Remaining: sanctions screening (`staff/tools/compliance_kyc.py::screen_sanctions_list()` exists but isn't wired into any settlement path yet) at settlement; AML on the journal stream | — |
| FT-6 | Consolidation: single `authorize_payment()` chokepoint (+ ratchet), one x402 impl, one order model (absorbs NF-6/MI-4) | ⬜ | — |
| FT-7 | Assurance: money-conservation property tests, chaos tests, auditor export, SOC 2 mapping | ⬜ continuous | — |

Related non-FT items scheduled in the kickoff plan: MI-1/MI-2 (GSAM taps +
quarantine gate in marketplace — Track B), NF-5 mediator (Track B, DE-4),
MI-5 tunnel enforcement v1 (Track B, coordinate `net_guard` with Track A).

---

## Conflict zones (shared files — ownership rules)

| # | File / surface | Track A touched | Track B touched | Reconciliation rule |
|---|---|---|---|---|
| C1 | `warden/causal_arbiter.py` | SR-3: zero-prior drift-gate hole fix + 25% CPT gate | DE-5: online Robbins-Monro calibration | **DE owns the math.** Any calibration change MUST keep the 25%/zero-prior drift gate (anti-poisoning). Add a test asserting both hold together. |
| C2 | Data layer (62 `_conn`/DDL copies, Turso/SQLite/ClickHouse) | SR-5 (unify connection layer) | DE-6 (ClickHouse on, category 11) | **Single effort.** Merge SR-5 + DE-6 → one `warden/db/` consolidation, owned by Track B (they own storage). Track A supplies the "one context-manager, DDL-once" requirement. |
| C3 | `staff_dispatch` / `BoundaryRegistry` | SR-4.2: A2A boundary+suspension enforcement | GSAM quarantine additive gate; DE-7/S5: extend to SOVA/Master | **Additive gates only**, after boundary check; never weaken STAFF-01/02. Track B's S5 extension builds on SR-4.2 — coordinate order. |
| C4 | SSRF (`net_guard`, Inner Warden) | SR-2: 8 sinks guarded | SAC "Inner Warden SSRF fail-CLOSED" (#150) | Deduplicate: one guard path. SR-2.3 IP-pinning, if done, lands in `net_guard` and both consume it. |
| C5 | Key hygiene (`resolve_key`, JIT lease) | SR-4.4 refund key via resolve_key | DE-7 key hygiene; SAC/GSAM JIT lease (now real) | SR-8 doc-reconciliation marks JIT lease SHIPPED (it exists now) and closes the old doc-vs-code gap. |

---

## Owners (assigned 2026-07-12)

- **Track A — Security Remediation** owns: authn/authz, SSRF wiring, IDOR/GDPR, request-path invariants, CI/supply-chain hardening (SR-2.4, SR-6, SR-7, SR-8, SR-1.4b).
- **Track B — Deep-Eng / Math** owns: all ML/detection math (TDA, MAESTRO, Causal, embeddings), GSAM, storage/data-layer (incl. the merged SR-5+DE-6), runtime-isolation math.
- **Shared, coordinate before touching:** the five files in the conflict table. Rule: whoever edits one references the other track in the PR description and runs the other track's relevant tests.

## Decisions log

- **2026-07-18 — S7 done; §6d S1–S7 security-hardening backlog CLOSED.** S5 was recognised as already delivered (= DE-7 Phase 7 Slice 2, `agentic_gate()`, 2026-07-13). S7 repaired the weekly DAST (`pentest.yml`): Nuclei install 404 fixed (versioned release asset via API), and a new `zap-api-scan` job drives ZAP off `/openapi.json` against an ephemeral CI-booted warden — the old "green" baseline had scanned exactly one URI (`/robots.txt`). Pen-test (annual) + threat-model refresh (semi-annual) cadence in `docs/security-model.md` §8.
- **2026-07-12 — Registry adopted as canon.** Wired into `CLAUDE.md` ("Modernization Governance") so both efforts read the same rules. `SR-*`/`DE-*` prefixes are now required; bare "Phase N" is retired.
- **2026-07-12 — Track owners assigned** (above). The session that has been landing security PRs (#148/#149/#154) drives **Track A**; the session landing the deep-eng/GSAM PRs (#150–#153, Phase-6 data-layer) drives **Track B**.
- **2026-07-12 — C2 (data-layer) RESOLVED: Track B leads.** SR-5 does **not** spawn a separate DB-consolidation effort; it folds into DE-6, which is already in flight (`421f2ea6` "data-layer consolidation, Phase 6 slice 1"). Track A's contribution to DE-6 is a requirement, not a parallel PR: *one connection context-manager, DDL applied once at startup (not per call), guaranteed `close()`; retire the ~62 duplicated `_conn`/DDL helpers.* Track A will review DE-6 PRs against that checklist.
- **C1 guardrail ✅ (2026-07-14):** `warden/tests/test_causal_c1_guardrail.py` asserts DE-5 online calibration and the SR-3 25%/zero-prior drift gate coexist — shared `0.25` bound, per-step online clamp, batch gate still rejects >25% drift after online updates, ordering invariant survives adversarial slow-burn, zero-prior safe on both paths.

- **2026-07-13 — SR-8 reconciliation done; Track A closed out.** The table above was re-derived from
  the code, not from the plan text. Findings worth recording:
  - The plan's "JIT lease missing" gap (SR-8.1) is **stale** — `warden/gsam/jit_lease.py` exists and is
    fail-CLOSED. Likewise SR-4.4's refund key was already on `resolve_key`.
  - SR-5 was never worked as a separate effort (C2 held): it is satisfied by DE-6.
  - SR-6 was already satisfied by the FAILOPEN-01 ratchet + `warden_stage_failopen_total`.
  - Enabling bandit surfaced **three real HIGH findings the plan had not listed**, now fixed:
    `verify=False` on the MISP threat-intel feed (a MITM could inject IOCs/rules straight into the
    detection corpus) and on the LND client (which ships a bearer macaroon); SHA-1 in a cache key; and
    raw bidi/trojan-source control characters in `obfuscation.py`'s own source (now codepoints).
    `shadow_ai/discovery.py` keeps `verify=False` deliberately — it is a credential-free internal probe.
  - Turning **semgrep** on surfaced 6 more, all **XXE**: stdlib `xml.etree` parsing *untrusted* XML —
    the SAML assertion an attacker POSTs to the ACS endpoint, plus external threat/ArXiv feeds. External
    entities resolve, so this allowed local-file exfiltration, SSRF and billion-laughs DoS. Fixed with
    `defusedxml` at all 4 call sites (`auth/saml.py`, `brain/threat_feed.py`, `threat_intel/sources.py`),
    pinned in requirements, and pinned shut by `warden/tests/test_xxe_hardening.py`.
  - **Lesson:** semgrep and gitleaks were landed *observing* precisely because they could not be run on
    the dev box. That call was right — semgrep failed on its first run. Gating them sight-unseen would
    have reddened `main`. Both gate now, from a verified baseline.

## Immediate actions

1. Adopt the `SR-*` / `DE-*` prefixes; retire bare "Phase N" in messages.
2. ~~Merge SR-5 and DE-6~~ — done (DE-6 delivered both).
3. ~~Land #154 / GSAM chain~~ — #154 merged (1c920552).
4. ~~C1 regression test~~ — done (`test_causal_c1_guardrail.py`).
5. **SR-7 remainder:** all three SAST/secret gates now gate (bandit HIGH / semgrep ERROR / gitleaks).
   Still open: coverage floor 75% → 85% (SR-7.2) and extending mutation testing (SR-7.3).
6. **DE-7 remainder:** BrowserSandbox process isolation (seccomp/restricted-user sidecar).
7. **SR-2.3 transport wiring** — the validated-IP resolver (`resolve_validated_ips`) is done + tested;
   the remaining step is a pinned httpx transport (connect to the validated IP, preserve Host/SNI) wired
   into the live outbound callers. That step needs a real-host TLS-SNI test and auto-deploys to prod, so
   it was NOT shipped blind. (SR-1.4b resolved: own-tenant-or-admin.)
