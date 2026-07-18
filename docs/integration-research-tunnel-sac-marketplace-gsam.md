# Integration Research — Tunnel × SAC × Agentic Marketplace × GSAM

Date: 2026-07-18 · Status: research (no code changes) · Owner: Track B (DE-*)

Scope: how the four subsystems exist today, where they already connect, where they
do **not**, and a proposed integration roadmap. Sources: repo state on
`deeng/de6-p1-open-db-helper` (post-84aa374c), `docs/sac-architecture.md`,
`warden/marketplace/CLAUDE.md`, `docs/modernization-plan-v8.md`.

---

## 1. Current state per subsystem

### 1.1 Tunnel (MASQUE Jurisdictional Tunnels — `warden/sovereign/`)

- `tunnel.py`: MASQUE-over-H3/H2/CONNECT registry, lifecycle
  PENDING→ACTIVE→DEGRADED→OFFLINE, TOFU TLS pinning + CA upgrade (CR-15),
  Redis-backed with in-proc fallback.
- `router.py`: routing decision engine (policy → allowed jurisdictions → ACTIVE
  tunnels → preferred/lowest-latency), `check_compliance()`, adequacy decisions.
- `attestation.py`: HMAC-signed sovereignty attestations (7-year Redis TTL).
- Probing: `sova` scheduler job calls `probe_tunnel()` periodically.
- REST surface: `warden/api/sovereign.py` (full CRUD + route + attest).

**Reality check:** the tunnel layer is a *registry + decision engine*, not an
enforced data path. Nothing in `warden/openai_proxy.py`, `/filter`, or the SEP
transfer path (`communities/peering.py` / `sep.py`) calls `route()` or proxies
traffic through a tunnel. `communities/sep.py` uses only the
`jurisdictions.is_transfer_allowed()` matrix. Tunnels are advisory today.

### 1.2 Shadow Agentic Container (SAC — `warden/sac/`)

- `guard.py` (Inner Warden): screens every agent tool call at the dispatch
  chokepoint — SSRF/exfil URL block **fail-CLOSED** via `net_guard`, secret-path
  denylist (warn-only), and emits the GSAM `Observation` (**fail-OPEN**,
  metadata-only). Wired into `agent/tools.py::traced_dispatch` (SOVA +
  MasterAgent via `agentic_gate`) and `staff/dispatcher.py::staff_dispatch`.
- `preflight.py`: two-phase billing wallet (`reserve → commit/release`,
  micro-USD, Turso-or-SQLite `sac_wallet`), used by `staff/agents/base.py`,
  `finops/wallet.py`, `api/wallet.py`. Reads **GSAM rollup** for actual cost
  (`recent_agent_cost_usd()` → `gsam.rollup.read_agent_stats`).
- Companion: Hermes JIT credential lease lives in `gsam/jit_lease.py`
  (fail-CLOSED key via `resolve_key`, single-use redeem).

### 1.3 Agentic Marketplace (`warden/marketplace/`, ~30 modules)

Full M2M lifecycle (register → search → negotiate → clear) with its **own,
self-contained trust & economics stack**:

| Concern | Marketplace mechanism |
|---|---|
| Identity | DID `did:shadow:…`, Ed25519 keys, KYA (PENDING/VERIFIED/FLAGGED/REVOKED) |
| Reputation | `reputation.py` TrustRank (PageRank) + `sybil_guard.py` |
| Threat detection | `maestro.py` — goal misalignment, collusion (Pearson ≥0.80), model poisoning + 7-step auto-isolation |
| Spend control | `autonomy.py` L1/L2/L3 + `x402_gate.py` (credits-first, USDC nanopayments) + `escrow.py` + `clearing.py` (1.5% take rate, Decimal) |
| Search intelligence | `vector_search.py` (pgvector + sponsored boost), `memory.py` handoff memory |

**"Modeling Intelligence"** does not exist as a module today. The nearest
existing assets are: MAESTRO detectors, TrustRank, `analytics.py`
(`fairness_stats`), `business_intelligence/predictive.py` (OLS), and the
Semantic Layer (`gsam_agent_stats` model already registered). See §3.7.

### 1.4 GSAM (`warden/gsam/`)

- Ingest: `collector.py` → ClickHouse (fail-OPEN NDJSON spool + replay),
  GDPR-allowlisted metadata only.
- Downstream: `rollup.py` (hourly `gsam_agent_stats` + drift baselines),
  `drift.py` (EWMA total-variation, poisoning-gated baseline, anti-inflation
  clamp), `quarantine.py` (Redis flag + in-proc TTL).
- Credential: `jit_lease.py` (Hermes).
- Read APIs: `/gsam/heatmap`, `/gsam/agents/{id}/stats`,
  `/gsam/compliance/score`, `/gsam/health` — always from rollup, never CH.

**Producers today: exactly one** — the SAC guard (SOVA/Master/staff tool calls).
**Quarantine consumers today: exactly two** — `agent/gate.py::agentic_gate` and
`staff/dispatcher.py`.

---

## 2. Integration matrix (today)

| From \ To | Tunnel | SAC | Marketplace | GSAM |
|---|---|---|---|---|
| **Tunnel** | — | none | none | none |
| **SAC** | none | — | none | ✅ guard emits Observations; preflight reads rollup cost |
| **Marketplace** | none | **none** | — | **none** |
| **GSAM** | none | ✅ jit_lease colocated; quarantine gates SOVA/staff | **none** | — |

The headline finding: **GSAM is named "Global Statistic Agentic *Marketplace*",
yet the marketplace package has zero imports of `gsam`, `sac`, or `sovereign`.**
Two disjoint reputation systems run in parallel (TrustRank/KYA/ERS vs GSAM
drift/compliance-score), and M2M agent actions are the only agentic surface in
the product that bypasses both SAC screening and GSAM observation. Similarly,
tunnels are registered and attested but never sit in a real data path.

---

## 3. Proposed integration workstreams (MI-1…MI-7)

Ordered by security value / effort. All additive — no existing invariant
(STAFF-01/02, fail-open telemetry vs fail-closed security, GDPR metadata-only)
is weakened.

### MI-1 — Marketplace → GSAM observation taps (small, high value)
Emit `gsam_emit(Observation)` from the `/marketplace/action` dispatcher
(register/search/negotiate/clear), `x402_gate.deduct_payment()`,
`escrow` state transitions, and MAESTRO verdicts. `payload_kind` = action type,
`scan_verdict` = MAESTRO/Sybil outcome, `cost_usd` = x402/clearing amounts.
Metadata only — never offer bodies. Mirrors the SAC-guard tap pattern
(fail-OPEN, swallowed exceptions). This makes GSAM's name true and gives drift
baselines per M2M agent for free.

### MI-2 — GSAM quarantine gate in the marketplace (small)
Check `gsam.quarantine.is_quarantined(agent_id)` in the action dispatcher and
`x402_gate.require_payment()` — **additive**, after the existing Sybil/KYA
gates, same pattern as `staff_dispatch`. A drift-quarantined agent stops
trading, not just tool-calling.

### MI-3 — Reputation unification (medium)
Feed `gsam.rollup.compliance_score` into KYA risk scoring
(`kya.py` v2 slot already reserved for external identity) and into the
BrandAgent TrustRank gate as an additional factor. The anti-inflation clamp
(≥2 distinct counterpart contracts) already guards against self-dealing boosts.
Keep TrustRank authoritative; GSAM is a modifier, not a replacement.

### MI-4 — SAC preflight for M2M spend (medium)
Route `BuyerAgent.search_and_buy()` / `auto_buy()` through
`sac.preflight.reserve → commit` per tenant, reconciled against the autonomy
L2/L3 caps (autonomy stays the *decision*, preflight becomes the *hold*).
Prevents a runaway buyer loop from draining credits between autonomy checks.
Open design question: relationship between `sac_wallets` (micro-USD) and
Flex Credits (`marketplace_credits`) — recommend keeping both, with preflight
holds on the credit balance mapped 1 credit = 1000 micro-USD.

### MI-5 — Tunnel enforcement in real data paths (large)
Two candidate paths, in order:
1. **SEP cross-community transfers**: `peering.transfer_entity()` consults
   `sovereign.router.route()` (not just the jurisdictions matrix) and records
   the tunnel_id in the Causal Transfer Proof + STIX bundle. Cheap: it's a
   decision + audit field, no actual proxying needed for v1.
2. **Upstream AI calls**: `openai_proxy` optionally egresses via the tenant's
   routed tunnel endpoint (httpx proxy support), issuing a sovereignty
   attestation per call. Requires real MASQUE endpoints — v2, gated on infra.

### MI-6 — JIT lease for marketplace credentials (small)
Marketplace payment/webhook secrets handed to agents via
`/gsam/lease` + single-use redeem instead of env-var exposure — consistent with
the STAFF-03 refund-intent rule ("payment credentials never passed to an
agent") and the existing token_vault mirror.

### MI-7 — "Modeling Intelligence" layer (definition proposal)
No such module exists; propose defining it as the **analytics/prediction brain
over the unified stream** rather than a new detector:
- Input: GSAM rollup (`gsam_agent_stats`) + marketplace analytics + clearing.
- Methods: existing pure-Python `business_intelligence/predictive.py` (OLS,
  trend), MAESTRO correlation outputs, drift series from `gsam/drift.py`.
- Surface: a `marketplace_intelligence` Semantic Layer model + `/gsam/heatmap`
  extension + Streamlit/SOC dashboard tab (price trends, agent-behaviour
  clusters, collusion-risk forecast).
- Explicitly not: a new LLM loop. Deterministic math first, consistent with
  Track B ownership of ML/detection math.

---

## 4. Constraints & risks

- **Governance:** all of the above is Track B (DE-*) territory (storage,
  GSAM, detection math). MI-5 touches `net_guard`/SSRF surface — shared file,
  coordinate with Track A per the roadmap conflict table.
- **DE-6 P1 in flight:** marketplace modules still use private `_conn()`
  helpers; any MI work touching their DBs should land *after* (or as part of)
  their `open_db()` migration batch to avoid conflicts.
- **Fail-posture discipline:** telemetry taps (MI-1) fail-OPEN; gates
  (MI-2, MI-4) are additive and must not convert marketplace fail-open rules
  (Brand Agent, MAESTRO isolation, x402 gate) into fail-closed by accident.
- **GDPR:** observations carry metadata only — never offer/message bodies
  (marketplace messages are freetext and already injection-screened separately).
- **Double-counting:** if MI-2 lands, ensure a single quarantine check per
  action (dispatcher OR x402 gate deciding path), mirroring the
  `already_gated=True` pattern in `staff_dispatch`.

## 5. Gap analysis vs the external integration guide (2026-07-18 addendum)

An external "CLAUDE_INTEGRATION_GUIDE" (Prisma/NestJS/TS-monorepo/Rust-eBPF
stack) and a two-sided-marketplace agent taxonomy were evaluated against the
repo. Verdict per stage:

### 5.1 Already implemented (Python-native equivalents — do NOT rebuild)

| Guide item | Existing equivalent |
|---|---|
| ClickHouse `gsam_observations` + bloom filter + TTL 30d + `SummingMergeTree` ledger + `mv_billing_rating` (cached-token discount) | `docker/clickhouse/init.sql` — **verbatim feature match** (lines 45–75), `gsam/schema.py` already carries `cached_tokens` |
| NestJS `PreflightBillingGuard` (hold → 402) | `warden/sac/preflight.py` (reserve/commit/release, micro-USD) + `warden/api/wallet.py` |
| Governance CI + SARIF upload | `.github/workflows/warden-scan.yml` + `scripts/warden_github_scan.py` (SARIF shipped in FM-0), `--gsam-posture` |
| Self-correcting test loop | `workflows/autonomous-security-loop.md` (nightly Maker/Checker) |
| Referral loop | `billing/referral.py` + `finops/growth.py` (viral-K math) + `feature_gate.py` (bonus requests/bytes per tier) |
| A2A Agent Cards, Assistant/Service roles | `protocols/a2a/agent_card.py`; `AGENT_ROLES = ("ASSISTANT","SERVICE")` in GSAM schema; buyer/seller/brand agents |
| Router/Orchestrator agent | MasterAgent (decompose → 4 sub-agents, HMAC task tokens) |
| Collusion **detection** | `marketplace/maestro.py` (Pearson ≥ 0.80 across ≥ 3 sellers) |
| AgentSonar-style shadow-AI network classifier | `shadow_ai/discovery.py` (subnet probe + DNS telemetry, 18 providers) |
| Runtime policy guard | SAC Inner Warden (`sac/guard.py`) — app-level, fail-CLOSED SSRF |

### 5.2 Genuinely new functions worth adding (adapted to the real stack)

- **NF-1 Wallet sub-balances**: extend `sac_wallets` with `trial_micros` +
  `bonus_micros` (spend order: trial → bonus → prepaid; hold math unchanged).
  Welcome trial auto-grant on tenant creation. Today referral bonuses are
  quota-based (requests/bytes), not monetary.
- **NF-2 Monetary referral kickback**: 15%-of-spend bonus credited to
  `bonus_micros` via `billing/referral.py` — closes the loop `finops/growth.py`
  already measures.
- **NF-3 OLAP→OLTP billing reconciliation**: ARQ cron that folds the ClickHouse
  `billing_session_ledger` (rate phase) back into wallet `commit()` — today
  commit uses GSAM *rollup* cost only; the CH ledger is write-only.
- **NF-4 Capability-based dynamic routing**: MasterAgent routes only to 4
  hardcoded sub-agents; add registry-driven selection over A2A agent cards /
  marketplace service agents (intent → capability match → dispatch through
  `agentic_gate`).
- **NF-5 Mediator (detect → enforce)**: MAESTRO detects collusion but corrects
  nothing; add an incentive-correction hook — reputation penalty and/or
  clearing-fee surcharge on flagged cliques (bounded, logged, reversible).
  This is the practical analogue of the guide's "Nash payoff correction".
- **NF-6 Preflight gate on agent HTTP surfaces**: enforce `reserve()` before
  `/agent/sova`, `/agent/master`, `/marketplace/action` sessions (HTTP 402 on
  insufficient funds) — same as MI-4, now with the trial/bonus split.
- **NF-7 Scan baseline file**: `--baseline` support in `warden_github_scan.py`
  (suppress known findings, fail only on new) — small CI ergonomics win.

### 5.3 Rejected (stack mismatch / documented non-goals)

- Prisma + PostgreSQL wallet schema, NestJS/Express middleware, TS monorepo
  packages — the product is Python/FastAPI with Turso-or-SQLite; duplicate
  billing state in Prisma would violate the one-data-layer rule (DE-6).
- Rust/Aya eBPF kprobe sensor, Kata/QEMU micro-VMs, QEMU vCPU-second billing —
  explicit SAC non-goals (`docs/sac-architecture.md`); no bare-metal fleet.
- MILP (PuLP) resource allocator for container placement — no multi-node
  fleet to place onto (single VPS + Docker Compose). Keep as a future pure-math
  Track B module only if/when multi-node SAC hosting exists. The proposed
  TS→Python `exec()` bridge writing solver scripts to `/tmp` also violates the
  `WARDEN_DATA_DIR` and injection-hygiene rules.
- Domain-agent zoo (Requirement/Architect/Reviewer/Sales/SEO agents) — Digital
  Staff already covers BDR/SEO/support/KYC/SAR/refund under STAFF-01…05;
  new roles belong in the marketplace as listed third-party service agents,
  not as first-party staff.

### 5.4 Feasibility verdicts — proposed "Modeling Intelligence (MI)" layer

| Proposal | Verdict | Form it should take |
|---|---|---|
| Normal-form non-cooperative game for model-quality selection + AI Mediator vs collusion | **Feasible now** | Pure-Python `warden/marketplace/mediator.py` (= NF-5/MI-7): payoff matrix from clearing prices + reputation, best-response iteration / equilibrium check (small discrete strategy sets — no solver dep), bounded incentive correction (reputation penalty, fee surcharge). Consumes existing MAESTRO collusion flags. Track B math, no LLM, tests run without infra. |
| MILP bare-metal cost minimisation (RAM, KSM dedup, SAC placement) | **Defer — no-op today** | Single VPS ⇒ placement polytope is a point (`finops/capacity.py:17` already documents this, FM-4). Revisit at ≥2 nodes as a pure-Python module with optional `pulp` extra; model then: min Σ cᵏyᵏ s.t. one-node-per-container, Σwʲxʲᵏ ≤ Cᵏyᵏ. |
| TypeScript `packages/modeling-intelligence` + `ModelingIntelligenceAllocator` (TS `exec()` → generated PuLP script in `/tmp`) | **Rejected** | Violates: no-root-workspaces rule, `WARDEN_DATA_DIR` (no `/tmp` artifacts), and injection hygiene (`JSON.stringify` interpolated into Python source = code-injection vector). Python-native module or nothing. |
| C_session cost tracing incl. MI influence | **Feasible, small** | Cost plumbing exists end-to-end (Observation.execution_cost → CH `mv_billing_rating` → rollup → preflight commit). Add an MI cost component as one more term in the rollup, not a new pipeline. |

## 6. Suggested sequencing

1. MI-1 + MI-2 (one PR each, ~1 day) — closes the "marketplace invisible to
   GSAM" gap and the quarantine bypass.
2. MI-6 (small) — credential hygiene parity.
3. MI-3, MI-4 (medium) — reputation + spend unification.
4. MI-7 — semantic model + dashboard.
5. MI-5 v1 (SEP route decision + audit field), v2 (real MASQUE egress) — gated
   on infrastructure.
