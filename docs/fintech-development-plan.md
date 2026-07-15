# FinTech-Grade Development Plan — Track C (FM-*)

**Date:** 2026-07-15 · **Status:** proposed · **Governance:** registers as **Track C — FinOps / Monetization (`FM-*`)** in `docs/unified-modernization-roadmap.md`. Commits carry `FM-N` prefixes, never bare "Phase N".

This plan is the reconciliation of an external integration guide (TypeScript/Prisma/NestJS/eBPF architecture) against the actual codebase, plus a full-project assessment across six axes: architecture, security, efficiency, resource economy, monetization, profitability.

---

## 1. Current-State Assessment (1–100, fintech lens)

| Axis | Score | Evidence | Primary gap |
|---|---|---|---|
| **Architecture** | 78 | Layered monolith + app factory (`RouterSpec`), DDL registry, `WARDEN_DATA_DIR` consolidation, route-inventory guard, CI layer-rule enforcement | 100+ routers in one process; single-node deployment; SQLite sprawl (mitigated, not eliminated) |
| **Security** | 88 | Fail-closed signing keys (`resolve_key`), SSRF IP-pinning (SR-2.3 complete), agentic gate on every tool dispatch, gating SAST (bandit/semgrep/gitleaks), PQC hybrid, STIX audit chains | BrowserSandbox process isolation (DE-7 remainder); single-tenant blast radius on one VPS |
| **Efficiency** | 55 | CPU-only ML (<2ms TDA gate), Redis cache, ONNX export, model singleton | ~17 containers on a 4 GB VPS; no memory-limit audit; hourly rollups instead of real-time rating |
| **Resource economy** | 60 | L1/L2/L3 model routing (Haiku/Sonnet/Opus), `TokenCostTracker`, prompt caching in SOVA | Cost math ignores the 90% cached-token discount → margins over-reported; no per-tenant COGS |
| **Monetization** | 70 | Full stack built: 5 tiers ($0→$249), add-ons (402/403 gates), two-phase wallet, x402 nanopayments, Lemon Squeezy metered billing, referral flywheel, 14-day trial | Demand unproven; no conversion-funnel instrumentation; wallet/trial/referral are three disjoint balance systems |
| **Profitability** | pre-revenue | Gross-margin potential >90% on `/filter` traffic (local ML, zero marginal LLM cost); infra floor ≈ $25/mo | Distribution, not technology, is the bottleneck |

**Headline economics.** The filter pipeline's marginal cost per request is CPU-only (~$10⁻⁶); LLM spend occurs only on HIGH/BLOCK evolution and agent runs. Break-even at current infra floor is **one Community Business tenant + one Individual** ($24/mo) or any single Pro ($69/mo). This is a structurally high-margin product; every phase below either protects that margin or measures it.

---

## 2. External-Guide Reconciliation (adopt / adapt / reject)

| Guide stage | Verdict | Reason |
|---|---|---|
| 1. Headless Claude auth | **Already solved** | `customApiKeyResponses.approved` fix (d6f64eb9) |
| 2. Prisma/PostgreSQL wallet schema | **Reject stack, adapt semantics** | Repo is Python/FastAPI; a TS monorepo rewrite violates the no-root-`package.json` rule and discards 4 300+ tests. Wallet **exists** (`warden/sac/preflight.py`, reserve→commit, 402). The *segmented balances* idea (prepaid/trial/bonus/hold) is adopted as FM-1 |
| 3. ClickHouse `gsam_observations` | **Already shipped (v7.7)** — near-identical schema incl. bloom filters | Adopt the delta: `billing_session_ledger` SummingMergeTree + `mv_billing_rating` MV + `cached_tokens` column → FM-2 |
| 4. MILP resource allocator (PuLP) | **Defer** | One physical node ⇒ the assignment polytope is a point; nothing to optimize. Formulation archived in §FM-4 for the ≥2-node future. Writing solver scripts to `/tmp` also violates `WARDEN_DATA_DIR` |
| 5. Preflight billing middleware | **Already shipped (DE-2, PR #151)** | Availability formula A(t) = prepaid + trial + bonus − hold adopted into FM-1 as the unified check |
| 6. eBPF/Rust guest sensor | **Reject** | Documented non-goal (`docs/sac-architecture.md`); no Kata/QEMU runtime exists to host it; SAC Inner Warden + agentic gate already cover the dispatch boundary |
| 7. Governance scan CI | **Exists** (`warden-scan.yml`) | Adopt the delta: SARIF export → GitHub Code Scanning tab (FM-0) |
| 8. Self-correcting test loop | **Exists** | Nightly autonomous loop + Maker/Checker |
| Agent taxonomy (Assistant/Service/Orchestrator/Guard) | **Exists** | GSAM `role Enum8('ASSISTANT','SERVICE')`, MasterAgent = orchestrator, SAC guard = runtime policy agent; A2A = `warden/staff/a2a.py`. Mediator payoff-correction (Nash) folds into MAESTRO work (DE-4), not a new track |

The guide file itself must **not** be committed to the repo root: it is Russian-language (violates the English-only rule) and its `[cite: N]` references are unverifiable.

---

## 3. Phased Roadmap

### FM-0 — Quick wins (≤1 day)
- **SARIF export** in `scripts/warden_github_scan.py` + `upload-sarif` step in `warden-scan.yml` → findings appear in the repo's Code Scanning tab.
- **`cached_tokens UInt32`** column added to `gsam_observations` (ClickHouse `ALTER TABLE ADD COLUMN` is metadata-only; also update `warden/gsam/schema.py` — the two DDLs must stay in sync).
- Uptime monitors for all four public hostnames (api/dash/analytics/portal) via the existing `/monitors` API — tonight's outage was detected only on `api`.

### FM-1 — Unified wallet math (segmented balances)
Today three balance systems coexist and cannot be summed: wallet (USD, SQLite), trial (requests, Redis TTL), referral bonus (requests, Redis). Unify the **availability check** without merging storage:

    A_tenant(t) = balance_usd + usd_equiv(trial_remaining(t)) + usd_equiv(bonus_remaining(t)) − holds(t)

- `usd_equiv()` prices remaining request-quota at the tenant's tier marginal rate (overage price), making trial/bonus spendable against agent runs, not only `/filter` quota.
- One function `warden/billing/availability.py::available_usd(tenant_id)` consumed by `sac/preflight.reserve()`; 402 body enumerates the shortfall per segment (actionable top-up CTA).
- Invariant test: no path may spend the same trial/bonus unit twice (idempotent decrement, mirrors the x402 nonce pattern).
- **Fail-closed** for reserve (insufficient data ⇒ 402), fail-open for read-only balance display.

### FM-2 — Real-time cost rating (the guide's one genuinely new idea)
Hourly SQLite rollups are fine for dashboards but too slow for margin enforcement. Add to ClickHouse:

```sql
CREATE TABLE IF NOT EXISTS gsam.billing_session_ledger (
    session_id String,
    tenant_id LowCardinality(String),
    total_cost_usd Float64,
    last_update DateTime
) ENGINE = SummingMergeTree() ORDER BY (tenant_id, session_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS gsam.mv_billing_rating
TO gsam.billing_session_ledger AS
SELECT session_id, tenant_id,
       sum( ((input_tokens - cached_tokens) * in_rate(model))
          + (cached_tokens * in_rate(model) * 0.1)      -- 90% prompt-cache discount
          + (output_tokens * out_rate(model)) ) AS total_cost_usd,
       max(ts) AS last_update
FROM gsam.gsam_observations GROUP BY session_id, tenant_id;
```

- Rates come from one authoritative dict (extend `_MODEL_BY_LEVEL` pricing in `warden/staff/economics.py`; never duplicate rate tables).
- **Consumers read the ledger via the existing rollup/read-API pattern — never raw ClickHouse from request paths** (same rule as `gsam_agent_stats`).
- Margin alert: when a session's ledger cost exceeds `α × tier_price/expected_sessions` (start α=0.5), emit a `warden.margin` structured log + Slack alert. This converts the tracker from *reporting* to *enforcement input* for FM-3.
- Correctness gate: ledger totals must reconcile with `staff_action_costs` SQLite within 2% weekly (drift test), since ClickHouse ingest is fail-open and can drop rows.

### FM-3 — Margin-aware routing & pricing floor
With per-action real costs (FM-2) and prompt-cache-corrected math:
- Expected-margin router: before an L3 (Opus) escalation, compute `E[margin] = tier_marginal_revenue − E[cost | model]`; if negative and the task class permits, degrade to L2 with a logged `margin_downgrade` event. Never degrade security-critical paths (Checker audits, evolution validation) — margin routing is **additive after** correctness constraints, mirroring the quarantine-gate pattern.
- Publish a **pricing floor** per tier from observed P95 COGS: `price_floor = P95(monthly_COGS_per_tenant) / (1 − target_margin)`, target_margin = 0.8. Re-derive monthly; alert if any tier price < floor.
- Prompt-cache hit-rate becomes a first-class metric (`warden_prompt_cache_hit_ratio`); every 10-point improvement on SOVA/staff workloads cuts agent COGS ≈ 9%.

### FM-4 — Resource efficiency on the 4 GB node (defer MILP)
- **Memory-limit audit**: every service in `docker-compose.yml` gets an explicit `mem_limit`; sum ≤ 3.4 GB (leave 600 MB for kernel/page cache). Today limits are partial — one leaky container can OOM-evict the gateway.
- **Latency SLO model**: treat warden as M/G/1 with service time S (P50≈2ms filter path). P99 wait ≈ (λ·E[S²])/(2(1−ρ)) · scaling; solve for the max sustainable λ at P99 < 50 ms (the SLA). Publish the derived capacity ceiling as a Prometheus recording rule; alert at ρ > 0.7.
- Consolidation candidates (measure, then act): Jaeger+Loki cohabitation, Grafana render pressure, MinIO idle overhead.
- **MILP (archived for ≥2 nodes)**: min Σ_k c_k·y_k s.t. Σ_k x_jk = 1 ∀j; Σ_j w_j·x_jk ≤ C_k·y_k ∀k; x,y ∈ {0,1}. Correct formulation, adopt only when a second Hetzner node exists — then via a proper solver dependency, not `/tmp` scripts.

### FM-5 — Reliability = revenue protection
The Pro SLA (99.9%) allows **43 min/mo** of downtime; the 2026-07-15 tunnel incident (rogue laptop connector round-robining prod traffic) consumed most of one month's budget and was invisible to the product's own monitors.
- Run `cloudflared` as **two replicas on the VPS** (compose `deploy.replicas: 2` or a second service) so one connector crash isn't total; document that *only* VPS machines may hold the tunnel token (incident memory: a dev-box connector on a prod tunnel is an intermittent-502 trap).
- Error-budget accounting: monthly availability report per hostname from `probe_results` (TimescaleDB already stores it); burn-rate alert at 2× (Google SRE multiwindow).
- SLA credits are a *liability*: credit exposure = MRR × credit% × P(breach). Keeping P(breach) < 1% at 99.9% requires the two-connector fix plus the FM-0 monitors — cheap insurance against a real dollar liability.

### FM-6 — Distribution instrumentation (growth accounting)
The billing machinery exceeds the measurement machinery. Instrument before spending on acquisition:
- **Funnel events**: signup → first `/filter` call → trial start → trial→paid conversion → expansion (add-on). Store as metadata-only events (GDPR rule holds).
- **Viral coefficient** K = invites_sent × acceptance_rate × activation_rate from `referral.py` counters (already in Redis; today nothing reads them analytically). K > 0.5 justifies raising the referral bonus; K < 0.2 means the loop is dead weight.
- **Unit-economics dashboard** (extends BI module): ARPA, gross margin per tenant (FM-2 data), logo churn, NRR, LTV = ARPA × margin ÷ churn, LTV:CAC once acquisition spend exists. Payback target < 6 months at SMB price points.
- Pricing-elasticity experiment: one variable at a time (e.g., Individual $5→$7) with cohort tracking — the tier table is already config-driven.

---

## 4. Sequencing & Governance

| Order | Item | Effort | Depends on |
|---|---|---|---|
| 1 | FM-0 quick wins | ≤1 day | — |
| 2 | FM-5 reliability | 1–2 days | FM-0 monitors |
| 3 | FM-2 cost rating | 2–3 days | FM-0 `cached_tokens` |
| 4 | FM-1 wallet unification | 2–3 days | — |
| 5 | FM-3 margin routing | 2 days | FM-2 |
| 6 | FM-4 efficiency audit | 1–2 days | — |
| 7 | FM-6 growth accounting | 2–3 days | FM-2 |

Rules of engagement (inherited): full test suite + full-tree mypy before every merge; one merged phase = one push to main (autodeploy); shared files (`economics.py` pricing, GSAM schema, preflight) follow the conflict-table coordination rule; **FM never weakens a security gate** — margin logic is additive after fail-closed checks, exactly like the GSAM quarantine gate.

Track C owns: billing math, cost rating, margin routing, growth instrumentation, capacity/SLO math. It does **not** own detection math (Track B) or authn/SSRF (Track A).
