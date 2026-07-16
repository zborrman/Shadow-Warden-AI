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

## Track C — FinOps / Monetization (from `docs/fintech-development-plan.md`)

| ID | Item | Status | PR |
|---|---|---|---|
| FM-0 | Quick wins: SARIF export, `cached_tokens` GSAM column, uptime monitors ×4 hostnames | 🟡 2/3 — SARIF + `cached_tokens` merged (4ab0e15f); uptime monitors folded into FM-5 | 4ab0e15f |
| FM-1 | Unified wallet availability math (prepaid+trial+bonus−hold, one `available_usd()`) | ✅ core shipped — `warden/finops/wallet.py`: `available_usd()` single formula (components floored, holds subtracted, micro-precision), `WalletComponents`, `spend_breakdown()` (free money first: bonus→trial→prepaid), `resolve_wallet()`/`resolve_available_usd()` resilient adapters composing prepaid+hold from `sac.preflight` and trial/bonus grants (Redis `finops:grant:*`, default 0). No schema change to the SAC ledger. 15 tests | _pending_ |
| FM-2 | Real-time cost rating — CH `billing_session_ledger` SummingMergeTree + MV, prompt-cache discount | ✅ core shipped — `warden/finops/rating.py` single price-book (90% cache-read discount, `rate_usage`/`blended_input_rate`); `compute_cost_usd` cache-aware; `billing_session_ledger` SummingMergeTree + MV (units-only, rate at read) applied fail-open in `ensure_schema` + init.sql | _pending_ |
| FM-3 | Margin-aware model routing + per-tier pricing floor (additive after security gates) | ✅ core shipped — `warden/finops/margin.py`: `margin_fraction`, `pricing_floor_usd`, `evaluate_margin` (proceed/throttle/block), `pick_model_within_margin` (most-capable model clearing the floor, never routes below the allowed set), `tier_revenue_per_request` (price÷quota from billing, resilient→None=no floor). Pure + advisory, additive after fail-closed gates. 23 tests | _pending_ |
| FM-4 | 4 GB-node efficiency: mem-limit audit, M/G/1 capacity ceiling; MILP archived until ≥2 nodes | ✅ core shipped — `warden/finops/capacity.py`: Pollaczek–Khinchine M/G/1 (`mg1_wait_seconds`/`mg1_response_seconds`/`utilization`), capacity ceilings (`max_rps_for_utilization` ρ-cap + `max_rps_for_latency` closed-form solve + binding `capacity_ceiling`), `audit_mem_limits` (over-commit vs schedulable RAM) + resilient `parse_compose_mem_limits`. MILP left archived (single node). 17 tests | _pending_ |
| FM-5 | Reliability = revenue: 2× cloudflared replicas, error-budget burn-rate alerts | 🟡 in-flight — pure error-budget + multiwindow burn-rate math (`warden/reliability/`) + `GET /monitors/error-budget` landed; cloudflared replicas + monitor creation + Slack alert routing remain (operational) | — |
| FM-6 | Growth accounting: funnel events, viral coefficient K, LTV/NRR dashboard | ✅ core shipped — `warden/finops/growth.py`: `build_funnel` (per-stage + top-of-funnel conversion, worst-leak detection), `viral_coefficient` (factored K = invites/user × acceptance × activation, verdict self_sustaining/healthy/weak/dead + amplification 1/(1−K)), unit economics (`arpa`, `logo_churn`, `net_revenue_retention`, `ltv`, `ltv_cac_ratio`, `payback_months`, `unit_economics` bundle with SMB healthy gate LTV:CAC≥3 & payback≤6mo), `resolve_referral_k` resilient adapter reading `billing/referral.py` redemption counters. Pure + observational, no storage added. 34 tests | _pending_ |

Track C shared-file notes: `staff/economics.py` pricing dict (C-shared with Track B GSAM), GSAM schema (`gsam/schema.py` + `docker/clickhouse/init.sql` must stay in sync), `sac/preflight.py` wallet. FM never weakens a security gate — margin logic is additive after fail-closed checks.

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
