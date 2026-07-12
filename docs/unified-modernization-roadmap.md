# Unified Modernization Roadmap — reconciling the two parallel plans

**Date:** 2026-07-12 · **Purpose:** merge the two concurrently-running modernization efforts into one registry so they stop colliding on shared files and on "Phase N" numbering.

## Why this doc exists

Two plans have been running in parallel, each numbering its work "Phase 1…7/8". In commit messages and reviews "Phase 5" has meant two different things. They also touch overlapping files (`causal_arbiter.py`, `staff_dispatch`, `net_guard`, the data layer). This document is the single source of truth: two **named tracks**, one status table, explicit conflict-ownership.

| Track | Source doc | Scope | Prefix |
|---|---|---|---|
| **A — Security Remediation** | `MODERNIZATION_PLAN.md` | Audit findings: auth, SSRF, IDOR, GDPR, invariants, DB-layer, CI hardening | `SR-*` |
| **B — Deep-Eng / Math** | `docs/modernization-plan-v8.md` | TDA, MAESTRO/reputation, Causal calibration, GSAM, embeddings, data-layer, runtime isolation | `DE-*` |

> **Rule:** commit messages and PR titles carry the track prefix (`SR-1.4`, `DE-5`), never a bare "Phase N".

---

## Track A — Security Remediation (from `MODERNIZATION_PLAN.md`)

| ID | Item | Status | PR |
|---|---|---|---|
| SR-0 | CRITICAL marketplace SQL | ✅ merged | #148 |
| SR-1.2/1.3 | Router auth (staff/secrets/red-team/doc-intel) + admin fail-closed | ✅ merged | #148 |
| SR-1.1 | Tenant tier from billing plan, not `X-Tenant-Tier` header | ✅ merged | #149 |
| SR-1.4 | `/gdpr` router auth (unauthenticated erasure closed) | 🟡 open | #154 |
| SR-1.4b | GDPR IDOR tenant-ownership match (`purge_tenant`/`audit`) | ⬜ deferred — **policy call** (operator-admin vs self-service) | — |
| SR-2 | 8 SSRF sinks through `net_guard` + no-redirect | ✅ merged | #148 |
| SR-2.3 | net_guard validated-IP pinning (TOCTOU/DNS-rebind) | ⬜ deferred — needs TLS-SNI-safe transport design; LOW | — |
| SR-2.4 | CORS `/ext/*` allowlist | ⬜ remaining | — |
| SR-3 | Correctness: Semantic params, STIX race, ZSET, OpenAI URL, stream-unmask, priv-esc, blocking-I/O | ✅ merged | #148 |
| SR-3.8 | Remove dead `_collect_or_emit` | 🟡 open | #154 |
| SR-4 | Invariants: SAR pre-screen, A2A boundary, GDPR-logs, refund key, Settings secrets | ✅ merged | #148 |
| SR-5 | **DB-layer consolidation** (62 `_conn`/DDL copies → one layer) | ⬜ remaining — **see conflict C2 (merge with DE-6)** |
| SR-6 | Fail-open observability (`record_failopen`, `warden_failopen_total`) | ⬜ remaining |
| SR-7 | CI/supply-chain hardening (bandit/semgrep/gitleaks/SBOM, coverage→85%) | ⬜ remaining |
| SR-8 | Doc-vs-code reconciliation (JIT lease now exists via SAC/GSAM — verify) | ⬜ remaining |

## Track B — Deep-Eng / Math (from `docs/modernization-plan-v8.md`)

| ID | Item | Status | PR |
|---|---|---|---|
| DE-1 | GSAM downstream completion | ✅ merged | #150 (+ GSAM chain #138–#143 open) |
| DE-2 | Two-phase preflight billing (reserve→commit) | ✅ merged | #151 |
| DE-3 | Embedding + hyperbolic model upgrade (TDA H1 slice done) | 🟡 in-flight | #152 (slice) |
| DE-4 | Bayesian MAESTRO & reputation (collusion slice done) | 🟡 in-flight | #153 (slice) |
| DE-5 | Causal Arbiter online Robbins-Monro calibration | ✅ merged | (c946b1f1) |
| DE-6 | **Data-layer consolidation** + turn ClickHouse on (category 11) | ⬜ remaining — **merge with SR-5** |
| DE-7 | Runtime isolation & key hygiene (categories 3,7) + §6 security S1–S5 | ⬜ remaining — **overlaps SR-4.4/SR-7** |

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

## Proposed ownership split (to stop collisions)

- **Track A owns:** authn/authz, SSRF wiring, IDOR/GDPR, request-path invariants, CI/supply-chain hardening (SR-2.4, SR-6, SR-7, SR-8, SR-1.4b).
- **Track B owns:** all ML/detection math (TDA, MAESTRO, Causal, embeddings), GSAM, storage/data-layer (incl. the merged SR-5+DE-6), runtime isolation math.
- **Shared, coordinate before touching:** the five files in the conflict table. Rule: whoever edits one pings the other track in the PR description and runs the other track's relevant tests.

## Immediate actions

1. Adopt the `SR-*` / `DE-*` prefixes; retire bare "Phase N" in messages.
2. Merge SR-5 and DE-6 into one data-layer workstream (Track B).
3. Land the open SR PR (#154) and the GSAM chain (#138–#143) before starting SR-5/DE-6 so the base is stable.
4. Add the C1 regression test (calibration + drift-gate coexist) as the first shared-file guardrail.
