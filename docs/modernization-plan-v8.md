# Deep Engineering & Mathematical Modernization Plan (v8 track)

Date: 2026-07-10 · Basis: full-codebase exploration during the SAC (FE-52) build.
Companion docs: `docs/sac-architecture.md`, `docs/security-model.md`, `ROADMAP.md`.

---

## 1. Development-level assessment (1–100)

Scores reflect *verified code state*, not roadmap claims. Key calibration events from
this session: GSAM v7.7 downstream source was never committed (only ingest survived);
the agent-URL SSRF gap existed until FE-52 closed it.

| # | Category | Score | Evidence & gap |
|---|----------|-------|----------------|
| 1 | Core filter pipeline (9-layer: topology → obfuscation → redaction → semantic → brain → causal → ERS) | **88** | Mature, contract-tested (52 invariant tests), <2ms topology stage, fail-open discipline. Gap: thresholds are static env vars, no calibration loop. |
| 2 | ML & mathematical models (TDA Betti, Poincaré blend, Bayesian DAG) | **78** | Real math, pure-numpy, do-calculus with backdoor correction, CPT drift gate. Gaps: MiniLM (2021-era) embedder; fixed 70/30 hyperbolic blend; β₀/β₁ only (no persistence); no online learning anywhere. |
| 3 | Agent runtime & safety (SOVA, MasterAgent, staff, SAC guard) | **82** | Boundaries+velocity+A2A HMAC+approval gates; SAC guard now screens dispatch (SSRF fail-CLOSED) and produces GSAM telemetry. Gaps: SOVA/Master bypass BoundaryRegistry (staff-only); no OS-level isolation; model routing is static per-level. |
| 4 | GSAM / observability | **55** | Ingest (collector/spool/ClickHouse) + first producer (SAC) + JIT lease rebuilt. Missing: rollup sink → `gsam_agent_stats`, EWMA drift math, quarantine, read API, semantic model — DDL exists, code does not. |
| 5 | Billing & monetization (x402, audit chain, Lemon Squeezy, add-ons) | **80** | Replay-protected x402, SHA-256 audit chain w/ EVM anchoring, metered billing, feature gates. Gaps: no wallet/two-phase reserve→commit; immediate deduction only; overage math simplistic. |
| 6 | Marketplace & agent protocols (ACP/AP2/MCP/A2A, clearing, escrow) | **84** | 38-module marketplace, DID identity, ClearingEngine with Decimal take-rate, SPT vault, MAESTRO collusion detection. Gaps: MAESTRO uses raw Pearson; reputation PageRank has no uncertainty. |
| 7 | Crypto & PQC (hybrid Ed25519+ML-DSA, KEM, CTP proofs) | **85** | XOR-then-HKDF hybrid KEM, fail-open liboqs, STIX hash chains. Gap: `resolve_key` adoption incomplete (e.g. `staff/boundaries.py` refund intent still uses raw env fallback). |
| 8 | Compliance & GDPR (DPIA, SOC2, ISO27001, posture service) | **87** | 19-control posture service, 93-control ISO mapping, content-never-logged enforced down to GSAM schema (`FORBIDDEN_FIELD_HINTS`). Gap: posture checks are boolean, no weighted risk scoring. |
| 9 | Frontend (site 40 pages, SOC dashboard, portal, Streamlit ×22) | **75** | Broad surface, DS-01 design system. Gaps: residual mock/placeholder data paths; breadth > depth; localStorage-backed community SPA. |
| 10 | Testing & CI | **83** | ~4 900 tests, 79% gate (~81% actual), mutation testing, contract tests, warden-scan gate, ratchets (fail-open floor 201, config 615). Gap: adversarial suite informational-only; no property-based testing of the math modules. |
| 11 | Data layer (SQLite ×20+, Turso, Redis, ClickHouse) | **65** | Turso adapter clean, but `/tmp/*.db` defaults in prod paths, per-module DB sprawl, ClickHouse defined-but-idle, no unified migration story outside alembic islands. |
| 12 | Infra & deploy (VPS, compose, Caddy, CF WAF, Grafana/Jaeger) | **70** | Full observability stack, autodeploy, SLO alerts. Gaps: single-node, no HA/backup automation, 30s stop-grace is the only resilience mechanism. |
| 13 | Docs & knowledge base | **90** | CLAUDE.md/ROADMAP/security-model/DPIA/SLA dense and current; memory discipline strong. |

**Weighted overall: ≈ 78/100.** The three drag anchors: GSAM downstream (55), data layer (65), infra (70).

---

## 2. Modernization plan — 7 phases

Ordering rule: each phase feeds data or primitives to the next. Phases 1–2 finish
committed-but-missing v7.7 scope; 3–5 are the mathematical upgrades; 6–7 harden the base.

### Phase 1 — GSAM downstream completion ✅ DONE (2026-07-10)

Files shipped: `warden/gsam/drift.py` (pure math), `warden/gsam/rollup.py` (sink + reads),
`warden/gsam/quarantine.py` (Redis+in-proc gate), extended `warden/gsam/api.py` (3 read endpoints),
`gsam_agent_stats` semantic model in `engine.py`, sink registered in `main.py` lifespan, additive
quarantine gate in `staff_dispatch`. 35 new tests (drift/rollup/quarantine-gate), 173 regression
green, ruff+mypy clean. Category 4: 55 → ~80.

1. **Rollup sink** — register via existing `collector.register_sink()`; hourly upsert into
   `gsam_agent_stats` (DDL exists). Pure function core: `fold(rows) -> dict[agent_id, StatDelta]`.
2. **Drift index (EWMA over action-frequency vectors).** Per agent, maintain frequency
   vector `f_t` over `payload_kind` labels in bucket `t`, baseline `μ` in
   `gsam_drift_baselines.freq_vector_json`:

   ```
   D_t = λ · ½‖f_t − μ_{t−1}‖₁ + (1 − λ) · D_{t−1},   λ = settings.gsam_drift_lambda (0.2)
   μ_t = (1 − λ) · μ_{t−1} + λ · f_t   — updated only when D_t < quarantine threshold
                                          (poisoning-resistant, mirrors the CPT 25% gate)
   ```
   ½·L1 on normalized vectors = total-variation distance ∈ [0,1] — directly comparable to
   `gsam_drift_quarantine_threshold` (0.85).
3. **Anti-inflation co-occurrence rule.** An agent cannot inflate `trust_score` by
   self-dealing: trust gains require observations co-occurring with ≥2 distinct
   counterpart `contract_id`s in the window; else the gain is clamped to 0.
4. **Quarantine** — `D_t ≥ 0.85` ⇒ insert `gsam_quarantine_log`, set Redis flag
   `gsam:quarantine:{agent_id}` (TTL `gsam_quarantine_ttl_s`); **additive** gate in
   `staff_dispatch`/marketplace (never weakens STAFF-01/02).
5. **Read API** — `GET /gsam/heatmap`, `GET /gsam/agents/{id}/stats`,
   `GET /gsam/compliance/score` reading the **rollup, never ClickHouse**; register the
   `gsam_agent_stats` semantic-layer model (built-in id, rollup-backed).

Effort: ~4 PRs. Testable without ClickHouse (SQLite rollup path). Lifts category 4: 55 → ~80.

### Phase 2 — Two-phase preflight billing (reserve → commit) ✅ DONE (2026-07-10)

Files shipped: `warden/sac/preflight.py` (integer micro-USD wallet ledger: `deposit`,
`reserve`→hold_id, `commit`(actual, clamped to balance, releases remainder), `release`;
`InsufficientFundsError`/`HoldError`), `warden/api/wallet.py` (`/wallet` REST — GET + deposit
[admin]/reserve/commit/release), config flags `sac_preflight_enabled` (default OFF)
`/sac_preflight_estimate_usd`/`sac_wallet_db_path`, wired into `StaffAgentRunner.run()`
(`warden/staff/agents/base.py` — `_preflight_reserve`/`_preflight_settle`, both fail-open,
only an explicit `InsufficientFundsError` blocks a run) at both success-return points. Every
reserve/commit/release appended to `billing.audit_chain`. 17 new tests, ruff+mypy clean.
Known follow-up: a hold is not released on an unhandled mid-loop exception (relies on the
default-off gate + manual/TTL release) — acceptable for this slice, flagged for hardening.
**Security fix during review:** `commit()`/`release()` gained an `expected_tenant_id` param
(checked in `_resolve_hold`, IDOR-safe — a tenant mismatch reads identically to "not found")
after review caught that `/wallet/commit|release` let any authenticated tenant settle/release
*any* tenant's hold by guessing/observing its hold_id; the API layer now always passes
`auth.tenant_id`. 3 more tests added for this. Category 5: 80 → ~86 (full 88 needs the
mid-loop exception-safety follow-up).

### Phase 3 — Embedding + hyperbolic model upgrade (category 2, the biggest math lever)

- **Replace MiniLM** with a 2025-class small instruction embedder (e.g. a distilled
  `gte`/`bge`-class model, still CPU-ONNX, `@lru_cache` singleton unchanged). Re-embed
  `_brain_guard` corpus offline; keep MiniLM behind a flag for A/B.
- **Learn the hyperbolic blend** instead of hard-coding 70/30: fit `α` on labeled
  jailbreak/benign pairs by maximizing AUC of `α·cos + (1−α)·(1−d_H/κ)`; store `α` as a
  calibrated constant + per-tenant override. Pure-numpy logistic fit; no training infra.
- **Persistence homology H₁ lifetimes** in `topology_guard` (add birth–death of the longest
  1-cycle, not just β₁ count) — richer separation of paraphrase-obfuscated attacks. Ripser
  already optional; gate behind `TDA_PERSISTENCE=true`.
- **Conformal thresholds:** replace static `SEMANTIC_THRESHOLD` with a split-conformal band
  giving a bounded false-positive rate `ε`; recalibrate nightly from labeled logs with the
  same 25%-shift drift gate. Lifts category 2: 78 → ~88, category 1: 88 → ~92.

### Phase 4 — Bayesian upgrade of MAESTRO & reputation (category 6)

- **MAESTRO collusion**: replace raw Pearson-≥0.80 with a Bayesian correlation test
  (posterior P(ρ > ρ₀ | data) with a Jeffreys prior) so 3-sample flags carry an explicit
  credible interval rather than a point estimate — cuts false collusion flags on thin data.
- **Reputation TrustRank**: propagate uncertainty — Beta(α,β) reputation per agent, PageRank
  over expected values, flag when the 5th percentile (not the mean) crosses the trust floor.
- Feed both from the Phase-1 GSAM rollup (single source of truth). Lifts category 6: 84 → ~90.

### Phase 5 — Causal Arbiter online calibration (categories 1–2) ✅ DONE (2026-07-12)

Shipped: `causal_arbiter.online_update()` — bounded Robbins–Monro CPT nudge (`θ ← θ + η_t(y−θ)`,
`η_t = 1/(1+n)`) on the ContentRisk cells, step clamped to ±25% (poisoning gate) with the
`obfusc_pos > obfusc_neg` ordering invariant preserved; per-cell sample counters on `_CPT`.
Wired into `/filter` (gray-zone only, off the hot path via `background_tasks`, fail-open) using
the final verdict as the supervised label. `reliability_curve()` + `online_state()` back the new
`GET /xai/calibration` reliability-diagram endpoint. 21 property-style tests (bounds, convergence
to empirical mean, drift clamp, ordering, fail-open, bin correctness). ruff + mypy clean.

- The CPT tables in `causal_arbiter.py` are static + gated at 25% drift. Add a **bounded
  online update**: after each labeled decision, nudge the relevant CPT cell by a Robbins–Monro
  step `θ ← θ + η_t(y − θ)`, `η_t = 1/(1+n)`, still clamped by the 25%-per-calibration gate.
  Turns the DAG from static-expert into slowly-learned while keeping the poisoning guarantee.
- Expose `P(HIGH_RISK|evidence)` calibration curve on the XAI dashboard (reliability diagram).
  Lifts category 1: 88 → ~93.

### Phase 6 — Data-layer consolidation (category 11, the quiet risk)

**Slice 1 ✅ DONE (2026-07-12):** central `WARDEN_DATA_DIR` primitive — `warden/config.py`
`data_dir()` / `data_path(filename, override_env)`. One env var relocates every default DB/spool
off ephemeral `/tmp` onto a persisted volume; per-module `X_DB_PATH` overrides still win;
backward-compatible (defaults to `/tmp`). All 17 `config.py` path defaults routed through it plus
the staff cluster (a2a, economics, bdr, compliance_kyc, growth, support) as the module-wiring
proof. 10 property tests (override precedence, relocation, dir creation, legacy parity). ruff +
mypy clean.

**Slice 2 ✅ DONE (2026-07-12):** completed the direct-call-site sweep — all remaining
`os.getenv("*_DB_PATH", "/tmp/…")` defaults in real module code routed onto `data_path`
(79 files auto-swept via verified regex + 2 multi-line `os.getenv` in communities/charter+registry
+ 1 bare literal in soc2_collector). Clusters: marketplace (~35), communities/SEP (~14),
financial, secrets_gov, protocols/acp, m2m_store, business_intelligence, compliance, voice, push,
sovereign, vendor_gov, kya, tokenomics, security, semantic_layer, webhooks, agent/api. Zero
`/tmp/warden*` literals remain outside tests + Streamlit display pages. ruff + mypy clean;
966 tests green across affected subsystems (1 pre-existing unrelated failure).

**Slice 3 ✅ DONE (2026-07-12):** nightly encrypted DB backup. `warden/backup/service.py` —
single source of truth: discovers every `warden_*.db` under `data_dir()`, SQLite online-backup API
→ Fernet (`VAULT_MASTER_KEY`, **fail-CLOSED**) → `SNAPSHOT_DIR/<ts>/<name>.db.enc`, rotation
(`SNAPSHOT_KEEP`, default 7), atomic restore, optional S3/MinIO ship (**fail-OPEN**). Wired as
`sova_nightly_backup` ARQ cron (03:30 UTC) in `warden/workers/settings.py`;
`scripts/db_snapshot.py` refactored to a thin wrapper (preserves the autonomous-loop Step-1b CLI).
8 tests (round-trip integrity, ciphertext-not-plaintext, fail-closed-no-leak, empty no-op,
rotation, ship fail-open). ruff + mypy clean.

**Slice 4 ✅ DONE (2026-07-13):** DDL registry + ClickHouse observability.

*Migrations unification* — `warden/db/ddl_registry.py`. **Deliberately not** folded into the Alembic
tree: that tree targets the PostgreSQL app DB (`DATABASE_URL`), whereas the ~98 module DBs are
independent, optional, created-on-demand SQLite files; forcing them through a global migration run
would couple optional subsystems to it. The registry gives the same wins without that coupling:
`register(db_key, module, ddl)` at import time + `ensure_schema(conn, db_key, path)` that is **lazy**
(applied on first connection, so workers/tests that never run the FastAPI lifespan still get their
tables — a startup-only `apply_all()` would silently break them), **memoized** (DDL-once per DB per
process instead of on every connection), **persistent** (`_warden_ddl_applied` tracks module+checksum
across restarts), **drift-detecting** (changed checksum → re-apply), and **fail-safe** (tracking
failure ⇒ execute DDL directly; never lose tables). Staff cluster (`a2a`, `economics`) converted as
the proof, with per-DB keys so schemas don't cross-leak into each other's files. 11 tests.

*ClickHouse for GSAM* — already fully wired in `docker-compose.yml` (service + `init.sql` +
`GSAM_CLICKHOUSE_ENABLED=true` default, deliberately outside warden's `depends_on` so the gateway
boots without it). The real gap was that the collector is **fail-OPEN** toward ClickHouse — it spools
to NDJSON and replays — so a broken OLAP store fails *silently*. `collector.stats()` even documented
itself as "Health snapshot for GET /gsam/health", but **that route was never added**. Added
`GET /gsam/health` exposing `clickhouse_enabled/reachable`, `spool_bytes`, queue depth/dropped, plus a
`degraded` flag (enabled-but-unreachable, or spool backlog, or drops) — the condition worth alerting
on. 6 tests.

**Follow-on ratchet:** convert the remaining ~96 modules' inline `CREATE TABLE IF NOT EXISTS` onto
`ddl_registry` (mechanical, cluster-by-cluster, same style as the `data_path` sweep).

- **Kill `/tmp/*.db` prod defaults**: route every module DB through `warden/db/turso.py` or a
  single `DATA_DIR` (persisted volume) — a config sweep like the T1–T12 Settings ratchet.
- **Unify migrations**: one alembic tree (or Turso DDL registry) instead of per-module
  `executescript`. Add a `scripts/db_snapshot.py`-style nightly encrypted backup for all DBs.
- **Turn ClickHouse on** for GSAM in prod (Phase 1 makes it worthwhile). Lifts category 11:
  65 → ~80, category 12 partially (backup automation): 70 → ~76.

### Phase 7 — Runtime isolation & key hygiene (categories 3, 7)

**Slice 1 ✅ DONE (2026-07-13) — key hygiene.** The plan's "`staff/boundaries.py` refund intent"
item was already on `resolve_key` (commit 34e54cd6), but the sweep found a worse, unlisted hole:

- **`warden/agentic/mandate.py` accepted UNSIGNED payment mandates.** `validate_mandate()` verified
  the HMAC only `if _MANDATE_SECRET:`, and `_MANDATE_SECRET` was read from env *at import* with a
  `""` default. Any deployment that never set `MANDATE_SECRET` therefore skipped signature
  verification entirely — a caller could spend against an agent's budget with no signature. Now:
  key via `resolve_key("MANDATE_SECRET", purpose="agentic_mandate")` (resolved per-call, never at
  import), verification **unconditional**, and an unresolvable key **DENIES** instead of waving the
  payment through. Explicit `MANDATE_SECRET` is still used verbatim, so existing signatures keep
  verifying. New `sign_mandate()` export keeps signer/validator canonical forms from drifting.
- **`warden/api/bot_entity.py`** minted a *random ephemeral* JWT secret when `BOT_JWT_SECRET` was
  unset (tokens silently died each restart; prod never failed closed) → now `resolve_key`, with the
  operator override honoured verbatim so existing tokens still verify.
- **CI gate:** `warden/tests/test_no_new_raw_signing_key.py` — baseline ratchet (8, was 10) over
  raw-env reads of signing-key-shaped secrets. A ratchet, not a ban, because provider-issued webhook
  secrets (Stripe/Slack/Lemon) genuinely cannot be derived. 7 regression tests pin the bypass shut.

**S2 ✅ DONE (2026-07-16) — `resolve_key` migration finished + grep gate confirmed.** Audit of the
§6c #3 "incomplete `resolve_key` adoption" risk: the two stated items were already shipped in Slice 1
(refund-intent on `resolve_key`; the ratchet grep gate). A sweep of the remaining 9 baseline reads
confirmed **no forgeable fail-open signing path survives** — each is either fail-CLOSED by an explicit
empty-secret check (`saml_provider` raises/returns None; `auth/router._secret()` raises) or a
provider-issued webhook/cloud credential that cannot be derived (Slack, Lemon Squeezy, AWS). One
genuine reduction: `saml_provider._JWT_SECRET` was a **dead import-time snapshot** of the signing
secret (never referenced — both call sites re-read fresh) → removed, dropping the ratchet 9 → 8.
key-mgmt 76 → 86 (with S1). No forgeable-key path remains open.

**Slice 2 ✅ DONE (2026-07-13) — BoundaryRegistry extended to SOVA/MasterAgent.**
`warden/agent/gate.py` — `agentic_gate()` applies the same three checks Digital Staff get
(boundary fail-CLOSED → velocity → GSAM quarantine, additive) to every agentic tool call, and
`traced_dispatch` now runs it for all non-staff callers.

The sweep found a **privilege escalation**: `MasterAgent` bypassed `traced_dispatch` entirely
(`master.py` called `TOOL_HANDLERS[name]` directly), so its sub-agents had **no SAC guard / SSRF
screen, no boundary, no velocity limit, no quarantine and no OTel span**. Worse, `_AGENT_TOOLS` only
filtered which tools were *offered* to the model — a sub-agent that named a tool outside its own
subset still executed it, i.e. least privilege was advertised but never enforced. MasterAgent now
dispatches through `traced_dispatch` under a namespaced id (`master:<sub_agent>`), and its boundary
is seeded **from `_AGENT_TOOLS` itself**, so the subset is enforced for real.

Boundaries are seeded from the authoritative tables (SOVA = every `TOOL_HANDLERS` key; each
sub-agent = its `_AGENT_TOOLS` list) by an idempotent `ensure_agentic_boundaries()`. `staff_dispatch`
passes `already_gated=True` so its calls are not double-counted by the velocity guard (which would
trip a false loop alert on a single legitimate call). STAFF-01/02 are untouched — the staff path
still calls `check_and_dispatch` + `record_and_check` itself. New `AgentRole` members are additive.
11 tests.

**Slice 3 ✅ DONE (2026-07-14) — BrowserSandbox process isolation.** `--no-sandbox` (which disables
Chromium's renderer sandbox — the biggest isolation gap for the browser tool) is now conditional:
`_browser_launch_args()` drops it when `BROWSER_ENABLE_SANDBOX=true`, restoring the real sandbox once
the runtime provides it (non-root user + Chromium seccomp profile via `security_opt`). Default false =
unchanged legacy behaviour, so trusted internal visual-patrol keeps working — opt-in hardening, not a
forced change. Added always-on defence-in-depth flags (disable background-networking/sync/media-router/
extensions). Operator enablement in `docs/browser-sandbox-hardening.md` (points at the canonical upstream
Chromium seccomp profile rather than a hand-rolled one; `--cap-add=SYS_ADMIN` explicitly rejected as
worse). Flag logic unit-tested (`test_browser_sandbox_args.py`, 5 tests); end-to-end launch under the
profile must be validated on a real Playwright host (CI image has no Chromium). **Phase 7 (DE-7) complete.**

This was the last named engineering item across both modernization plans.

- **Extend BoundaryRegistry to SOVA/MasterAgent**, not just staff — every agentic tool call
  through one boundary + velocity + GSAM-quarantine gate. (SAC guard is already the shared
  screen point; add the boundary check beside it.)
- **Finish `resolve_key` adoption**: migrate the last raw-env HMAC fallbacks (notably
  `staff/boundaries.py` refund intent) to `resolve_key(purpose=…)` — closes the one remaining
  forgeable-key path. Add a CI grep gate forbidding new `os.getenv(...HMAC...)` fallbacks.
- **Optional process isolation** for the browser tool: run `BrowserSandbox` under a seccomp/
  restricted-user Docker sidecar (drop `--no-sandbox`) — the realistic, testable analogue of
  the SAC spec's Kata isolation. Lifts category 3: 82 → ~90, category 7: 85 → ~92.

---

## 3. Sequenced roadmap & projected scores

| Phase | Theme | Lifts | New overall |
|-------|-------|-------|-------------|
| 1 | GSAM downstream | cat 4: 55→80 | ~81 |
| 2 | Two-phase billing | cat 5: 80→88 | ~82 |
| 3 | Embedding/hyperbolic/conformal | cat 1,2 | ~85 |
| 4 | Bayesian MAESTRO/reputation | cat 6 | ~86 |
| 5 | Causal online calibration | cat 1,2 | ~87 |
| 6 | Data-layer consolidation | cat 11,12 | ~89 |
| 7 | Isolation + key hygiene | cat 3,7 | ~91 |

Target after the 7-phase track: **≈ 91/100**, with no category below 76.

## 4. Invariants every phase must preserve

GDPR content-never-logged (down to GSAM `FORBIDDEN_FIELD_HINTS`); fail-open detection / fail-CLOSED
credentials split; STAFF-01…05; the CPT 25%-drift poisoning gate; all 32 Playwright assertions;
`<link rel="agent-protocol">`; clearing.py Decimal math; x402 fail-open. Each phase ships pure-function
math with property-based tests, then wiring — mirroring how SAC (FE-52) and GSAM v7.7 landed.

## 5. Verification pattern (per phase)

Pure math modules get `hypothesis` property tests (e.g. drift ∈ [0,1]; EWMA monotonic under
constant input; conformal FPR ≤ ε on held-out). Wiring gets fail-open/fail-closed unit tests +
one end-to-end run via the `run-warden` skill. ruff + mypy clean; coverage ratchet respected;
adversarial suite promoted from informational to gating for the touched detector.

---

## 6. Cybersecurity deep-dive (1–100)

Security splits into two faces that score differently: **product security** (the gateway's
core job of defending *others'* AI) and **self-security** (Warden defending *itself*).

### 6a. Product security — defending the customer's AI

| Sub-area | Score | Evidence & gap |
|---|---|---|
| Prompt-injection / jailbreak defense | **86** | 9-layer TDA+ML+causal, 52 contract invariants. Gap: `/filter` pre-screen fail-OPEN on timeout = a bypass window under load. |
| Secret / PII redaction & masking | **88** | 15 regex + Shannon entropy + Fernet vault + HMAC reverse map; content-never-logged to GSAM schema level. |
| Obfuscation / evasion resistance | **82** | depth-3 recursive decode, homoglyphs, adversarial-suffix stripping. Gap: adversarial suite informational-only. |
| Rate-limit / abuse / shadow-ban | **80** | ERS sliding window, `secrets.choice` gaslight pool, CF WAF. |
| Phishing / social-eng / shadow-AI discovery | **80** | PhishGuard + SE-Arbiter + 18-provider shadow-AI probe. |

**Product security ≈ 84.**

### 6b. Self-security — Warden's own hygiene

| Sub-area | Score | Evidence & gap |
|---|---|---|
| AuthN / AuthZ | **84** | Fail-closed startup, bcrypt, constant-time compare, multi-tenant keys, HttpOnly JWT. |
| Key & secret management | **76** | `resolve_key` fail-closed **but adoption incomplete** (e.g. `staff/boundaries.py` refund intent raw-env fallback); secret-bearing SQLite DBs default to `/tmp`. |
| SSRF / egress control | **80** | `net_guard` fail-closed, now on agent dispatch via SAC. Gap: not universal; browser egress unscreened past dispatch. |
| Sandbox / code-exec isolation | **62** | `BrowserSandbox` runs `--no-sandbox`; agent tools in-process; **no OS boundary**. Lowest point. |
| Supply-chain security | **68** | OSV CVE scan exists but **informational**; no SBOM; no secret-scanning/SAST gate. |
| Cryptography & PQC | **85** | Hybrid Ed25519+ML-DSA, XOR-then-HKDF KEM, liboqs fail-open. |
| Tamper-evidence & audit | **88** | STIX + billing SHA-256 chains + optional EVM anchoring. |
| Detection / SIEM / IR | **82** | Splunk HEC + Elastic ECS, WardenHealer, alerting, incident register. |
| CI/CD security gates | **78** | warden-scan + Claude Opus security review on sensitive files. Gap: adversarial + CVE gates informational; no SAST/DAST/gitleaks. |

**Self-security ≈ 75.**

**Cybersecurity overall ≈ 81/100.**

### 6c. Ranked risks (fix order)

1. **Secret-bearing SQLite DBs default to `/tmp`** (secrets-governance inventory, masking vault, staff economics, etc.) — ephemeral + potentially world-readable; one prod misconfig leaks credentials/PII. **HIGH.**
2. **`BrowserSandbox --no-sandbox` + in-process tool exec** — a hostile page or tool has no OS boundary; SAC screens URLs, not code execution. **HIGH.**
3. **Incomplete `resolve_key` adoption** — remaining raw-env HMAC fallbacks are forgeable when the env var is unset. **MED-HIGH.**
4. **Fail-open security gates on timeout** — `/filter` injection pre-screen and x402 both fail-open; a targeted timeout is a bypass primitive (x402 is at least `payment_bypassed`-audited). **MED.**
5. **CVE + adversarial gates informational-only** — a known-vuln dependency or a regressed detector can merge green. **MED.**
6. **SOVA / MasterAgent bypass BoundaryRegistry** — the strongest per-agent gate is staff-only. **MED.**

### 6d. Security hardening plan (folds into Phases 6–7 + adds)

- **S1 (fast win):** move every secret-bearing DB off `/tmp` to a persisted `DATA_DIR` (mode 0700); startup assertion rejects `/tmp` secret paths in prod. → key-mgmt 76 → 86.
- **S2:** finish `resolve_key` migration + CI grep gate forbidding new `os.getenv(...HMAC...)` fallbacks. → closes the forgeable-key path.
- **S3 ✅ DONE (2026-07-16):** supply-chain gates. Track A had already landed the SAST half — gitleaks (gating), Bandit (gating on HIGH), Semgrep ERROR (gating), Syft SBOM + cosign; and the **adversarial ratchet** (`test_adversarial_ratchet.py`) already gates (baseline may only improve; single-layer stress stays informational). S3 closed the CVE half: **`pip-audit` + Trivy promoted informational → GATING on *actionable* CVEs only** — a dependency/OS CVE that has a published fix. `pip-audit` gates on `fix_versions`-present (jq filter, baseline 0 fixable at introduction; 1 unfixable stays informational), with an auditable per-ID waiver file `.github/pip-audit-ignore`. Trivy gates on `HIGH,CRITICAL` + `ignore-unfixed`. Both jobs are outside the deploy job's `needs`, so a red CVE gate blocks PR merges without ever stalling a hotfix autodeploy. → supply-chain 68 → 82, CI 78 → 88.
- **S4 ✅ DONE (2026-07-17):** browser process isolation, both halves. DE-7 had already made `--no-sandbox` **conditional** (`_browser_launch_args` + `BROWSER_ENABLE_SANDBOX`, opt-in, unit-tested). S4 closed the rest: (a) **usable sidecar wiring** — committed-but-commented `security_opt` + `BROWSER_ENABLE_SANDBOX=true` opt-in on `arq-worker` (the service that drives Chromium), `docker/seccomp/README.md` as the authoritative fetch+checksum-pin procedure for the upstream Chromium seccomp profile (deliberately **not** a hand-transcribed 800-line allowlist committed to the repo; gitignored artifact), doc updated. (b) **in-process resource + timeout budget** — `warden/agent/tool_budget.py` wraps every `traced_dispatch` handler in an `asyncio.wait_for` wall-clock budget (default 60s / browser 120s, env-tunable) and caps concurrent in-process browser-tool launches with a semaphore (default 2). **Fail-safe** (bounded, logged `tool_timeout` denial + Chromium teardown on cancel), never fail-open. `warden/tests/test_tool_budget.py` (11, no Chromium/network). → isolation 62 → 82.
- **S5 ✅ DONE (2026-07-13):** extend BoundaryRegistry + velocity + GSAM-quarantine to SOVA/Master (= Phase 7) beside the existing SAC screen point. Delivered as Phase 7 Slice 2 (`agentic_gate()`, MasterAgent priv-esc closed) — see the Slice 2 entry above.
- **S6 ✅ DONE (2026-07-17):** convert fail-open *security-gate timeouts* to fail-**safe**. The genuinely-*silent* gate was the Rec-1 injection pre-screen (`screen_sanctions_list` / `score_kyc_profile` / `generate_sar` / `generate_seo_content` sent freetext through `/filter` and on timeout did a bare `log.debug` + carry on — a targeted filter timeout smuggled injection payloads past the guardrail). New shared `warden/staff/tools/_prescreen.py::prescreen_freetext()` keeps availability but makes the bypass **observable + throttled**: **bounded retry** (`STAFF_PRESCREEN_ATTEMPTS`, default 2), then on a real bypass a P0 `record_failopen()` Prometheus counter + a structured `injection_prescreen_bypassed` audit line, plus a **per-tenant sliding bypass counter** (`STAFF_PRESCREEN_THROTTLE_*`) that escalates the audit to `status="degraded"` and flips `should_throttle` once a tenant bursts — the "tighten rate-limit" signal. A filter `blocked=True` verdict stays **fail-CLOSED**. Both call sites (`compliance_kyc._prescreen_text`, `growth.generate_seo_content`) refactored onto it; `_prescreen_text`'s bool contract preserved. x402's fail-open was already `payment_bypassed`-audited (v7.4); retry/throttle on the payment path is an optional follow-on. Tests `warden/tests/test_staff_prescreen.py` (9, httpx faked). ruff + mypy clean; counter-less-fail-open ratchet net-neutral (removed 2 silent token lines, new file is covered).
- **S7 ✅ DONE (2026-07-18):** DAST repaired + assessment cadence formalised. The weekly `pentest.yml` (TC-02) had been red for 4+ weeks (Nuclei's unversioned `latest/download` asset URL 404s — now resolved via the GitHub releases API) and its "green" ZAP baseline was hollow — the spider saw exactly **one** URI (`/robots.txt`) because a JSON API has nothing to crawl. New `zap-api-scan` job boots an ephemeral warden on the runner (pip + cached MiniLM, `ALLOW_UNAUTHENTICATED=true`) and drives `zaproxy/action-api-scan` off the app's own `/openapi.json`, so every route is actually exercised — without Cloudflare interference, prod alert noise, or ERS pollution. External pen-test (annual) + threat-model refresh (semi-annual) cadence documented in `docs/security-model.md` §8. → **S1–S7 backlog closed.**

**Projected cybersecurity after S1–S7: ≈ 90/100**, sandbox isolation the last item to fully close.
