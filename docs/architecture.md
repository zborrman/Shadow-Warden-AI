# Shadow Warden AI — Target Architecture

**Status:** Phases 1-2 landed · Phase 3 in progress (safety net + 2 groups
extracted) · Phase 4 layer-guard landed — **zero upward imports of `warden.main`,
enforced in CI**
**Style:** Layered modular monolith (single-node, CPU-only, fail-open <2ms hot path)
**Non-goal:** microservices / event bus — they break the latency budget and add ops
weight a single-tenant-per-node security gateway does not need.

---

## 1. Why not a rewrite

The domain decomposition is sound: a 9-stage `/filter` pipeline plus ~60 feature
verticals (marketplace, communities, billing, sovereign, staff, …). Measured debt:

| Signal | Value | Verdict |
|--------|-------|---------|
| `warden/main.py` | 6207 LOC · 134 fns · 92 inline routes · 88 `include_router` | god-module |
| Reach-backs into `main` from domains | 7 sites (`_brain_guard`, `_evolve`, `_semantic_engine`) | real cycle source |
| Lazy `# noqa: PLC0415` imports | 651 total | ~400 legit (httpx/redis/numpy/anthropic, fail-open + cold-start) · ~250 cross-domain `warden.*` |
| Router registration | 2 mechanisms (`app_factory` 8 · inline 88) | half-migrated |

Conclusion: **restructure within the monolith**, don't rewrite. Four phases, each a
standalone PR that keeps external APIs and the 4305-test suite green.

---

## 2. Target layers

Dependencies point **downward only**. A CI guard (Phase 4) enforces it.

```
┌─────────────────────────────────────────────────────────┐
│ api/        thin routers: HTTP ⇆ service. No domain logic.│
├─────────────────────────────────────────────────────────┤
│ services/   orchestration: FilterPipeline, Evolution, …   │
├─────────────────────────────────────────────────────────┤
│ domains/    topology, obfuscation, secrets, semantic,     │
│             causal, ers, brain, marketplace, communities… │
├─────────────────────────────────────────────────────────┤
│ runtime/    shared singletons, config, contracts.          │
│             LEAF — imports no warden domain. Cycle-proof.  │
└─────────────────────────────────────────────────────────┘
```

Rule: a layer may import only from layers below it. Domains never import `api` or
`services` or `main`; they read shared state from `runtime`.

---

## 3. Phase 1 — Runtime container ✅ (landed)

**Problem:** domains did `from warden import main; main._brain_guard`, and `main`
imports nearly every domain → cycles → 651 lazy-import workarounds.

**Fix:** `warden/runtime.py` — a dependency-free leaf holding the shared singletons
(`brain_guard`, `evolve`, `semantic_engine`, `redactor`, `guard`, `agent_monitor`).

- `main` **publishes** during lifespan: `runtime.publish(brain_guard=…, evolve=…)`.
- Domains **read**: `from warden.runtime import runtime; runtime.brain_guard`.
- Readers tolerate `None` (unit tests that never boot the app) and fall back to a
  local instance.

Migrated sites: `api/agent.py`, `brain/evolve.py`, `marketplace/importer.py`,
`testing/context.py`. Tests: `test_runtime.py` (incl. an AST guard asserting the
module imports no `warden.*`).

---

## 4. Phase 2 — Extract the pipeline into a service ✅ (seam landed)

**Landed:** `warden/services/pipeline.py` — `FilterPipeline` is now the stable
public entry point. The `/filter` and `/filter/batch` HTTP handlers call
`FilterPipeline().run(...)` instead of the main-private orchestrator. The facade
resolves the orchestrator from `runtime` (published at startup as
`filter_orchestrator`) and **fails closed** if the app isn't booted. Callers now
depend on `warden.services.pipeline`, not `warden.main` internals — the seam
Phase 3 needs. Tests: `test_pipeline_service.py` (delegation, fail-closed, layer
guard); all 16 `/filter` e2e + batch tests green.

**Remaining (incremental, behind the unchanged interface):** move the ~900-line
`_run_filter_pipeline` body from `main.py` into the service.

**Goal:** the crown-jewel `/filter` logic leaves the god-module.

- New `warden/services/pipeline.py` → `FilterPipeline.run(request) -> FilterResponse`,
  owning the 9 stages (topology → obfuscation → secrets → semantic → brain → causal
  → phish → ers → decision) and `trace_stage`.
- `main.filter_content` (currently ~450 LOC at `main.py:3031`) becomes a ~10-line
  router in `warden/api/filter.py` that calls the service.
- Stage instances come from `runtime` (published in Phase 1), so the service has no
  `main` dependency.
- Invariants preserved verbatim: x402 fail-open, GDPR content-never-logged, all 32
  Playwright assertions, `<link rel="agent-protocol">`, Decimal clearing math.
- Verification: existing `/filter` end-to-end tests unchanged; add
  `test_pipeline_service.py` calling the service directly.

Also split the other oversized modules by responsibility:
`agent/tools.py` (2821) → `agent/tools/{sova,forensics,compliance,threat}.py`;
`marketplace/api.py` (1315) → already has sub-routers, move remaining inline handlers.

---

## 5. Phase 3 — Dissolve `main.py` 🚧 (safety net + first extraction landed)

**Landed:** a route-inventory guard (`test_route_inventory.py` +
`fixtures/route_inventory.json`, 713 routes) — the executable "OpenAPI diff":
any route added/removed/renamed fails CI. A pure Phase-3 *move* must leave it
green. First extraction proving the recipe: `POST /api/contact` moved from an
inline `@app.post` to `warden/api/contact.py` (`APIRouter`), included via
`app.include_router`. Guard stayed green (route unchanged); `test_contact_endpoint.py`
locks behaviour + a layer check that the router doesn't import `warden.main`.

**Recipe (repeat per route group, one PR each):** copy handler+models into
`warden/api/<group>.py` as an `APIRouter`; replace the inline block in `main.py`
with `app.include_router(...)`; run the inventory guard (must stay green) + the
group's tests. Coupled routes (health, config) first need their shared state
(`_bypass_window`, `_filter_window`, `_cb`) lifted into `runtime`/`api/deps.py`.

**Goal:** `main.py` < 300 LOC — only `create_app()` + lifespan wiring.

- Move the 92 inline `@app.*` routes into `warden/api/*` modules grouped by concern
  (`api/health.py`, `api/config.py`, `api/batch.py`, `api/output.py`, …).
- Extract shared helpers still living in `main` (`_tenant_key`, `_load`, docs-auth,
  blocklist) into `warden/runtime/` or `warden/api/deps.py`.
- Lifespan startup (singleton construction + `runtime.publish`) moves to
  `warden/bootstrap.py`; `main.py` just calls `create_app()`.
- Verification: full suite + Docker smoke (`/health`, `/filter`) must stay green;
  OpenAPI schema diff must be empty (no route lost or renamed).

---

## 6. Phase 4 — One registration path + layer enforcement

**Landed — the self-defending layer guard.** `test_architecture_layers.py`
enforces the core invariant in CI: **no module under `warden/` (except `main.py`)
may import `warden.main`** — directly, aliased, or `from warden import main`. The
scan is AST-based (docstring mentions ignored). The last four upward reach-backs
were removed by publishing their singletons to `warden.runtime` and having readers
resolve from there:

| Reader (was `warden.main.…`) | Now reads from runtime slot |
|------------------------------|-----------------------------|
| `api/config_api.py` (`set_default_rate_limit`) | imported from `warden.auth_guard` (its real home) |
| `brain/evolve.py` (`_poison_guard`) | `runtime.get("poison_guard")` |
| `integrations/misp_bridge.py` (`_threat_store`) | `runtime.get("threat_store")` |
| `analytics/pages/2_Settings.py` (`_intel_bridge`) | `runtime.get("intel_bridge")` |

A second test asserts `warden.runtime` imports no `warden.*` package (the
cycle-proof leaf). Result: **the historic cycle source is gone and cannot
regress** — any new upward import fails the build.

**Remaining (optional debt reduction, non-behavioural — the guard makes each
safe to land incrementally):**

- Fold the inline `include_router` calls into `CORE_ROUTERS` / `OPTIONAL_ROUTERS`
  specs consumed by a single `register_router_safe` loop in `app_factory`.
- Retire the ~250 cross-domain lazy `warden.*` imports that only existed to dodge
  cycles now removed; keep the ~400 legit lazy imports of heavy/optional deps
  (httpx, redis, numpy, web3, anthropic) that serve fail-open + cold-start.
- Continue moving the remaining inline `main.py` routes into `warden/api/*` behind
  the route-inventory guard until `main.py` is just `create_app()` + lifespan.

---

## 7. Sequencing & risk

| Phase | Scope | Risk | PR |
|-------|-------|------|-----|
| 1 Runtime | +2 files, 5 sites | low (additive) | landed |
| 2 Pipeline service | extract `/filter` | medium (hot path) | own PR + e2e |
| 3 Dissolve main | move 92 routes | medium (surface area) | own PR + OpenAPI diff |
| 4 Registration + guard | wiring + lint | low | own PR |

Each phase is independently shippable, changes **no external API**, and is gated by
the existing CI (4305 tests, ≥75% coverage, ruff + mypy, Docker smoke, 32 Playwright).
Do phases in order — Phase 1 unblocks 2–4 by making `runtime` the shared-state seam.

## 8. Invariants the refactor must never touch

`<link rel="agent-protocol">` · `clearing.py` Decimal math · x402 fail-open · all 32
Playwright assertions · GDPR content-never-logged · Digital-Staff STAFF-01…05 ·
`resolve_key` fail-closed signing · `net_guard` SSRF filter on outbound URLs.
