# Plan 85 — raising every audit category to 85/100

**Status: proposal.** Produced 2026-08-22 against `origin/main` `c1ce005f`.
Baseline scores come from the audit of the same date; every one of them is
anchored to a command that can be re-run.

| # | Category | Now | Target | Delta |
|---|---|---|---|---|
| 1 | Performance & scalability | 52 | 85 | +33 |
| 2 | Functional correctness | 58 | 85 | +27 |
| 3 | Security & privacy | 70 | 85 | +15 |
| 4 | Stability & availability | 62 | 85 | +23 |
| 5 | Data integrity & integration | 66 | 85 | +19 |
| 6 | Maintainability & code quality | 74 | 85 | +11 |

**Overall 64 → 85.**

---

## The rule this plan follows

A category only counts as 85 when a **measurement in CI** says so. This repo
already learned the alternative the hard way — `docs/capability-matrix.md`
records nine published numbers that no instrument ever produced. So every item
below ships with a gate, and the gate is the deliverable, not the number.

Three items are deliberately *not* in this plan, with reasons stated at the
bottom.

---

## Track 1 — Performance & scalability: 52 → 85

**The gap.** Two things, and only one of them is code.

`warden/metrics.py` defines exactly one `Histogram`
(`warden_arq_job_duration_seconds`, line 900). There is no `/filter` latency
instrument anywhere. The site publishes sub-1ms / sub-2ms / sub-3ms stage
latency in 19 places. `/stats` computes `avg_latency_ms` and `p99_latency_ms`
from `logs.json` (`warden/main.py:1865`) — that data exists, it is just never
exported to Prometheus.

Separately, ~204 distinct SQLite files are the primary store. 48 call sites pass
`turso_name=`; 9 modules touch Postgres. `k8s/hpa.yaml` scales 2→10 replicas.
Node-local SQLite and 2+ replicas are mutually exclusive; today that is hidden
because prod runs a single compose node at 0 rps.

| ID | Work | Gate |
|---|---|---|
| P-1 | `FILTER_LATENCY_SECONDS` Histogram, label `stage`, buckets `(.0005,.001,.002,.005,.01,.025,.05,.1,.25,.5,1,+Inf)`. Observe it inside `trace_stage()` (`warden/telemetry.py:159`) so all 9 stages are covered by one change. | `test_filter_latency_histogram_exists` — scrape `/metrics`, assert the family is present **and** `_count > 0` after one `/filter` call. A metric with no writer is the OB-F12 failure mode; assert the writer. |
| P-2 | Grafana panel + alert rule on `histogram_quantile(0.95, ...)` per stage; wire into the existing 35-rule file. | `test_grafana_metrics_resolve` already exists — it fails if a panel references a metric no code writes. |
| P-3 | Rewrite the 19 site latency claims from the measured p50/p95, or delete them. Move the row in `capability-matrix.md` from `UNMEASURED` to `LIVE`. | Claims ratchet: a site latency string must match a value the probe can produce. |
| P-4 | Run `k6/load_test.js` against staging at 50/200/500 rps and publish the knee. The current thresholds (p95 < 800 ms) have never been exercised under real concurrency. | The `k6-smoke` job exists — add a nightly `k6-load` at 200 rps, informational first, blocking after two green weeks. |
| P-5 | **Storage decision, written down.** Three options: (a) Turso for all 204 — extends the existing seam, 156 call sites to convert; (b) Postgres for the ~20 DBs carrying money, identity and audit, leave the rest node-local and cap replicas at 1; (c) stay single-node and delete the 2–10 range from `k8s/hpa.yaml`. **Recommend (b)** — it spends the effort where the risk is; (a) is a 156-site change for stores no user reads. | `test_no_replica_unsafe_store` — a ratchet listing every DB permitted to be node-local; adding one requires editing the baseline. |
| P-6 | RSS is 1.39 GB at 0 rps across 4 uvicorn workers. Profile model/ONNX residency; target < 800 MB. | `scripts/profile_under_load.sh` exists; add an RSS ceiling assertion to the Docker smoke phase. |

**Effort:** P-1..P-3 ≈ 2 days · P-4 ≈ 1 day · P-5 ≈ 1 week for option (b) · P-6 ≈ 2 days.

---

## Track 2 — Functional correctness: 58 → 85

**The gap is not the test suite.** 6,690 of 6,694 pass, 0 collection errors,
83% coverage gate, mypy clean over 982 files, ruff clean. The suite is already
at 85+.

The gap is the product function. `warden/tests/adversarial/baseline.json`
records `missed: 37` of 58 — **36.2%** detection. The cause is visible in
`warden/brain/semantic.py`: `_JAILBREAK_CORPUS` holds ~85 seed strings
(lines 123–210) and `DEFAULT_THRESHOLD` is 0.72 cosine on all-MiniLM-L6-v2.
Above ~0.70, MiniLM cosine is a paraphrase detector. So the semantic stage
catches restatements of 85 sentences and very little else.

**The trap to avoid.** The six named misses are quoted in
`capability-matrix.md` §1.1. Pasting them into `_JAILBREAK_CORPUS` would move
the ratchet to `missed: 31` tomorrow and teach us nothing — it is training on
the test set. This plan forbids it.

| ID | Work | Gate |
|---|---|---|
| D-1 | **Fix the instrument first.** 58 jailbreaks / 35 benign is too small to carry a percentage. Grow to ≥500 jailbreak and ≥500 benign from public sources, split 70/30 into `train` and a **held-out** `eval` that no corpus edit may read. | `test_corpus_disjoint` — assert `train ∩ eval = ∅` by hash, and that `_JAILBREAK_CORPUS` shares no entry with `eval`. |
| D-2 | Re-baseline on the held-out eval. Expect movement — 36.2% over 58 prompts carries roughly a ±13 pp interval. Publish the interval, not just the point. | `test_adversarial_ratchet` keeps its `missed <= baseline` monotonicity, now over ≥150 held-out prompts. |
| D-3 | Expand `_JAILBREAK_CORPUS` from the *train* split only, 85 → ~600 entries. FAISS already switches on at 500 (`FAISS_MIN_CORPUS`), so the latency path is built. | Held-out detection ≥ 75%. |
| D-4 | Threshold sweep on the train split. 0.72 is a documented guess ("intentionally conservative", line 66). Plot detection against FP across 0.55–0.80 and pick off the curve. | FP rate over ≥500 benign stays ≤ 2%. The present 0/35 is real but under-powered. |
| D-5 | If D-3 + D-4 stall below 85%, add a cross-encoder or fine-tuned classifier head as stage 2c, flag-gated, on the ONNX path. Cosine similarity has a ceiling and we will have found it. | Held-out detection ≥ 85%, FP ≤ 2%, added p95 ≤ 15 ms. |
| D-6 | Fix the 4 order-dependent failures (`test_pii_vault`, `test_production_readiness`, `test_threat_neutralizer`, `test_ws`). All four pass in isolation, so this is fixture pollution — the class already recorded for `os.environ.pop()` teardowns. | Full suite green in one run, plus a nightly random-order run. |

**Effort:** D-1..D-2 ≈ 1 week (corpus sourcing dominates) · D-3..D-4 ≈ 1 week · D-5 ≈ 2 weeks if needed · D-6 ≈ 1 day.

**This is the long pole.** Nothing else on this page matters as much: a gateway
that misses two thirds of its own attack corpus is the product risk.

---

## Track 3 — Security & privacy: 70 → 85

**The gap.** The perimeter is strong — 195 keyed routes, SAST + pip-audit +
pentest + commit-scan workflows, SBOM signing, SLSA provenance,
`warden/constraints.txt` governing both CI and the image, origin lockdown,
`net_guard` pinning, XXE coverage, hash-chained audit. What is weak is what
happens when a stage breaks.

Production reports `fail_strategy: "open"`. `scripts/fail_open_inventory.py`
finds **362 fail-open sites, 198 counter-less** (baseline 200 — the ratchet
works, slowly). And right now, live:
`warden_stage_failopen_total{reason="model_not_loaded",stage="image_guard"} 1`.
A guard stage is disabled in production and nothing paged.

| ID | Work | Gate |
|---|---|---|
| S-1 | Drive counter-less fail-opens 198 → 0 for sites inside `/filter`. Reporting and UI code may keep theirs, but moves to an explicit allowlist rather than a count. | Split `counterless_failopen_baseline.json` into `pipeline: 0` (hard zero) and `peripheral: N` (ratchet). |
| S-2 | Alert on any increase of `warden_stage_failopen_total`, per stage, severity `critical`, routed to the PagerDuty receiver already in `contact_points.yml`. | An alert rule whose expression references a metric with a proven writer — the OB-F12 lesson. |
| S-3 | Fix the live `image_guard` `model_not_loaded`. Either ship the model or mark the stage `BUILT`, not `LIVE`, in the capability matrix. | `/health/pipeline` returns `degraded_stages: []` **and** the matrix row agrees. |
| S-4 | Declare fail-open vs fail-closed per stage in config. Today one global `fail_strategy` sits above 362 local decisions. | `test_failopen_policy_declared` — every pipeline stage names its strategy; an undeclared stage fails. |
| S-5 | Reduce the 138 `noqa: BLE001` blanket excepts in pipeline modules — each is a candidate silent fail-open. Peripheral modules keep theirs. | Suppression ratchet already counts these; add a per-directory floor for `warden/brain/` and `warden/guards/`. |
| S-6 | Re-run the Strix findings against single-key production; several were recorded LATENT rather than fixed. Remove any `warden/poc_*.py` scan artifacts. | `pentest.yml` clean; commit-scan clean. |

**Effort:** S-1 ≈ 1 week · S-2..S-4 ≈ 3 days · S-5 ≈ 3 days · S-6 ≈ 2 days.

---

## Track 4 — Stability & availability: 62 → 85

**The gap.** The machinery is good: 35 alert rules across Slack, webhook and
PagerDuty receivers, autoheal, 14 healthchecks and 25 restart policies over 35
services, a green uptime workflow. What is missing is a track record and a
second node.

Two production outages in roughly four weeks — the
`prometheus-fastapi-instrumentator` arity break (closed by making
`constraints.txt` govern the image) and the 2026-08-22 deploy race (closed at
`c1ce005f`, `group: deploy-vps`). Both were found by people, not by alerts.

| ID | Work | Gate |
|---|---|---|
| A-1 | Page on deploy failure. Today the deploy job can fail with no notification. | `notify-deploy` runs on `failure()` as well as success, to PagerDuty. |
| A-2 | Prove the alert path end to end: fire one synthetic alert per receiver and assert delivery. Both wake-up channels were previously undelivered without anyone noticing. | Quarterly `test_alert_delivery` job posting a synthetic alert and checking receipt. |
| A-3 | Replace the stale-container fallback that tore down all 19 services with a scoped restart of the failed service. | Staging runbook test: kill one container, assert the other 18 stay up. |
| A-4 | Publish a real SLO — availability and `/filter` p95 — computed from the uptime workflow plus P-1's histogram. `filter_rps_1m: 0.0` means there is no number today. | 30 consecutive days of measured uptime ≥ 99.5%. |
| A-5 | Second node, or an honest single-node SLO. One Hetzner VPS with `k8s/` and `helm/` unused caps availability regardless of config quality. Recommend stating the single-node SLO now and planning the second node after P-5 settles storage. | Architecture doc states node count and the SLO it supports. |
| A-6 | Validate load-shedding and backpressure on the 4-worker / 8-vCPU layout using P-4's load run. | No 5xx at 200 rps for 10 minutes. |

**Effort:** A-1..A-3 ≈ 4 days · A-4 ≈ 30 days elapsed, ~1 day of work · A-5 depends on P-5 · A-6 ≈ 2 days.

---

## Track 5 — Data integrity & integration: 66 → 85

**The gap.** The ratchets here are genuinely good — ghost column / table /
database baselines at or near zero, a single-Postgres-schema-authority test, a
DDL registry, atomic writes, alembic actually running, offsite `pg_dump` with a
proven 17-second restore, WORM hash chains, and a money-columns ratchet added
after clearing settled every trade at $0.00.

What holds this below 85 is that the same bug class keeps recurring — journal
ghost fields, the $0.00 settlement, a ledger cutover gate that passed with zero
tenants verified. Each was caught after the fact by a new ratchet. 85 means
catching the next one before it ships.

| ID | Work | Gate |
|---|---|---|
| I-1 | Generalise the ghost-field idea: for every write path producing a number a human reads, assert a non-trivial value against a fixture that is *not* the one the writer produced. The $0.00 bug survived because the fixtures agreed with it. | `test_no_self_confirming_fixture` across money, journal and metrics paths. |
| I-2 | Evidence bundles are on-demand only and never leave the node. For a compliance product that is a gap, not an optimisation. | Nightly evidence-bundle ship offsite, with a restore drill modelled on R6. |
| I-3 | Unify DB path resolution. Three modules resolve paths three ways; `open_db()` now covers 109 call sites but 12 raw `sqlite3.connect` remain. | `raw_sqlite_connect_baseline.json` → 0. |
| I-4 | Cutover gates must count verified subjects, never elapsed time — the FT-2 shadow period concluded on a clock with zero tenants checked. | Any `*_cutover` gate asserts `verified_count >= N` before passing. |
| I-5 | Backup coverage for the ~204 SQLite stores, not only Postgres. R1/R6 cover `pg_dump`; most state lives in files. | Restore drill covering the stores P-5 designates authoritative. |

**Effort:** I-1 ≈ 4 days · I-2 ≈ 3 days · I-3 ≈ 2 days · I-4 ≈ 1 day · I-5 ≈ 3 days.

---

## Track 6 — Maintainability & code quality: 74 → 85

**The gap.** Already the strongest category: ruff clean, mypy effectively clean
(5 errors, all missing `types-PyYAML` stubs), 205k lines of test against 665k
total, 12 downward-only ratchet baselines, 10 CI workflows, a route-parity
inventory, and a capability matrix that marks the project's own published
claims `FABRICATED` and `OVERSTATED`. That last one is rare and worth keeping.

Three concrete drags remain.

| ID | Work | Gate |
|---|---|---|
| M-1 | **852 frontend files, 1 test.** `site` 110, `dashboard` 321, `portal` 421. The Python side sits at ~31% test-to-source; TypeScript is at ~0. | Vitest + Playwright on `dashboard` and `portal`; coverage floor 40%, ratcheting up. Start with the SOC dashboard's fail-closed proxy — security-relevant and untested. |
| M-2 | `warden/main.py` is 4,274 lines. The layered-monolith refactor already has a runtime seam and a route-inventory guard; finish moving routes out. | Ratchet: `main.py` line count monotonically decreasing, target < 1,500. |
| M-3 | Two source trees on disk, and the running Docker stack mounts the stale one (`Shadow Warden AI`, spaces, May). Live verification has been testing the wrong tree. | Delete or archive the stale checkout; assert the deployed commit SHA matches `origin/main` in the deploy job. |
| M-4 | Add `types-PyYAML` to dev deps — 5 of 5 mypy errors disappear. | mypy exits 0. |
| M-5 | 831 `noqa` + 226 `type: ignore`. 652 are `PLC0415` (import-inside-function), deliberate for lazy imports — leave them. Target the 138 `BLE001` under S-5, the rest opportunistically. | Suppression ratchet already enforces; no work beyond S-5. |

**Effort:** M-1 ≈ 2 weeks · M-2 ≈ 1 week · M-3 ≈ 1 day · M-4 ≈ 10 minutes.

---

## Sequencing

Ordered by what unblocks what, not by score delta.

| Phase | Contents | Elapsed |
|---|---|---|
| 0 — same day | M-4, M-3, S-3, A-1, D-6 | 1 day |
| 1 — instrument | P-1, P-2, S-2, I-4 | 1 week |
| 2 — measure honestly | D-1, D-2, P-3; A-4 starts its 30-day clock | 2 weeks |
| 3 — the long pole | D-3, D-4, S-1, M-1 | 3 weeks |
| 4 — structure | P-5, I-3, I-5, M-2, A-3, A-5 | 3 weeks |
| 5 — close | D-5 if needed, P-4, P-6, A-6, I-1, I-2, S-4..S-6 | 3 weeks |

**Roughly 10–12 weeks of focused work** for one engineer, with Track 2 on the
critical path and M-1 the largest single block.

---

## Three things deliberately not in this plan

**Lowering `SEMANTIC_THRESHOLD` to raise the detection number.** It would work,
and it would be dishonest — the false-positive corpus is 35 prompts, far too
small to detect the damage. D-4 runs the sweep only after D-1 makes the FP
measurement trustworthy.

**Seeding the six named misses into `_JAILBREAK_CORPUS`.** Moves the ratchet,
teaches nothing. See D-1's disjointness gate.

**Converting all 204 SQLite stores to Turso.** 156 call sites for stores that
carry no user-visible state, at a moment when production has zero users.
Option (b) under P-5 spends the effort where the risk is.

---

## Re-scoring

Each category is re-scored by re-running its evidence, not by review:

```bash
pytest warden/tests/ -q -m "not adversarial and not slow"    # Tracks 2, 6
pytest warden/tests/test_adversarial_ratchet.py              # Track 2
python scripts/fail_open_inventory.py                        # Track 3
python scripts/capability_probe.py --json                    # Tracks 1, 2
curl -s https://api.shadow-warden-ai.com/metrics             # Tracks 1, 3, 4
ruff check warden/ analytics/ --ignore E501                  # Track 6
mypy warden/ --ignore-missing-imports --no-strict-optional   # Track 6
```
