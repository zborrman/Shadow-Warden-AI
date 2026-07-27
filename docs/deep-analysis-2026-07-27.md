# Deep Project Analysis — Shadow Warden AI

**Date:** 2026-07-27 · **Baseline commit:** `f2754fd1` (main) · **Scope:** whole repository, CI, compose topology, governance docs

This is an evidence-first assessment. Every score below is anchored to a measurement
taken from the tree at the baseline commit, not to what the plan documents claim.
Where a governance document and the code disagree, the code wins and the
disagreement is recorded in the **Conflict register** (§4).

---

## 1. Measurement base

| Metric | Value | How measured |
|---|---|---|
| Python files (non-test, `warden/`) | 610 | recursive file scan |
| Python LOC (whole repo, excl. vendor) | 371,761 | line count |
| Test files / test LOC | 545 / 101,402 | line count |
| Tests collected | **5,809**, 0 collection errors | `pytest --collect-only` |
| Coverage gate in CI | 79% (`--cov-fail-under=79`) | `.github/workflows/ci.yml:396` |
| HTTP routes / defining modules | **769 / 108** | `warden/tests/fixtures/route_inventory.json` |
| `warden/main.py` | 3,680 lines, 23 inline `@app` routes, 39 `include_router` | file scan |
| `warden/config.py` | 1,846 lines, 441 settings fields | file scan |
| Remaining `os.getenv`/`os.environ` sites (non-test) | 545 | recursive grep |
| Suppression baselines | 830 `noqa`, 223 `type: ignore` across 226 files | `warden/tests/suppression_baseline.json` |
| Counter-less fail-open baseline | 200 | `warden/tests/counterless_failopen_baseline.json` |
| Runtime deps in the deployed image | 53, of which **52 are floating (`>=`)** | `warden/requirements.txt` |
| `requirements-lock.txt` | 36 exact pins — **not used by the Dockerfile** | `warden/Dockerfile` |
| Compose services / declared memory limits | 22 services / **20,352 MB** total | `docker-compose.yml` |
| ARQ cron jobs | 30 | `workers/settings.py`, `agent/scheduler.py` |
| CI workflows / jobs in `ci.yml` | 10 files / 18 jobs, `ci.yml` = 58 KB | `.github/workflows/` |
| Markdown governance surface | 14 root + 57 `docs/` files; README 150 KB, CLAUDE.md 79 KB | file scan |
| Open PRs | 20 — 19 Dependabot (oldest 2026-03-28), 1 feature (#167, 2026-07-19) | `gh pr list` |
| Repo hygiene | 1,936 tracked files, 64 MB `.git`, no `node_modules`/`.next` tracked | `git ls-files` |

---

## 2. Scorecard (1–100)

Scores are *absolute* against a production-grade commercial security product, not
relative to the project's own history. Weight reflects how much each category
determines whether this product survives a paying enterprise customer.

| # | Category | Score | Weight | Verdict |
|---|---|---:|---:|---|
| 1 | Security controls & posture | **88** | 12 | Genuinely strong; fail-closed by construction |
| 2 | Agentic subsystem safety | **85** | 6 | One gate, ratchet-enforced; best-in-class for this class of product |
| 3 | Compliance artefacts | **85** | 3 | DPIA, SOC 2 evidence, ISO 93-control map, licensing posture |
| 4 | ML / detection core | **82** | 5 | TDA + hyperbolic + causal DAG with anti-poisoning gates |
| 5 | Observability | **80** | 5 | OTel/Prom/Loki/Jaeger + fail-open counters + GSAM health |
| 6 | Testing & QA | **80** | 8 | 5,809 tests, 7 ratchets, clean collection; adversarial still advisory |
| 7 | Reliability / resilience | **78** | 8 | R1–R6 all closed, restore drill RTO ~17 s; still a single node |
| 8 | Data layer | **70** | 6 | DDL registry + `open_db` seam landed; 5 stores, one mid-flight migration |
| 9 | CI/CD | **68** | 5 | Broad gates, but a 58 KB monolith workflow and many advisory `\|\| true` |
| 10 | Money-layer correctness | **62** | 7 | Ledger/idempotency/outbox/recon built — **almost all default-OFF** |
| 11 | Architecture & modularity | **58** | 6 | 769 routes, one mega-image carrying torch+playwright+opencv+whisper+web3 |
| 12 | Code maintainability | **55** | 7 | 3.7k-line `main.py`, 1.8k-line `config.py`, 1,053 suppressions |
| 13 | Frontend | **55** | 3 | Three separate apps; shared DS package not wired as a workspace |
| 14 | Operational complexity | **50** | 4 | 22 services + 30 crons + 20 GB of declared limits on one VPS |
| 15 | Product scope discipline | **50** | 2 | Feature surface grows faster than any evidence of demand |
| 16 | Documentation coherence | **45** | 4 | 71 markdown files, 5 duplicate basenames, contradictory versions |
| 17 | **Supply chain / dependency mgmt** | **34** | 9 | 52/53 floating pins; the lock file exists and is ignored |

### Composite: **68 / 100**

> **One-line diagnosis:** the *security engineering* is at ~85; the *software
> industrialization* around it is at ~50. The project does not have a security
> problem — it has a **build-determinism, surface-area and finish-the-last-10%
> problem**. The 2026-07-26 full-API outage was not caused by a security bug; it
> was caused by an unpinned dependency, which is category 17.

---

## 3. Findings by severity

### P0 — fix now

**F-1 · CI is pinned; the production image is not. They had drifted by 48 packages.**

> Revised after reading the CI config and measuring against production. The
> first draft of this finding said "no lockfile exists" — wrong, and the truth
> is worse.

A lockfile does exist: `warden/constraints.txt` (241 exact pins, generated from
a green CI run on 2026-07-05). **CI uses it** — `pip install -r
warden/requirements.txt -c warden/constraints.txt`. **`warden/Dockerfile` did
not**: it ran a bare `pip install -r requirements.txt` against 53 requirements
of which 52 are `>=`. So the image resolved whatever PyPI served at build time,
and CI tested something else.

Measured on 2026-07-27 by diffing `constraints.txt` against `pip freeze` inside
the running production container: **48 packages differ** between the CI-tested
set and production. `prometheus-fastapi-instrumentator` (CI 8.0.2 → prod 8.1.0)
is one of them, and it is the one that caused the 2026-07-26 full-API outage —
8.1.0 changed the arity of `_get_route_name`, which `main.py` monkeypatches, so
every request 502'd. The other 47 were the same accident with a different fuse.
Notable ones: `fastapi` 0.139→0.140, `onnxruntime` 1.27→1.28, the whole
OpenTelemetry stack 1.43→1.44, `anthropic` 0.116→0.120, `transformers`
5.13→5.14.

Two secondary defects in the same class:
- The `pip-audit` job installed requirements **without** `-c`, so it audited the
  newest release of every floating requirement — a set neither CI nor production
  ran. (The job's *gate* on fixable CVEs was already correct; an earlier draft of
  this finding wrongly called it non-gating. The `|| true` there is on the
  informational report, not on the gate.)
- `analytics/Dockerfile` contained `pip install fastapi>=0.115.0
  uvicorn[standard]>=0.30.0` **unquoted in a shell-form RUN** — `>` is a
  redirection operator, so the build installed *bare* `fastapi` and
  `uvicorn[standard]` and wrote the version strings into files named `=0.115.0`
  and `=0.30.0`. Completely unpinned, and silently so.

A third, orphaned `warden/requirements-lock.txt` (36 stale pins, referenced by
nothing) was a competing source of truth (conflict C-B).

Meanwhile 19 Dependabot PRs sit unmerged since March/April — the controlled
update channel is dead while the uncontrolled one was wide open.

**Status: fixed in P-0** (see §5).

**F-2 · There is no single version of record.**
`pyproject.toml` declares `version = "5.3.0"`. `README.md`, `CLAUDE.md`,
`ROADMAP.md`, `PLAN.md` and `Rule.md` all declare 7.7. `CLAUDE.md` simultaneously
documents SAC as v7.8. The packaged artefact therefore reports a version two
majors behind the product. Any customer-facing SBOM, support ticket or CVE
correlation keyed on the package version is wrong today.

**F-13 · A paid Enterprise feature has never worked in any deployed image.**

> Found on 2026-07-27 while investigating F-4's apt layer, not by looking for it.

Post-quantum cryptography (ML-DSA-65 / ML-KEM-768) is sold on the Enterprise
tier ($249/mo, "PQC + Sovereign") and gated by `pqc_enabled` in `TIER_LIMITS`.
It has been non-functional since `967303cd` (v4.7), when it was introduced.

Verified against the **running production container**:

```
find / -name 'liboqs.so*'   ->  (nothing)
pqc_status()                ->  {'available': False, ...}
```

Three independent failures had to line up, and all three are the same mistake —
a fail-open with nobody reading the output:

1. `warden/Dockerfile` ran `pip install liboqs-python`, with a comment claiming
   it "builds liboqs C library from source via cmake". It does not — that
   package is **Python bindings only**. The native library is a separate CMake
   build that was never run. The 466 MB apt toolchain in F-4 was installed
   specifically for a build that does not exist.
2. The step ended in `|| echo "⚠ liboqs-python build failed …"`, so the image
   build always succeeded regardless.
3. At import, `oqs` raises `RuntimeError: No oqs shared libraries found`.
   `warden/crypto/pqc.py` caught that in the same handler as `ImportError` and
   logged **"liboqs-python not installed"**. An operator who checked would find
   liboqs-python present in `pip freeze`, conclude the message was stale, and
   move on. *That one inaccurate log line is why this survived for months.*

`warden/crypto/pqc.py` then fail-opens: `PQCUnavailableError` on the explicit
paths, and `hybrid_verify()` "falls back to Ed25519-only if liboqs unavailable".
So hybrid signatures silently degraded to classical crypto, and
`CommunityKeypair.is_hybrid` could never be true.

**Status: fixed in P-3a** — the builder stage now compiles liboqs 0.16.0 for
real, the image **fails to build** if `ML-DSA-65`/`ML-KEM-768` are not loadable,
`pqc.py` reports bindings-missing and native-library-missing as different
problems, and `pqc_selfcheck()` (startup ERROR log + a `pqc` key on
`GET /health/pipeline`) makes the state alertable.

**Generalise the lesson:** this codebase uses fail-open deliberately and
correctly in the request path. But a fail-open on a *build* or *capability*
step, with no counter and no assertion, is indistinguishable from success. The
FAILOPEN-01 ratchet counts fail-opens in the request path only. Nothing was
watching the Dockerfile.

### P1 — fix this quarter

**F-3 · `main.py` was never finished being dissolved.**
The route-inventory guard was built specifically to make "dissolving
`warden/main.py`" safe (its own docstring says so). The file is still 3,680
lines with 23 inline routes. The safety net exists and is unused for its
stated purpose.

**F-4 · One image carries five unrelated runtimes — 4.75 GB, and ships a compiler.**
Measured on the production host (`docker history shadow-warden-warden:latest`):

| Layer | Size | What it is |
|---|---:|---|
| `pip install -r requirements.txt` | **2.09 GB** | transformers, opencv, streamlit, web3, whisper, onnxruntime, … |
| `pip install torch` (CPU wheel) | **911 MB** | used only for the ONNX export path |
| `apt-get install` | **466 MB** | gcc, g++, cmake, ninja-build, libssl-dev, astyle, git, postgresql-client |
| base `python:3.11-slim` | ~140 MB | |
| liboqs-python | 12.7 MB | |
| application code | 8 MB | the actual product |

Two separable problems:

1. **No multi-stage build.** 466 MB of *build* toolchain — a full C/C++ compiler,
   cmake and ninja — is present in the running gateway container. It is needed
   only to build `liboqs` and a few sdists. Shipping a compiler inside a security
   gateway is both weight and attack surface: it turns a file-write primitive
   into a code-execution primitive. A builder stage that discards the toolchain
   is a contained, high-value change.
2. **One image for two jobs.** `warden` and `arq-worker` run the *same* 4.75 GB
   image, but only `arq-worker` needs torch, whisper, opencv and the browser
   stack. The gateway's `deploy.limits` is 8 GB for what is a request filter.

The base is already `python:3.11-slim` and Chromium is deliberately not installed
(`BROWSER_ENABLED=false`), so neither is the cause. The weight is the Python
dependency graph plus the un-discarded build toolchain.

> Note on measuring: `docker image inspect --format '{{.Size}}'` reported
> 1.07 GB for a locally-built copy of this same image. That is a multi-manifest
> artifact, not a real size — the layer sums are the honest number. Do not size
> the image that way when checking P-3's result.

**F-5 · The money layer is built but inert.**
`LEDGER_DUAL_WRITE`, `KYB_ENFORCEMENT_ENABLED`, `SANCTIONS_SCREENING_ENABLED`,
`AML_MONITOR_ENABLED` and `AUTHORIZE_PAYMENT_ENFORCED` all default to false.
FT-6 order-model consolidation is stopped between Phase B (dual-write) and
Phase C (cutover) with **no bake deadline**, so two sources of truth for orders
coexist indefinitely and the mirror is explicitly "not yet trusted". Roughly a
quarter of Track F's delivered code is currently doing nothing in production.

**F-6 · Configuration is still half-consolidated.**
441 settings fields in a single 1,846-line `config.py`, yet 545 direct
`os.getenv` sites remain outside it (down from the 996 baseline — real progress,
but the seam is not closed). 185 env vars are wired in `docker-compose.yml`.
Behaviour is not derivable from one place.

**F-7 · Static-analysis debt is large and only frozen, not shrinking.**
830 `noqa` + 223 `type: ignore` + 200 counter-less fail-opens are *ratcheted*
(cannot grow) but have no decrement schedule. A frozen baseline is a floor, and
this floor is high enough to hide real defects.

### P2 — plan it

**F-8 · 769 public routes on a security product.** Every route is attack surface
that the product itself must defend. There is no usage-based inventory saying
which are actually called.

**F-9 · Declared memory limits (20.4 GB across 22 services) are unverified
against the node.** FM-4 shipped `audit_mem_limits()` precisely for this and it
is not wired into CI or alerting.

**F-10 · Documentation surface exceeds what anyone (human or agent) can hold.**
71 markdown files; `README.md` alone is 150 KB; `CLAUDE.md` 79 KB. Five basenames
are duplicated between root and `docs/` (`README`, `ROADMAP`, `PLAN`, `Hook`,
`CONTRIBUTING`). Three overlapping fintech plans, two architecture docs, two API
references, two roadmaps. Every stale line is a future wrong decision.

**F-11 · Language-rule violations persist in governance docs.** 360 lines
containing Cyrillic, concentrated in `MODERNIZATION_PLAN.md` (117) and
`AUDIT_REPORT_2026-07-10.md` (105), plus `warden/testing/scenarios/*` (~50) and
`output_guard.py` (18). The known do-not-translate list (detection regexes,
homoglyph map, adversarial test payloads) must be preserved.

**F-12 · Single-node topology.** R1–R6 closed backup, restore, autoheal, disk and
Redis bounds — but the VPS itself remains a single point of failure. Recovery is
proven (~17 s RTO from an offsite snapshot); *availability* is not.

---

## 4. Conflict register

These are contradictions **inside** the project — two sources of truth that
disagree. Each needs a decision, not just a code change.

| ID | Conflict | Current state | Resolution |
|---|---|---|---|
| **C-A** | Version of record | `pyproject.toml` 5.3.0 · docs 7.7 · code 7.8 | Single `warden/__version__`; everything else derives from it; CI ratchet |
| **C-B** | Dependency spec | `requirements.txt` (floating, **installed**) vs `requirements-lock.txt` (pinned, ignored) | `requirements.in` = abstract intent; compiled lock = the only thing installed |
| **C-C** | Doc namespace | 5 duplicate basenames root↔`docs/`; 3 fintech plans; 2 architecture docs; 2 API refs; 2 roadmaps | One canonical file per topic; the rest to `docs/archive/` with a redirect line |
| **C-D** | Order model | `m2m_orders`/`commerce_orders` (truth) + `marketplace_purchases` mirror (untrusted), dual-write open-ended | Set a dated bake deadline; then Phase C cutover or roll the mirror back — no third option |
| **C-E** | Shipped vs enforcing | 5 money/compliance gates default-OFF; roadmap marks the tracks "closed" | Split status into `built` and `enforced`; a track is not closed until it is enforced or explicitly deferred with an owner |
| **C-F** | Registry vs `main` | Track C rows say "PR _pending_" while `warden/finops/` (8 files) and `warden/ledger/` (8 files) are on `main` | Re-derive the registry from the code (as SR-8 already did once) and add a periodic reconciliation |
| **C-G** | English-only rule vs content | 360 Cyrillic lines, incl. the governance plan itself | Translate everything except the documented detection-payload exclusions |
| **C-H** | Stale feature PR | #167 "Feat/ft0 ledger money" open since 2026-07-19; FT-0/FT-1 already merged | Verify overlap, then close or rebase — it cannot be both |
| **C-I** | Update channel | 19 Dependabot PRs unmerged since March, while floating pins let the same upgrades in silently | Fix C-B first; then grouped weekly Dependabot batches become the *only* path |

---

## 5. Modernization plan — Track P (Platform Hardening)

Registered as a **new track `P-*`** so it obeys the existing governance rule
(no bare "Phase N"; prefixed IDs; shared-file coordination). Track P owns
build determinism, packaging, configuration, code-shape and documentation.
It never owns detection math (Track B), money semantics (Track F) or
security-control behaviour (Track A) — where it touches those files it changes
*shape*, not *semantics*, and runs the owning track's tests.

### P-0 — Deterministic builds · **P0 · DONE 2026-07-27**

Scope turned out smaller and sharper than planned, because the lockfile already
existed and only the image bypassed it.

1. ✅ `warden/Dockerfile` installs with `-c constraints.txt`; `constraints.txt`
   is COPYed into the build context. torch (`==2.13.0+cpu`, CPU index) and
   liboqs-python (`==0.16.0`, cmake source build, still fail-open) are pinned
   explicitly — they are outside the PyPI resolution by design.
2. ✅ `warden/constraints.txt` gained the 3 requirements it did not cover
   (`clickhouse-connect`, `setuptools`, `wheel`) and a header stating it is the
   single lockfile and governs the image, not just CI.
3. ✅ `analytics/Dockerfile` shell-redirect bug fixed — exact, quoted pins
   matching constraints.
4. ✅ `pip-audit` job now installs with `-c`, so it audits the set that ships.
5. ✅ Orphaned `warden/requirements-lock.txt` deleted (conflict C-B closed).
6. ✅ New ratchet `warden/tests/test_deps_pinned.py` (9 tests, hermetic — no
   network, no Docker): constraints are all `==`; every requirement is
   constrained or explicitly exempt; no constraint contradicts a requirement
   floor; every `pip install` in every Dockerfile is version-decided (by `==`,
   by `-c`, or by pointing at an already-fully-pinned requirements file); and
   exactly one lockfile exists. Verified to *fail* when the `-c` is removed.
7. ⬜ Remaining: triage the 19 Dependabot PRs; enable grouped weekly updates.

**Deploy note:** the next production rebuild converges prod *down* onto the
CI-tested set — 48 packages change, including PFI 8.1.0 → 8.0.2. That is the
point: the hotfix in `main` (`*args/**kwargs` passthrough) handles both
signatures, and the tested set is the one that should ship.

**Acceptance:** ✅ two builds of the same SHA resolve identically; ✅ an unpinned
dep fails CI; ✅ pip-audit describes the shipped artefact.

### P-1 — Single version of record · **P0 · ~0.5 day**
`warden/__version__ = "7.8.0"`; `pyproject` reads it; README/CLAUDE/ROADMAP/site
badge derive from it; ratchet asserts equality across all five.
**Acceptance:** changing the version in one place updates every surface; CI fails on drift.

### P-2 — Finish dissolving `main.py` · **P1 · 3–5 days**
Move the 23 inline routes into `warden/api/*` routers behind the existing
route-inventory guard (a pure move produces an empty diff — that is what it was
built for). Target ≤ 800 lines: lifespan, middleware, factory wiring only.
**Acceptance:** route inventory diff empty; `main.py` ≤ 800 lines; `/health/pipeline` unchanged.

### P-3 — Split the mega-image · **P1 · ~1 week**
Do it in two independent steps, cheapest first:

**P-3a — multi-stage build (~half a day, no architectural risk).** Move
`gcc/g++/cmake/ninja-build/libssl-dev/astyle` and the liboqs/sdist compilation
into a builder stage; copy only the resulting site-packages into the runtime
stage. Removes ~466 MB *and* takes the compiler out of the running container.

**P-3b — two images from a shared base.**
- `warden-api` — fastapi, onnxruntime, redis, crypto. **No** torch, opencv,
  whisper, web3, streamlit.
- `warden-tools` (for `arq-worker`) — the heavy ML/audio/chain stack.

**Acceptance:** gateway layer sums drop below 1.5 GB (measure with
`docker history`, not `image inspect` — see F-4); no compiler in the runtime
image; `/filter` p99 unchanged; the gateway's Trivy CVE count drops; the 8 GB
`deploy.limits` becomes justifiable.
**Coordinate:** Track B (ONNX export path), Track A (Dockerfile is a supply-chain surface).

### P-4 — Close the configuration seam · **P1 · ~3 days**
Split `config.py` into per-domain settings modules behind one `Settings` facade;
step the `test_no_new_scattered_getenv` baseline down from 545 in tranches.
**Acceptance:** baseline strictly decreasing each merge; no behaviour change.

### P-5 — Debt burn-down schedule · **P1 · continuous**
Convert the three frozen baselines (830 `noqa`, 223 `type: ignore`, 200
counter-less fail-opens) into **decrementing** ratchets: −10% per quarter, the
number lowered in the same PR that removes the suppressions. No big-bang.
**Acceptance:** each baseline file's number is lower at quarter end; ratchets stay green.

### P-6 — Finish or roll back the half-migrations · **P1 · decision + ~2 weeks**
Two open-ended states must get dated deadlines:
- **FT-6 Phase C/D** — bake period end date, then cut reads over to
  `marketplace_purchases` and freeze the blob tables, or revert the mirror.
- **FT-2 read-cutover** — run `LEDGER_DUAL_WRITE=true` in prod for a defined
  window with `credit_drift()` on a dashboard; zero drift ⇒ flip; otherwise fix.

Same for the four default-OFF compliance gates: each gets an owner and a date to
be enforced or formally deferred.
**Acceptance:** no migration is in "dual-write, indefinitely" state; every
default-OFF gate has a dated decision.
**Coordinate:** Track F owns semantics; Track P only supplies the deadline discipline.

### P-7 — Documentation consolidation · **P2 · ~2 days**
One canonical doc per topic; superseded plans to `docs/archive/` (kept, not
deleted — they are decision history); `README.md` cut to an overview plus links;
resolve the 5 duplicate basenames; finish the Russian-copy cleanup honouring the
do-not-translate list.
**Acceptance:** no duplicate basenames; `docs/index.md` links every live doc; zero Cyrillic outside the exclusion list.

### P-8 — API surface reduction · **P2 · ~1 week**
Derive a usage inventory from access logs across all 769 routes; deprecate the
unused, tier-gate the rest, publish a deprecation window.
**Acceptance:** every route is either exercised by a test *and* observed in
logs, or scheduled for removal.

### P-9 — Capacity truth & HA path · **P2**
Wire FM-4's `audit_mem_limits()` into CI and Grafana alerting against the real
node's RAM. Then decide explicitly: stay single-node (accept the availability
ceiling, document it against the 99.9%/99.95% SLA) or add a second node.
**Acceptance:** over-commit is alertable; the SLA doc states the real topology.

### P-10 — CI workflow decomposition · **P2 · ~2 days**
Break the 58 KB / 18-job `ci.yml` into reusable workflows; move every advisory
`|| true` step into a clearly-named non-blocking job so a reader can tell at a
glance what actually gates a merge.
**Acceptance:** no `|| true` inside a gating job; `ci.yml` ≤ 15 KB.

---

## 6. Sequencing

```
Week 1   P-0 ─ P-1                    (build determinism + version of record)
Week 2   P-2 ─┐
Week 3   P-3  ├─ P-4                  (shape: main.py, images, config)
Week 4   P-3 ─┘   P-6 decision gate   (deadlines for the half-migrations)
Week 5+  P-7, P-10, then P-8, P-9     (surface + docs + ops)
P-5 runs continuously from week 1, one decrement per merge.
```

**Do P-0 first and alone.** Until builds are deterministic, every other
measurement in this document — coverage, CVE counts, latency, image size — is
taken against a runtime that may differ from what production actually runs.

---

## 7. Explicitly *not* recommended

- **Do not** start a new feature track. The problem is unfinished industrialization,
  not missing capability. 769 routes is already past the point where more surface helps.
- **Do not** big-bang the suppression debt. 1,053 suppressions removed in one PR
  is unreviewable; the ratchets exist so it can be done incrementally.
- **Do not** weaken any fail-closed gate to simplify P-3/P-4. Track P changes
  shape only; `agentic_gate()`, `resolve_key()`, STAFF-01/02 and the x402
  fail-open posture are out of scope by construction.
- **Do not** delete superseded plan documents. Archive them — they are the
  decision record that made the SR-8 reconciliation possible.
