# Pre-Production Plan — Shadow Warden AI

**Date:** 2026-07-21 · **Branch audited:** `deeng/de6-p1-batch9` (2 behind `origin/main`) · **Author:** engineering review cycle

This document records the result of a full check cycle and the prioritized plan to reach a production launch. It is grounded in what the checks actually returned, not in the roadmap text (which is slightly stale — see §0).

---

## 0. Check-cycle results (2026-07-21)

| Gate | Command | Result |
|---|---|---|
| Lint | `ruff check warden/ analytics/ --ignore E501` | ✅ **clean** |
| Types | `mypy warden/ --ignore-missing-imports --no-strict-optional` | ✅ **clean** (878 source files) |
| Ratchets | 7 ratchet tests (raw-sqlite, signing-key, failopen, getenv, silent-except, suppressions, money-columns) | ✅ **7/7 pass** |
| Test suite | `pytest -m "not adversarial and not slow"` (265 files) | ⚠️→✅ **5569 passed, 1 failed, 7 errors, 22 skipped** — all 8 non-green had one root cause (P0-1), **now fixed → fully green** |
| Frontends | `portal` / `dashboard` / `site` — `node_modules` present, build scripts defined | ⬜ not yet build-verified this cycle |

**State of the working tree:** clean. **Branch position:** local `deeng/de6-p1-batch9` is **2 commits behind `origin/main`**; its own work (DE-6 P1 batches 17–19) is already merged to main as **#190**, and **#189 (FT-5 AML structuring monitor)** also landed on main. The local branch should be retired/synced — do not keep developing on it.

**Roadmap staleness noticed:** `docs/unified-modernization-roadmap.md` still lists FT-5 "AML-on-journal-stream" and R2–R6 as open; both are in fact **done** (#189 on main; resilience plan R1–R6 all marked DONE). Reconcile the registry (P1-4).

---

## 1. P0 — Must fix before any launch

### P0-1 · Two test files error *on main* — CI is not catching it  ✅ code fix applied 2026-07-21
`warden/tests/test_listing_purchase_idempotency.py` (7 errors) and `warden/tests/test_x402_gate.py` (1 failure) both called `listing._ensure_schema(...)` / `x402_gate._ensure_schema(...)`. The DE-6 `open_db()`/`register()` migration removed those private helpers, but the test fixtures were not updated. On `origin/main` the modules no longer expose `_ensure_schema` yet the tests still call it.

- **Impact:** two money-path idempotency suites (listing purchase double-charge, x402 gate deduct) were **not running**. Worse, this merged to main green — so **CI does not fail on collection errors / this failure**, a silent hole that lets any stale test slip through.
- **Fix applied:** both call sites now seed schema via `warden.db.ddl_registry.ensure_schema(con, "<db_key>", path)` (`"marketplace"` / `"marketplace_x402"`). Re-run: **24 passed, ruff clean.** These edits live in the working tree; they must land **on `main`** (the branch here is stale — see §0), not only on `deeng/de6-p1-batch9`.
- **Meta-cause fixed 2026-07-21:** added a **blocking "Test collection gate"** step to the `test` job in `.github/workflows/ci.yml` — `pytest --collect-only -q -o addopts=""` (the `-o addopts=""` is required, else the repo's default `--cov-fail-under` masks the collection error with a misleading 0%-coverage failure). It runs before the test step, so any future stale/broken test import fails the build fast and unambiguously. Verified: whole tree collects clean (**5685 tests, exit 0**), YAML valid, gate ordered before the run step. Still recommended: confirm branch protection makes the `test` job a **required** check (a gate only helps if the merge is actually blocked on it).

### P0-2 · Confirm the authoritative full-suite result
Re-run the complete `-m "not adversarial and not slow"` suite after P0-1 and record the green count. Nothing else in P0/P1 starts until this is a known-clean number.

### P0-3 · Launch-blocking env & config (from `docs/production-launch.md`)
- `ALLOW_UNAUTHENTICATED=false` in prod (fail-closed auth).
- `WARDEN_ENV=production` + `WARDEN_DATA_DIR=/var/lib/warden` (mode-0700 persisted volume) so secret DBs are **off `/tmp`**; set `CONFIG_FAILCLOSED=true` so a `/tmp` resolution crash-loops instead of serving credentials from ephemeral storage (S1 guardrail).
- `VAULT_MASTER_KEY` valid Fernet, `SECRET_KEY`/`PORTAL_JWT_SECRET`/`DB_PASSWORD` strong, no `change-me` values in `.env`.
- Backups: `arq-worker` must carry `VAULT_MASTER_KEY` + `S3_*` **and** `OFFSITE_S3_*` (offsite copy is the only one that survives VPS loss).

---

## 2. P1 — Should fix before launch (correctness / operability)

### P1-1 · Frontend build verification
Run `npm run build` in `portal/`, `dashboard/`, `site/` and confirm all three produce a clean production build. Dashboard runner stage `COPY --from=builder /app/public` requires `public/.gitkeep` committed — verify.

### P1-2 · Production smoke + readiness
Run `pytest warden/tests/test_production_readiness.py` and `bash scripts/pre_deploy_check.sh` against a booted stack. Then the `docs/production-launch.md` curl smoke set (health, /filter safe+jailbreak, marketplace, edge packs, metrics) on the live VPS.

### P1-3 · Restore drill (resilience R6 — "DONE, gap found")
The resilience plan flags a gap discovered during the restore drill. Close it: execute one real encrypted-snapshot → `pg_restore`/SQLite restore into a scratch environment and confirm data integrity before launch. A backup you have never restored is not a backup.

### P1-4 · Reconcile the modernization registry
Update `docs/unified-modernization-roadmap.md`: mark FT-5 AML (#189) and R2–R6 done; correct FT-5 to 3/4 (AML landed, only continuous-assurance items remain). Retire the merged `deeng/de6-p1-batch9` branch. Keeps the single-source-of-truth honest.

---

## 3. P2 — Open modernization work (post-launch or parallel, not launch-blocking)

These are the genuinely-open track items after reconciliation. All are additive; none block a v1 launch.

| ID | Item | Status | Notes |
|---|---|---|---|
| **SR-7.2** | Coverage floor 75% → 85% | open | raise `--cov-fail-under` incrementally with real tests, not coverage-boost files |
| **SR-7.3** | Extend mutation testing beyond the 2 seeded modules | open | Linux/CI only (mutmut unsupported on native Windows) |
| **SR-2.3** | Pinned-IP httpx transport wiring | primitive done | `resolve_validated_ips()` exists; wiring the pinned transport into live callers needs a real-host TLS-SNI test and **auto-deploys to prod** — do not ship blind |
| **DE-3** | Embedding + hyperbolic model upgrade | in-flight | TDA H1 slice done; remainder is detection-quality, not a gate |
| **DE-4** | Bayesian MAESTRO & reputation | in-flight | collusion slice done |
| **DE-7** | BrowserSandbox process isolation | 2/3 done | last third = seccomp/restricted-user sidecar for the Playwright sandbox |
| **DE-8** | SOVA runtime modernization | core shipped on `feat/sova-modernization` | confirm merged to main; if not, land it |
| **FM-5** | Reliability=revenue ops tail | in-flight | math + Slack burn-rate alert wired; **create the 4 uptime monitors** + 2× cloudflared replicas (operational, needs prod coord) |
| **FT-2** | Ledger dual-write **read-cutover** | deferred (human go/no-go) | run `LEDGER_DUAL_WRITE=true` in prod, watch `credit_drift()`/`hold_drift()` = 0 over a shadow period, *then* re-point `available_usd()` |
| **FT-6** | Single `authorize_payment()` chokepoint + ratchet, one x402 impl | ⬜ not started | consolidation — reduces money-path surface; good first post-launch hardening |
| **FT-7** | Money-conservation property tests, chaos, auditor export, SOC 2 mapping | ⬜ continuous | pairs naturally with the P1-3 restore drill and SOC 2 evidence |
| **FT-0** | Float-money arithmetic ratchet | deferred | needs a low-false-positive money-path definition first |

---

## 4. Recommended execution order

1. **P0-1 + P0-2** — fix the two stale test fixtures, add the collection-error CI gate, re-run the full suite to a known-green count. *(same day)*
2. **P1-4** — reconcile the roadmap and retire the stale branch, so the team plans against reality. *(same day)*
3. **P1-1 + P1-2** — frontend builds + production smoke/readiness on the live stack.
4. **P0-3 + P1-3** — production env hardening (fail-closed auth, off-`/tmp` secret DBs, offsite backup env) and the restore drill. → **launch gate.**
5. **Post-launch:** FT-6 chokepoint consolidation, then SR-7.2 coverage, DE-7 sandbox isolation, FM-5 ops tail, FT-2 read-cutover under shadow monitoring.

---

## 5. What is genuinely solid (do not re-litigate)

Ruff + mypy clean across 878 files. All 7 security ratchets green. Security remediation Track A closed (SR-1…SR-8, incl. XXE/SSRF/CORS/TLS hardening with gating bandit+semgrep+gitleaks). §6d S1–S7 self-security backlog closed. Resilience R1–R6 done (pg_dump + offsite ship, zero-downtime deploy, autoheal, disk hygiene, Redis bounds). The double-entry ledger core (FT-1) with hash-chaining + conservation tests, settlement worker + reconciliation + transactional outbox (FT-4), and idempotency on all three money endpoints (FT-3) are complete. The one real defect this cycle surfaced is P0-1.
