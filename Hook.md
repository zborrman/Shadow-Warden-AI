# Hook.md — Commit-time and merge-time guards

Every automated check that stands between a change and `main`, and which file
implements it. The M2M Agentic Marketplace section (§3) is the one that guards
the money path.

---

## 0. What this document described for months, and did not have

Until this revision Hook.md catalogued ten shell hooks living in a `.hooks/`
directory: `check-stage.sh`, `check-user.sh`, `check-context.sh`,
`scan-vulnerabilities.sh`, `check-rotation-redis.sh`, `check-gdpr-content-log.sh`,
`check-whitelist-schema.sh`, `check-smb-compose.sh`, `check-ruff.sh`,
`check-mypy.sh`, each with a full script body and a `.pre-commit-config.yaml`
snippet.

**`.hooks/` has never existed in this repository, and not one of those ten ids
appears in `.pre-commit-config.yaml`.** The file was a proposal written in the
present tense. It was load-bearing anyway: `warden/hooks/smb_perimeter.py` opens
by naming `CONTRIBUTING.md:201` and `Hook.md:263` as the two documents that
described a `check-smb-compose` guard *for months* while nothing implemented it —
"the least-protected deployment profile in the repo was the one with zero
automated checks, while two documents said otherwise."

This is the same defect class the project has now hit in six places: a rule with
no caller, a gauge with no writer, a table with no reader, a DDL memo that never
committed. The lesson is always identical and it is the rule this file now
follows:

> **An entry belongs in Hook.md only once a caller exists.** Every row names the
> file that implements the guard and the regression it would have caught. A
> guard that is planned goes in §6 — "Not built" — and nowhere else.

Ruff, mypy and Trivy are not lost; they run, but as upstream pre-commit hooks and
CI jobs, not as the local shell scripts that were described, and they are
recorded below where they actually live. **`hadolint` and the GDPR content-log
check are not implemented anywhere** — they are in §6 with the other guards that
do not exist, which is the only honest place for them.

---

## 1. Where the wall is

CI (`.github/workflows/ci.yml`) runs **pytest, ruff, mypy and a Docker smoke
build**. It does not run `pre-commit`. That single fact decides how to read
everything below:

| Layer | Runs | Blocks a merge? | Purpose |
|---|---|---|---|
| `.pre-commit-config.yaml` | locally, on `git commit`, only if the developer ran `pre-commit install` | **No** | fast feedback, seconds after the edit |
| `warden/tests/test_no_*.py`, `test_*_ratchet`-shaped tests | in CI, as ordinary pytest | **Yes** | the real wall |
| `.github/workflows/warden-scan.yml` | on every push/PR | Yes (`fail-on: BLOCK`) | Shadow Warden's own 9-layer filter over the diff |
| `.github/workflows/claude-security-review.yml` | on PRs touching security-critical files | comment only | Opus audit of the diff |

So a guard that exists **only** in `.pre-commit-config.yaml` protects nobody who
has not installed pre-commit. Three of the five local hooks below say so in
their own comments, and each has a pytest twin that is the actual gate.

```bash
pip install pre-commit
pre-commit install          # once per checkout — nothing enforces this
```

---

## 2. Pre-commit hooks that actually run

From `.pre-commit-config.yaml`.

### Upstream

`check-added-large-files`, `check-case-conflict`, `check-json`,
`check-merge-conflict`, `check-toml`, `check-yaml`, `debug-statements`,
**`detect-private-key`**, `end-of-file-fixer`, `mixed-line-ending`,
`trailing-whitespace`; then `ruff` + `ruff-format`, `mypy`, `bandit`, and
`detect-secrets` against `.secrets.baseline`.

`detect-secrets` was red at baseline for a long time on 22 known-benign findings,
which trains everyone to ignore it — the fingerprints in `.gitleaksignore` and
the baseline exist so a *new* finding is the only red.

### Local (`warden/hooks/*.py`)

| id | Implementation | Catches | Merge gate |
|---|---|---|---|
| `idempotency-key` | `warden/hooks/idempotency.py` | a charge / refund / subscription call with no `idempotency_key` argument | — |
| `fail-open-lint` | `warden/hooks/fail_open.py` | `except …: pass`, or a bare return out of an except block with no logger call | `test_no_new_silent_except.py`, `test_no_new_counterless_failopen.py` |
| `check-smb-compose` | `warden/hooks/smb_perimeter.py` | SMB profile perimeter — published ports, required env, tier services | `test_smb_perimeter.py` |
| `dashboard-honesty` | `warden/hooks/dashboard_honesty.py` | a SOC dashboard page rendering an invented number on the permanent path when the API is unreachable | `test_dashboard_honesty.py` |
| `tenant-isolation` | `warden/hooks/tenant_isolation.py` | a query in `warden/api/` with no `tenant_id` filter — **advisory, warns only** | — |

`dashboard-honesty` exists because five of twenty-six dashboard pages substituted
fabricated values for live data on the permanent render path, not while loading.
The site did the same thing with agent counts. Which is exactly why §3's
storefront guard is shaped the way it is.

---

## 3. M2M Agentic Marketplace guards

The marketplace is the platform's thesis and its only path to money movement.
Its rules are canonical in **`warden/marketplace/CLAUDE.md`** (31 numbered
rules); this section lists what *enforces* them. Every row below is a pytest
file in `warden/tests/` that runs in CI.

Read the column on the right first. Each of these was written after the defect
shipped — none is hypothetical.

### Identity and authority

| Guard | Pins | The regression it exists for |
|---|---|---|
| `test_marketplace_route_auth.py` | rule 24 — every write route under `/marketplace/*` carries `require_api_key` | A `_KNOWN_OPEN` frozenset that may only **shrink**: a new unauthenticated write route fails, and a route that gets fixed must be deleted from the baseline so it cannot silently reopen (`test_known_open_baseline_has_not_gone_stale`). There is **no global auth middleware** in `main.py`, so a router that forgets the dependency is open to the internet. A flat assertion would have to be skipped — first-contact registration is open on purpose — and a skipped test protects nothing. **Scope:** FastAPI routes on `api.shadow-warden-ai.com`. It does not reach the Worker at `marketplace.shadow-warden-ai.com` (H-8), and it inspects *dependency callables*, not runtime behaviour (H-9). |
| `test_marketplace_offer_signing.py` | rule 1 — every offer is Ed25519-signed | `_verify_offer_signature()` existed and was **called from nowhere**; every stored signature was `''`. With an unauthenticated router that let a $1000 listing settle at $0.01 by impersonating the seller on accept. |
| `test_marketplace_payout_address_binding.py` | rule 28 — only the agent's own signature writes `payout_address` | An agent is an Ed25519 key; a trade settles to a secp256k1 address and nothing derives one from the other. Whoever writes that column decides where a seller is paid — a theft primitive. The unsigned writer it replaced had **zero callers**, so no seller could ever be paid at all. Fail-CLOSED, no enforcement flag. |
| `test_x402_signed_identity.py` | x402 payer identity is proven, not claimed | Strix drained a victim's prepaid balance with `base64({"agent_id": victim})` in `PAYMENT-SIGNATURE`. The gate trusted the claimed id. |
| `test_marketplace_worker_identity.py` | the **Worker's** DID derivation equals the gateway's, and its registration refuses an existing DID | The only ratchet in this table that is not about FastAPI. Its first half executes `did.ts` under node against `pubkey_to_agent_id()`: two implementations of an identity function that disagree are worse than one, because the same key would name two different agents and a signature verified on one surface would not verify on the other — which no source-grep can see. The rest are source ratchets, each naming the exact string that was the defect. See H-8 for what it still does not cover. |
| `test_marketplace_payout_address_binding.py` (`test_reregistering_*`, `…_answers_409_…`) | rule 29 — registration never mutates an existing agent | Registration is unauthenticated by design and `GET /agents/{id}` publishes the public key, so a stranger could re-register a victim's key: `tenant_id` reassigned, suspension lifted, `payout_address_signed_at` wiped — which silently disabled rule 28's rollback guard. `test_api_agents.py` had passed for months *by using the takeover as a fixture* (one module-scoped key, re-registered under a fresh tenant per test). |

### Money movement

| Guard | Pins |
|---|---|
| `test_purchase_escrow_atomicity.py` | purchase + escrow in one transaction. The `_db_lock` that appeared to guard it is an in-process `RLock`, and `arq-worker` writes the same database from another container. |
| `test_clearing_idempotency.py` | a retried `POST /clear` does not double-clear. `INSERT OR REPLACE` masked the bug because every row had a fresh UUID PK, so nothing ever collided. |
| `test_clearing_authorize_payment.py` | `authorize_payment()` runs **before** `_reject_losers()`, so a DENY cannot leave sibling negotiations marked `cleared_by_market` for a clearing that never happened. |
| `test_marketplace_money_schema.py`, `test_no_new_real_money_columns.py` | no new `REAL`-typed money column. Float money cannot reconcile to zero; the ledger core is integer micro-USD. A may-only-drop baseline — 40+ legacy columns drain under FT-2 rather than being rewritten. |
| `test_marketplace_autonomy.py`, `test_marketplace_kya.py`, `test_marketplace_kyb.py` | L1/L2/L3 `check_action()`, the KYA default-policy grant (rule 26) and KYB capping. The grant is what turned `AUTHORIZE_PAYMENT_ENFORCED=true` from a kill switch into a posture decision. |

### Settlement

| Guard | Pins |
|---|---|
| `test_escrow_settlement_wiring.py` | `settlement_mode` derives from capability, not from an RPC URL — `BASE_RPC_URL` defaults to a public endpoint, so "configured" was always true and production advertised `onchain` with $0 settled. Also: the real transaction path **fails CLOSED**; the stub returned True on every error, making a release that never reached the chain indistinguishable from one that did. |
| `test_escrow_abi_matches_callers.py` | the compiled ABI and the Python callers agree. The hand-written ABI omitted all six custom errors, so every revert would have decoded as an unnamed failure with funds in the contract. |
| `test_escrow_honours_settlement_result.py`, `test_escrow_remembers_what_it_sent.py` | rule 30 — a `TradeExists()` revert on `deposit` means *our* trade is funded, and `fund_tx`/`deliver_tx`/`settle_tx` are written once and never overwritten. |
| `test_escrow_state_machine.py`, `test_escrow_contract_on_evm.py`, `test_deploy_escrow_script.py` | the state machine and the deploy script executed on py-evm in CI. A deploy script that has only ever been read is a plan — and it fails *after* the first transaction has landed. |
| `test_escrow_columns_on_old_tables.py` | the migration runs on the connection it is given. Builds the pre-#403 table on purpose: a fresh `tmp_path` database can never reproduce a migration bug. |

### Performance, posture and claims

| Guard | Pins |
|---|---|
| `test_marketplace_migration_memo.py` | rule 27 — migrations run once per process, not per connection. **Asserts statement counts, not results**: on local SQLite the defect is microseconds and invisible, but the production DB is on Turso where every statement is an HTTPS round trip — `GET /marketplace/listings` took **9.5 s** to return an empty list against a `/health` of 10 ms. |
| `test_marketplace_posture_visibility.py` | the system does not report a stronger posture than it has (MP-6/MP-7) — `AUTHORIZE_PAYMENT_ENFORCED` off must read as off. |
| `test_site_marketplace_storefront.py` | the storefront **shows what the gateway said, or says it could not read it**. `/marketplace` was a 301 to `/agentic`; the product had no public surface. An empty market is exactly where an illustrative number gets invented. |
| `test_agent_card_truth.py` | `/.well-known/agent.json` fields are true, not merely present. It advertised `version: 5.6.0` against a 7.9.0 gateway, and `enabled: "false"` as a **string** — which every consumer language reads as true, so a disabled payment gate advertised itself as enabled. |
| `test_public_claims_reconciled.py` | every published surface (`site/`, `landing/`, `portal/`, `dashboard/`, `docs/`) against the banned-claims block in `docs/capability-matrix.md`. The test holds no list of its own, so there is no second copy to drift. |
| `test_marketplace_sybil_gate.py`, `test_marketplace_admin_guard.py`, `test_marketplace_sanctions.py`, `test_marketplace_injection_consolidation.py` | rules 4, 19, 22 and the injection scanner consolidation (MP-2 — `injection_guard.scan_negotiation_message()` was dead at 0% coverage while a weaker private matcher ran). |

---

## 4. Cross-cutting ratchets the money path depends on

Not marketplace-specific, but a marketplace change trips them:

| Guard | Pins |
|---|---|
| `test_no_new_raw_signing_key.py` | any key you *sign* with resolves through `secret_keys.resolve_key(..., purpose=…)`, per call, and **raises** when unresolvable. An unset `MANDATE_SECRET` once accepted unsigned payment mandates. |
| `test_no_raw_sqlite_connect.py` | module DBs open through the DDL-registry seam. Down to 2 legitimate sites (the `Connection.backup()` src/dst pair). |
| `test_no_ghost_table.py`, `test_no_ghost_column.py`, `test_no_ghost_database.py` | no table, column or database that nothing writes. Same class as a gauge with no writer: an empty read looks like a measurement. |
| `test_no_new_counterless_failopen.py` | a fail-open path increments a counter. A silent fail-open is an outage nobody can see. |
| `test_pricing_coherence.py` | one price list. Three copies had drifted a full tier apart — a year of Pro sold for $703 against a $1 199.88 list. |
| `test_no_new_latency_claim.py` | no published latency number without an instrument behind it. |
| `test_route_inventory.py` | the route inventory; `test_marketplace_route_auth.py` mirrors its enumeration deliberately, because `app.routes` does not flatten includes and a shadowed duplicate once left `/ws/events` unauthenticated. |
| `test_env_no_duplicate_keys.py` | compose takes the **last** duplicate key — a real NVIDIA key was once shadowed by a placeholder. |

---

## 5. Running them

```bash
# Local, fast
pre-commit run --all-files

# The marketplace suite (the wall)
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" ANTHROPIC_API_KEY="" \
LOGS_PATH="/tmp/warden_test_logs.json" DYNAMIC_RULES_PATH="/tmp/dr.json" \
REDIS_URL="memory://" MODEL_CACHE_DIR="/tmp/warden_test_models" \
python -m pytest warden/tests/test_marketplace*.py warden/tests/test_escrow*.py \
                 warden/tests/test_x402*.py warden/tests/test_clearing*.py \
                 -v --tb=short --no-cov

# The ratchets, before any push (they fail for reasons the diff does not show)
python -m pytest warden/tests/test_route_inventory.py \
                 warden/tests/test_no_new_counterless_failopen.py \
                 warden/tests/test_no_new_suppressions.py \
                 warden/tests/test_pricing_coherence.py \
                 warden/tests/test_public_claims_reconciled.py -q
```

Do **not** share `MARKETPLACE_DB_PATH` across test classes — concurrent writes
corrupt SQLite. Use `tmp_path` per class.

---

## 6. Not built — the guards the marketplace still lacks

Listed here, and deliberately not above, because nothing implements them. Each
is a real gap found while reconciling this file against the repo.

| # | Gap | Why it matters | Shape of the fix |
|---|---|---|---|
| H-1 | **No guard that a posture flag reaches the container.** `warden` has no `env_file`, so `MARKETPLACE_REQUIRE_SIGNED_OFFERS`, `ESCROW_SETTLE_CHAINS` and `AUTHORIZE_PAYMENT_ENFORCED` need an explicit `${…}` passthrough in `docker-compose.yml`. Seven of eight enforcement flags were once set in `.env` and silently never read. | A flag set and not delivered reads as enforcement in every document and is a no-op in production. | **Not a name pattern.** The obvious matcher — `*_ENFORCED` plus `REQUIRE_*` — catches `AUTHORIZE_PAYMENT_ENFORCED` and misses both `ESCROW_SETTLE_CHAINS` and `MARKETPLACE_REQUIRE_SIGNED_OFFERS`, so a test written that way would pass while two of the three flags it was built for went undelivered: a guard that looks like coverage and is not, which is the defect this whole file exists to stop. The set has no shared spelling (`X402_GATE_ENABLED`, `KYB_ENFORCEMENT_ENABLED`, `SANCTIONS_SCREENING_ENABLED`, `OVERAGE_CHARGE_ENFORCED`, …). Enumerate the posture flags explicitly in the test and assert a `${…}` passthrough for each; adding a flag means adding a line, and that cost is the point. |
| H-2 | **Nothing asserts a marketplace write route also proves *agent* identity.** Rule 25 says an API key authenticates a tenant, not an agent; `test_marketplace_route_auth.py` only checks the key. | A route that reads `from_agent_id` from the body without a signature is the $0.01 settlement bug in a new place. | Extend the route-auth ratchet with a second baseline: routes taking an agent id in the body and *not* calling `_assert_actor()`. |
| H-3 | **No CI mutation gate on the money modules.** `mutmut` is configured for 5 modules and commented out of `ci.yml`; `marketplace/x402_gate.py` carries 259 surviving mutants. | The suite's strength on the money path is unmeasured between manual sweeps. | Not a PR gate (too slow) — a weekly scheduled sweep whose survivor count is a ratchet. |
| H-4 | **No guard on `settlement_mode` truth at the edge.** `test_escrow_settlement_wiring.py` pins the derivation; nothing checks what the *deployed* manifest answers. | It has been wrong in production twice, both times by configuration rather than by code. | Add the assertion to `scripts/capability_probe.py`'s production run, which already checks PQC and SDK resolution. |
| H-5 | **`tenant-isolation` warns and never blocks**, and has no pytest twin. | Cross-tenant leakage has already shipped once in dashboard routes. | Give it a may-only-shrink baseline like the route-auth ratchet, then make it blocking. |
| H-6 | **`hadolint` is still unimplemented**, promised in the old §6 ToDo. Trivy does run (`trivy-action` in CI); no Dockerfile linter does. | Dockerfile drift — the base-image half is covered, the authoring half is not. | `hadolint` as a pre-commit hook on `Dockerfile*`. |
| H-7 | **Nothing enforces the GDPR content-never-logged invariant.** `CLAUDE.md` names it a protected invariant and the old Hook.md described a `check-gdpr-content-log` guard for it; `test_gdpr_endpoints.py` and `test_gdpr_idor.py` cover the export/purge routes and IDOR, not logging statements. | Content reaching a log line is the single hardest requirement in the product to undo once shipped — logs ship to Loki, MinIO and a SIEM. | An AST hook in `warden/hooks/` over `log.*()` calls carrying `content`/`text`/`body`/`prompt`, with a may-only-shrink baseline and a pytest twin, since CI does not run pre-commit. |
| ~~H-9~~ | **Closed** by `test_marketplace_auth_actually_denies.py`. No test had ever watched the marketplace auth gate refuse anybody: the ratchet inspects dependency callables, and the documented way to run the suite sets `WARDEN_API_KEY=""`, where `require_api_key` returns a default `AuthResult` for every caller. | Wiring and enforcement are different claims — three of the four anti-patterns in `Rule.md` §29.1 are a control that is present and permits everyone. | Done: a configured key, `ALLOW_UNAUTHENTICATED` shut, three requests — missing **401**, wrong **401**, configured **422** (auth ran, passed, validation rejected a deliberately invalid body). The fourth assertion carries as much as the first two: a gate that refuses its own credential passes both denial tests while protecting nothing usable. Subprocess, because `_VALID_KEY` binds at import; fails loudly rather than silently when the key does not reach the module, which is what it does under the suite's own env. |

---

*Rewritten 2026-09-19 against the repository as it is. Previous revision
(2026-05-16, v4.20) described ten hooks that were never installed; see §0.*
