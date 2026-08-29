# Launch Programme — from security platform to working marketplace

**Baseline 54/100 · target 82/100 · six gated phases · ~20 weeks.**
Opened 2026-08-18. Canonical companion: `docs/capability-matrix.md`.

The engine is production-grade. The market it serves does not exist yet: zero
registered users, zero listings, zero settled trades, no live payment rail. This
programme closes that gap, ordered so each phase unblocks the next.

Phases are numbered because they are genuinely sequential — each entry gate is
the previous phase's exit evidence. Two exceptions: **P2** runs alongside P1a,
and **P1b** is gated on a company rather than on a phase, so it lands whenever
the entity exists and blocks nothing. No phase is complete on effort spent, only
on its exit criteria being demonstrably true in production.

---

## Why this order

The audit that opened the programme found the spread, not the average, to be the
diagnosis. Categories owned by engineering discipline score in the 80s; every
category requiring contact with a paying counterparty scores below 30:

| Category | Score | Binding constraint |
|---|---:|---|
| Core security engine | 88 | `fail_strategy: open`, `strict: false` in production |
| Test & quality engineering | 84 | 786 surviving mutants; one CPT gate link dead by construction |
| Observability & SRE | 80 | Evidence Vault off (`S3_ENABLED=false`) |
| M2M protocol architecture | 76 | 16 actions defined, none exercised by an external agent |
| Compliance & legal | 68 | Entirely self-attested; no auditor engaged |
| Trust & identity (KYA/KYB) | 62 | Complete and tested, never run against a real counterparty |
| Data layer & scale | 56 | 30 SQLite files on one VPS; Postgres carries probe data only |
| Frontend & UX | 52 | Four overlapping surfaces, duplicated IA, no i18n |
| Developer experience & SDKs | 44 | Four SDKs written, none published; no API versioning |
| Money rail & settlement | 28 | Testnets only; no fiat provider; both enforcement flags off. Split into P1a (crypto, no entity needed) and P1b (fiat, needs one) |
| Customer service operations | 22 | No ticketing; SLA promises credits with no mechanism |
| Commercial traction | 10 | Zero of everything indicating a market exists |

That is a sequencing problem, not a capability problem. Hence: money rail before
market seeding, market seeding before service operations, service operations
before scale.

---

## P0 — Truth and freeze · +3 · week 0–1

**Entry gate:** none. Blocks everything else.

Stop the growth of surface area and publish an honest account of what is
simulated. The live exposure is selling "high security, escrow-backed" over an
escrow that settles nothing.

**Worse than the audit recorded (found 2026-08-21).** `GET /marketplace/protocol`
was not answering `settlement_mode: simulated` at all — production answered
`onchain`, because the field flipped on *any* configured RPC and production has
`WEB3_RPC_URL` pointing at Sepolia. A foreign agent reading the manifest was
told this market settles on-chain, on the strength of free test tokens. Repaired:
`onchain` now requires a chain in `MAINNET_CHAINS`, `testnet` is its own state,
and `escrow.chains` is derived from configuration rather than hard-coded.

| Workstream | Detail |
|---|---|
| Feature freeze | No new routers, subsystems or frontend surfaces. Recorded in `CLAUDE.md` so the autonomous loop honours it too. |
| Capability matrix | `docs/capability-matrix.md`: every public claim mapped to real / testnet / simulated / self-attested. Site copy reconciled against it. |
| Evidence Vault on | `S3_ENABLED=false` while the SOC 2 material cites the vault. Enable, verify a bundle lands in MinIO and offsite. |
| Posture written down | `fail_strategy: open` and `strict: false` are defensible — but as a documented decision with an alerting story, not an unexamined default. |
| Baseline instrumentation | One dashboard with the six numbers that define the business. All currently zero; make the zero visible daily. |

**Exit criteria**
- [x] Capability matrix published; every public claim reconciled against it.
      Reconciled and **enforced** 2026-08-28. The matrix always named the claims
      to remove; nothing made removal stick — `"SOC 2 compliant"` was struck from
      `AuthModal.astro` and survived untouched on the portal signup CTA, and a
      `Sub-3ms` latency nothing instruments survived in `FeaturesGrid.astro`. Both
      removed. `docs/capability-matrix.md` now carries a machine-readable
      ```banned-claims``` block, and `test_public_claims_reconciled.py` greps every
      published surface (`site/src`, `landing/`, `portal/src`, `dashboard/src`)
      against it — the test holds no list of its own, so there is no second copy to
      drift. Verified red against the pre-fix files. `scripts/capability_probe.py`
      re-run against production the same day: pipeline OK, PQC OK, SDKs resolve,
      `settlement_mode: simulated` (honest, and P1a's open item).
- [x] An evidence bundle written to MinIO and to the offsite bucket, verified by hand.
      MinIO half done 2026-08-21: generated, landed at `bundles/…json`, read back
      through the S3 API, `verify` returns `valid: true`. Offsite half built
      2026-08-22 — `ship_evidence_bundles()` mirrors the vault encrypted into
      `evidence-bundles/` from the nightly 03:30 job.
      **Confirmed by hand 2026-08-28**, and not by the file merely existing:
      both bundles listed in the offsite bucket (written 2026-08-23 03:30), one
      downloaded, Fernet-decrypted with `VAULT_MASTER_KEY`, parsed as JSON (12
      keys, `bundle_hash: sha256:2a46aef4f…`), and compared field-by-field
      against the MinIO original — **identical**. A copy that cannot be read
      back is not a backup, which is the lesson the R6 drill already paid for.
- [x] Liquidity dashboard live in Grafana, reporting honest zeros.
      `marketplace.json` — Active Agents, Active Escrows, Total Trade Volume, Open
      Negotiations, Listings & Purchases — provisioned and mounted in the running
      Grafana.

---

## P1a — The crypto rail · +12 · week 1–4

**Entry gate:** P0 exit. Do not connect real money to a system whose claims are
not yet reconciled.

**Why this is split from the fiat rail.** The original P1 put a Lemon Squeezy
subscription and an on-chain settlement in one phase, which quietly made the
whole money rail depend on a registered company: Lemon Squeezy is a merchant of
record and needs a legal entity behind it. That inverts the dependency the audit
found. The platform's binding constraint is not engineering — the engine is
production-grade and its suite is green — it is that **no transaction has ever
been exercised by a real counterparty**. A marketplace cannot be "finished and
tested" before it transacts; transacting *is* the test. Gating the first
transaction on incorporation, and incorporation on the platform being finished,
is a deadlock, and the programme would stall around 58 instead of reaching 82.

The crypto rail has no such dependency: an on-chain escrow needs a wallet and an
RPC endpoint, not an entity. It is also the more native rail for this product —
agents settling with agents is the M2M thesis, while a fiat subscription bills a
*human* tenant for gateway access, which is a different product on a different
clock. Roughly $10–15 covers the proof: USDC for one trade, plus Base gas
measured in cents.

| Workstream | Detail |
|---|---|
| Mainnet settlement | Integration wired 2026-08-24: `call_escrow()` builds, signs and sends a real transaction and returns the receipt status, **failing closed** — the stub returned True on every error, so a release that never reached the chain looked like one that did. `settlement_capability(chain)` derives the answer from ABI + deployed address + signer, per chain, and names which piece is missing. **That was wrong, and 2026-08-26 corrected it.** Setting those variables does not produce settlement: `EscrowService.fund_escrow()` calls `deposit` with `{}` — no trade id, no addresses, no amount — and the escrow record stores agent **DIDs** and a USD figure, not wallet addresses or a token contract. There is nothing to build a real `deposit()` from. On-chain settlement is **not implemented**; `simulated` is an accurate description of the software, not a configuration gap. Worse, `_call_contract()` discarded `call_escrow`'s return value and every caller advanced the escrow regardless, so enabling a real chain would have produced failed transactions recorded as funded and released. That half is fixed. Remaining work is a design task, now specified in [on-chain settlement design](onchain-settlement-design.md): non-custodial (**not** the gateway-treasury shape, which would import P1b's custody problem into P1a), addresses snapshotted onto the escrow, integer minor units rather than a float, a seven-check preflight, and a cutover gated on counted verified trades rather than elapsed time. Note that `sepolia` — the chain P1a actually deployed on — has **no USDC address configured** and cannot settle at all; `base_sepolia` is the target. |
| Escrow contract | Compiled 2026-08-25 with solc 0.8.24 (`--optimize --optimize-runs 200`), 3 924 bytes of bytecode, artefacts committed. The hand-written ABI held nothing false but omitted all six custom errors, so every revert would have decoded as an unnamed execution error rather than `WrongState(2)` — with funds sitting in the contract. **Compiled, not audited, not deployed.** Next: deploy to Base Sepolia and run one full trade through it; that is free and is the only thing that proves the ABI, the signer and the state machine agree. |
| Escrow, executed | Run on a local EVM 2026-08-25 (py-evm + a mock ERC-20): funds move to the seller only after the buyer confirms, refund returns them, the arbiter resolves a dispute, and five guards revert with the *named* custom error rather than merely failing. `eth-tester` is a dev dependency so CI runs this instead of skipping it. Still not audited and not deployed; a Base Sepolia trade is the next step and needs a testnet key. |
| Testnet deployment | `scripts/deploy_escrow.py` — one command that deploys the compiled bytecode to a testnet and runs a full trade through it with three distinct addresses: the buyer signs its own `approve`, the seller delivers, the buyer confirms, and the script asserts on token balances rather than on return values. It refuses any chain in `MAINNET_CHAINS`, takes the key from the environment rather than argv, and verifies the chain id against the node instead of trusting the flag. The whole flow is executed in `test_deploy_escrow_script.py` on py-evm, so the real run is not its first — a deploy script that has only ever been read is a plan, and it fails after the first transaction has already landed. Verified against Base Sepolia and Ethereum Sepolia with `--check`. |
| Escrow, on a public chain | **Executed 2026-08-25 on Ethereum Sepolia**, first attempt, no retries. Escrow at [`0x349f6361…`](https://sepolia.etherscan.io/address/0x349f6361e5C0a8c35EBB00b5d43Ed62d23c5C52a), nine transactions, 157s, ~0.003 ETH. Trade `0x22f13ce3…` reached state 3 (Released) with the seller holding 1 000 000 and the escrow holding 0 — read back afterwards through a *different* public RPC, because a script confirming its own result confirms nothing. Base Sepolia was the intended target; its faucets require either an Ethereum mainnet balance or a country the operator does not live in, and Sepolia exercises the same bytecode, ABI, signer and state machine. What Base Sepolia would add is L2 fee mechanics, which does not gate the audit. |
| Static analysis | Slither run 2026-08-26 (`ghcr.io/crytic/slither`, solc 0.8.24) — **8 findings, one high and real**. `deposit()` had no `msg.sender` check while calling `transferFrom` on a caller-supplied `buyer`, so anyone could sweep any address holding a standing allowance to the escrow into a trade of their own devising. Not theft — `confirmReceipt` checks the buyer — but the funds lock until a deadline the attacker chose, and `raiseDispute` (also unguarded) freezes them pending the arbiter. Infinite approval is the common integration, which is what made it serious. Two Slither missed and reading found: `deliverAsset` and `raiseDispute` accepted any caller. Fixed, plus a zero-arbiter constructor check and events moved before transfers. The one surviving finding is annotated, not suppressed: `buyer` stays arbitrary **to the arbiter**, which is the gateway's own signer and can already direct funds through `resolveDispute`. Redeployed to Sepolia at [`0x42Cb99A8…`](https://sepolia.etherscan.io/address/0x42Cb99A842a5bb6848Ef96b9f7070E348BD9b913) and re-traded. **A static analyser is not an audit**; a human review is still required before mainnet. |
| Flip `AUTHORIZE_PAYMENT_ENFORCED` | Prerequisite shipped: `kya.screen_agent()` grants a default L2 policy on VERIFIED, so the flag is no longer a kill switch. Stage it. |
| Per-trade value cap | Cap the first 90 days. Clearing once settled every trade at $0.00 with tests that agreed; assume that bug class is still latent and reconcile by hand initially. |

**Measured 2026-08-19, before any flip.**

- The flip is safe for verified agents — `test_kya_default_autonomy` covers
  purchase-under-enforcement, blocked-when-unverified and
  approval-above-threshold. What it buys is smaller than advertised: the Budget
  Guardian answers `ALLOW` at any amount for every production tenant, because
  none has agentic commerce configured. The flip enables the autonomy gate and a
  constant. Instrumented as `not_evaluated` rather than left to read as a pass.
- Mainnet is blocked on inputs that cannot be invented here: an RPC endpoint and
  a funded wallet. Built against mocks it produces exactly what the capability
  matrix already labels `SIMULATED`.

**Exit criteria**
- [ ] One on-chain USDC escrow funded, delivered and released on a mainnet chain.
- [ ] `GET /marketplace/protocol` reports `settlement_mode: onchain` — which since
      2026-08-21 requires a chain in `MAINNET_CHAINS`, so this criterion can no
      longer be satisfied by a testnet endpoint.
- [ ] Reconciled clean by `order_recon_job` and `ledger_recon_job`.
- [ ] `AUTHORIZE_PAYMENT_ENFORCED=true` in production with no purchase-path regression.
- [ ] Design accepted: [on-chain settlement design](onchain-settlement-design.md) (2026-08-26) — the schema, conversion and preflight that `deposit({})` needs.

---

## P1b — The fiat rail · +4 · gated on the company, not on the calendar

**Entry gate:** a registered legal entity able to hold a merchant-of-record
account. This is a business decision with tax consequences, and it belongs to
the owner and their accountant, not to this plan. Nothing in P1b blocks any
other phase.

The code is already written and idle: `warden/lemon_billing.py` has checkout
creation and webhook handling complete, and production simply has no keys. When
the keys exist this is about a day of work, most of it verification.

**Idle is not the same as unexercised (2026-08-21).** `FakeLemonSqueezy` — a
development double in the SWFE fake layer, not a new subsystem — now drives the
whole path with no account and no entity: checkout → HMAC-signed webhook → plan →
feature flags, plus replay, forged signature, missing signature and in-flight
tamper. It answers the module's only two external seams, `_ls_request()` and the
signature `handle_webhook()` verifies. Three levels of proof, kept distinct:

| Level | Proves | Needs |
|---|---|---|
| `FakeLemonSqueezy` | our side of the contract | nothing |
| Lemon Squeezy **test mode** | the wire format — event names, JSON:API shape, retries | an account, no company |
| Live keys | the rail | the entity — this phase |

Level 2 is the honest next step and is **not** gated on incorporation, so the
wire can be validated long before P1b opens. Until a real purchase settles, the
capability matrix row stays `SIMULATED`: a fake can only ever agree with the
developer who wrote it, which is precisely how clearing settled every trade at
$0.00 with tests that agreed.

| Workstream | Detail |
|---|---|
| Fiat rail live | Configure the Lemon Squeezy key, webhook secret and product/variant ids; run the sandbox flow; go live. |
| Overage collection | One full period accruing as `computed`, reconciled by hand, then `OVERAGE_CHARGE_ENFORCED=true`. |

**Exit criteria**
- [ ] One real subscription purchased end to end in production by a consenting third party, using their own payment instrument, with their authorization recorded alongside the transaction. A self-test proves the integration, not the rail.
- [ ] One overage period settled through the ledger with no double-charge on re-run.

---

## FT-6 Phase C — order-model cutover · moved out of P1

**Blocked on order volume, not on code, and not on either rail.**
`phase_c_ready()` on production reports `{'ready': False, 'reason': 'no orders
were compared (orders_checked=0)'}`. The gate is right to refuse: reconciling
zero rows against zero rows is the vacuous pass FT-2 shipped once already. It
unblocks inside **P3**, once real orders exist on both write paths — which is
why it now lives there rather than here.

---

## P2 — Distribution and developer experience · +8 · week 3–6

**Entry gate:** none — runs alongside P1a. Publishing an SDK against a simulated
rail is acceptable only because the capability matrix says so plainly.

For a machine-to-machine platform the front door is a package install, not a
562-endpoint OpenAPI document.

| Workstream | Detail |
|---|---|
| Publish the SDKs | **Done 2026-08-26.** `shadow-warden-sdk` 1.0.0 on PyPI and `@shadow-warden/sdk` 1.0.0 on npm, both from tag `sdk-v1.0.0` so the two can never drift from each other or from the gateway. Verified by querying both registries rather than by reading the workflow's own report. Prerequisite done 2026-08-22: three Python packages and two identically-named npm packages were consolidated to one each — the repo could not publish until it agreed with itself about what its SDK was called. The npm half failed first time with a 403: a granular token cannot publish unless **Bypass 2FA** is set on the token itself, because CI has no way to answer a 2FA prompt. |
| API versioning | Done 2026-08-23. `/v1` is an alias resolved by one ASGI middleware — no route declared twice — and every response on a non-exempt unversioned path carries `Deprecation`, `Sunset: 2027-08-23` and a `Link: rel="successor-version"` (health, metrics, docs and `/.well-known/*` are exempt: they are not moving). Policy in `docs/api-versioning.md`, window published in the discovery document. Freezing `v1`'s schemas against a conformance suite is separate. |
| Ten-minute quickstart | Done 2026-08-24. `docs/quickstart.md` — four calls, every response copied from `scripts/quickstart_check.py` running against the build. The script ships with it so the page can be re-verified rather than believed; it also runs against a live gateway with `--base-url`. Writing it found two defects: the listing step needs an asset that nothing documented, and the dev vault key was regenerated per call so asset registration raised `InvalidToken` on any fresh checkout. |
| Agent-native discovery | Done. `/.well-known/agent.json` returns the A2A card and the marketplace manifest merged, so a foreign agent gets `settlement_mode`, `escrow.chains`, pricing, negotiation and `api_version` without human docs. Audited 2026-08-26 for whether those fields are *true* rather than merely present, which found two: `version` was pinned at `5.6.0` while the gateway shipped `7.9.0` — a two-major-version-old identity — and `payment_schemes[].enabled` was the **string** `"false"`, which every consumer language reads as true, so a disabled payment gate advertised itself as enabled. Both now derive from the single source of truth and are pinned by `test_agent_card_truth.py`. |
| Surface consolidation | Portal for tenants, SOC dashboard for operators, Streamlit internal-only. Freeze the split. |

**Exit criteria**
- [x] `pip install shadow-warden-sdk` and `npm i @shadow-warden/sdk` both resolve. *(2026-08-26, both 1.0.0, checked against the registries.)*
- [ ] A developer outside the project completes the quickstart unaided, timed.
- [x] Every new route ships under `/v1`; the legacy surface has a published sunset date.
      Structurally true since 2026-08-23: `/v1` is an ASGI alias, so a route is
      reachable under it by construction rather than by remembering — verified on
      production 2026-08-29 (`/v1/marketplace/protocol` 200, and the unversioned
      path answering `deprecation: true` + `sunset: Mon, 23 Aug 2027`).
      **What was actually broken was the clients, not the routes.** Both SDKs
      published on 2026-08-26 called `/filter`, `/tax/calculate` and
      `/marketplace/*` unversioned — the front door targeting the surface the same
      release had declared deprecated three days earlier, with the clock already
      running. Fixed in 1.1.0 by joining the version once where the base URL is
      built, not at the ~15 path literals; `api_version=None` still reaches the
      legacy surface for a gateway older than the middleware.
      `test_sdks_target_v1.py` pins the seam (6 of 9 fail against 1.0.0).
      The quickstart carried the same defect and is now closed too: a `_Versioned`
      wrapper covers both of the verifier's request modes (httpx honours
      `base_url`, `TestClient` does not), re-run against the build — five steps,
      all `/v1`, all green. Fixing it surfaced a **regression from #403**: the
      new escrow columns were added to the DDL and to a migration that only ran
      on `escrow._conn()`, while `listing._do_purchase` hands `insert_escrow` its
      own connection — so any database whose table predated #403 failed the first
      purchase. Production was unaffected only by luck (it has no
      `marketplace_escrow` table, so it builds one from the new DDL); any dev
      machine or restored backup would have hit it. `insert_escrow` now migrates
      the connection it is given, pinned by `test_escrow_columns_on_old_tables.py`
      — which builds the pre-#403 table on purpose, because a fresh `tmp_path`
      database can never reproduce a migration bug.
      ⚠️ 1.1.0 is **not published**. Tagging `sdk-v1.1.0` releases it.

---

## P3 — Seeding both sides of the market · +12 · week 5–12

**Entry gate:** P1a exit. Seeding a market that cannot settle produces demos,
not liquidity — and it is settlement that is required here, not billing, so P1b
is not a prerequisite.

A two-sided market with zero supply and zero demand does not bootstrap itself,
and no feature fixes that. The platform's advantage is that it can credibly be
its own first seller.

| Workstream | Detail |
|---|---|
| First-party supply | `scripts/seed_first_party_supply.py` — twenty listings, each refusing to exist unless its capability does. Every entry names a route that must be present in the **live** OpenAPI of the gateway being seeded, not in the source tree; an unserved route is skipped and reported. Dry run by default, idempotent by sku. Writing it found that the marketplace could not express its own supply: `register_asset` accepted only `{rule, model, signals}`, so `/filter` metered and a compliance posture score had to be mislabelled as "rule" to be listed at all. Added `service` and `report`. Also found `/marketplace/protocol` advertising `asset_type: "general"`, which `register_asset` rejects with a 422 — the enum was written out twice, so the machine-readable schema and the enforcement had drifted. One definition now. **Not yet run against production.** |
| Design-partner demand | Five pilot buyer agents through real KYA to VERIFIED. Their integration friction is the next quarter's roadmap. |
| Referral loop | `warden/billing/referral.py` exists and is unwired. Agent-to-agent referral is the natural M2M growth mechanic. |
| Liquidity reporting | Weekly: listings, active agents, GMV, settled trades, fill rate, time-to-first-fill. A flat week is an incident. |
| Pricing calibration | The price list is coherent but untested against willingness to pay. The first ten transactions are an experiment. |
| FT-6 Phase C | Moved here from P1. Once orders flow on both write paths, run the reconciliation and cut `list_orders()`/`get_order()`/`order_history()`/`get_receipt()` over to `marketplace_purchases`. `phase_c_ready()` is the gate. |

**Exit criteria**
- [ ] 50 live listings and 10 agents that transacted in the last 30 days.
- [ ] ≥25 settled transactions per week, sustained four consecutive weeks.
- [ ] At least one trade where neither counterparty is first-party.
- [ ] `phase_c_ready()` returns `ready: True` on a non-zero sample, and the readers are cut over.

---

## P4 — Service and trust operations · +7 · week 8–14

**Entry gate:** the first real counterparty — a settled trade from P1a, or a
paying subscriber once P1b lands. Building support infrastructure before there is
anyone to support is the same mistake in another category.

| Workstream | Detail |
|---|---|
| Ticketing with an SLA clock | Intake, severity, response deadline, escalation. The static KB becomes tier-zero deflection, not the whole answer. |
| Public status page | `site/src/pages/status.astro` and `GET /deploy/status` both exist and are not connected. |
| SLA credits that issue | Detect breach from collected availability metrics, compute the credit, apply it to the invoice. A promise with no mechanism is worse than no promise. |
| Incident communications | Templates, a named owner per severity, a published postmortem within five working days. |
| Dispute handling | The escrow dispute endpoints exist; the human process behind `resolve_dispute` does not. |

**Exit criteria**
- [ ] A simulated SLA breach produces a real credit on a real invoice.
- [ ] The status page reflects a genuine degradation within five minutes of onset.
- [ ] One escrow dispute resolved through the documented process, start to finish.

---

## P5 — Enterprise and scale readiness · +10 · week 12–20

**Entry gate:** three or more paying customers, or one signed enterprise pilot.
Deploying HA for zero users is cost without risk reduction.

Everything here is written and unshipped.

| Workstream | Detail |
|---|---|
| Leave the single VPS | Deploy the existing Helm chart to managed Kubernetes. The point at which the architecture stops being a liability. |
| Money tables to Postgres | Thirty SQLite files on one box is the ceiling. Migrate ledger, orders, escrow, balances. The DDL registry makes it tractable. |
| SOC 2 Type II | Engage an auditor. Control mapping, evidence collector and the 93-control ISO matrix are built; the independent opinion is the part buyers accept. |
| Multi-region | `RegionMiddleware` and `docs/multi-region.md` exist. EU residency is a requirement, not a differentiator. |
| Detection-math debt | 786 surviving mutants. One is structural: the CPT drift gate's `entropy_center` link can never reject — the clamp bounds its maximum drift at 13.76% against a 25% threshold. |

**Exit criteria**
- [ ] A failover drill on the HA topology meets a stated RTO and RPO.
- [ ] Money-path reads and writes served from Postgres; SQLite retired for those tables.
- [ ] Auditor fieldwork underway with an observation window opened.

---

## Deliberately not doing

Every item below is defensible work that would nonetheless lower the score by
consuming the capacity the phases above need. Enforced by the feature freeze in
`CLAUDE.md`.

| Not doing | Because |
|---|---|
| New subsystems | The existing forty are under-exercised, not insufficient. |
| Internationalisation | Not until two paying non-English customers ask. English-only is defensible for a developer-facing M2M product. |
| A fifth frontend | Consolidate four to two. New UI lands inside an existing surface. |
| Additional chains | One mainnet chain done properly beats four testnets. |
| Chasing full mutation coverage | Fix the structural CPT finding; the rest stays tracked debt, not a sprint. |
| Browser sandbox revival | Reinstating the Playwright base image costs ~1.8 GB and serves no current customer. |

---

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Flipping `AUTHORIZE_PAYMENT_ENFORCED` blocks all purchases | High | Known failure mode: an agent with no autonomy policy returns `REQUIRE_APPROVAL`. Verify the KYA default-policy grant covers the `purchase` action string before flipping; stage it. |
| Mainnet moves real value through untested paths | High | Cap per-trade value for 90 days. Clearing once settled every trade at $0.00 with tests that agreed — assume the same bug class is still latent and reconcile by hand initially. |
| Cold start never ignites | High | P3's exit demands a trade between two third parties. If that has not happened by week 12, the market thesis needs revisiting — not more features. |
| "Finish the platform first, then incorporate" | High | The bar recedes: a marketplace cannot be finished before it transacts, because transacting is the test. P1a exists so the first real transaction needs a wallet rather than a legal entity. If P1a is also deferred, the programme stops at P0 and the score stays near 58. |
| Single VPS loss before P5 | Medium | Offsite encrypted backup, restore drilled at ~17s RTO. Accepted exposure until P5; state it in the SLA rather than implying HA. |
| Compliance claims outrun the audit | Medium | The capability matrix is the control. Never state a certification, only mapped controls and their attestation status. |
| Maintainer capacity | Medium | The freeze list is the mitigation, and only works if enforced against the autonomous loop as well as human enthusiasm. |

---

## Ceiling

All phases land the assessment at roughly **82**; without P1b — if the company
is deferred — the ceiling is about **78**, because a platform that settles
agent-to-agent but cannot bill a human tenant is a narrower product, not a
broken one. Nothing else in the programme waits on it. The remaining gap to the
high eighties is not engineering: it is an independent SOC 2 Type II opinion with
a completed observation window, and a transaction history long enough that the
trust, dispute and settlement machinery has been exercised by adversarial
counterparties rather than by its own test suite. Both are bought with time and
customers. The purpose of this programme is to reach the point where time and
customers are the only things still missing.
