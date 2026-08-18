# Launch Programme — from security platform to working marketplace

**Baseline 54/100 · target 82/100 · six gated phases · ~20 weeks.**
Opened 2026-08-18. Canonical companion: `docs/capability-matrix.md`.

The engine is production-grade. The market it serves does not exist yet: zero
registered users, zero listings, zero settled trades, no live payment rail. This
programme closes that gap, ordered so each phase unblocks the next.

Phases are numbered because they are genuinely sequential — each entry gate is
the previous phase's exit evidence. **P2 is the only phase that runs in
parallel.** No phase is complete on effort spent, only on its exit criteria being
demonstrably true in production.

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
| Money rail & settlement | 28 | Testnets only; no fiat provider; both enforcement flags off |
| Customer service operations | 22 | No ticketing; SLA promises credits with no mechanism |
| Commercial traction | 10 | Zero of everything indicating a market exists |

That is a sequencing problem, not a capability problem. Hence: money rail before
market seeding, market seeding before service operations, service operations
before scale.

---

## P0 — Truth and freeze · +3 · week 0–1

**Entry gate:** none. Blocks everything else.

Stop the growth of surface area and publish an honest account of what is
simulated. The live exposure is selling "high security, escrow-backed" while
`GET /marketplace/protocol` answers `settlement_mode: simulated` to anyone who
asks.

| Workstream | Detail |
|---|---|
| Feature freeze | No new routers, subsystems or frontend surfaces. Recorded in `CLAUDE.md` so the autonomous loop honours it too. |
| Capability matrix | `docs/capability-matrix.md`: every public claim mapped to real / testnet / simulated / self-attested. Site copy reconciled against it. |
| Evidence Vault on | `S3_ENABLED=false` while the SOC 2 material cites the vault. Enable, verify a bundle lands in MinIO and offsite. |
| Posture written down | `fail_strategy: open` and `strict: false` are defensible — but as a documented decision with an alerting story, not an unexamined default. |
| Baseline instrumentation | One dashboard with the six numbers that define the business. All currently zero; make the zero visible daily. |

**Exit criteria**
- [ ] Capability matrix published; every public claim reconciled against it.
- [ ] An evidence bundle written to MinIO and to the offsite bucket, verified by hand.
- [ ] Liquidity dashboard live in Grafana, reporting honest zeros.

---

## P1 — The money rail · +16 · week 1–4

**Entry gate:** P0 exit. Do not connect real money to a system whose claims are
not yet reconciled.

The largest score movement in the programme and the cheapest relative to its
effect, because most of the code exists and is tested. What is missing is
configuration, one mainnet chain, and the decision to flip two enforcement flags.

| Workstream | Detail |
|---|---|
| Fiat rail live | `warden/lemon_billing.py` has checkout creation and webhook handling complete. Production has no Lemon Squeezy keys at all. |
| Flip `AUTHORIZE_PAYMENT_ENFORCED` | Prerequisite shipped: `kya.screen_agent()` grants a default L2 policy on VERIFIED, so the flag is no longer a kill switch. Stage it. |
| Mainnet settlement | `warden/web3/chains.py` knows only Sepolia, Polygon Amoy and Arbitrum Sepolia. Add Base mainnet + USDC; the protocol must report `onchain`. |
| Order model cutover | FT-6 Phase C: move readers onto `marketplace_purchases`, retire the `m2m_orders` / `commerce_orders` / `commerce_receipts` triple. |
| Overage collection | One full period accruing as `computed`, reconciled by hand, then `OVERAGE_CHARGE_ENFORCED=true`. |

**Exit criteria**
- [ ] One real fiat subscription purchased end to end in production by a consenting third party, using their own payment instrument, with their authorization recorded alongside the transaction. A self-test proves the integration, not the rail.
- [ ] One on-chain USDC escrow funded, delivered and released on a mainnet chain.
- [ ] Both reconciled clean by `order_recon_job` and `ledger_recon_job`.
- [ ] `AUTHORIZE_PAYMENT_ENFORCED=true` in production with no purchase-path regression.

---

## P2 — Distribution and developer experience · +8 · week 3–6

**Entry gate:** none — runs alongside P1. Publishing an SDK against a simulated
rail is acceptable only because the capability matrix says so plainly.

For a machine-to-machine platform the front door is a package install, not a
562-endpoint OpenAPI document.

| Workstream | Detail |
|---|---|
| Publish the SDKs | `shadow-warden-client` to PyPI, `@shadow-warden/sdk` to npm. Tag-triggered release job in `ci.yml` so versions never drift from the gateway. |
| API versioning | 562 unversioned paths cannot evolve without breaking callers. `/v1`, a deprecation header, a published support window. |
| Ten-minute quickstart | One page, one path: register an agent, publish a listing, receive a settled payment. |
| Agent-native discovery | Extend `/.well-known/agent.json` with the protocol manifest so a foreign agent negotiates without human docs. |
| Surface consolidation | Portal for tenants, SOC dashboard for operators, Streamlit internal-only. Freeze the split. |

**Exit criteria**
- [ ] `pip install shadow-warden-client` and `npm i @shadow-warden/sdk` both resolve.
- [ ] A developer outside the project completes the quickstart unaided, timed.
- [ ] Every new route ships under `/v1`; the legacy surface has a published sunset date.

---

## P3 — Seeding both sides of the market · +12 · week 5–12

**Entry gate:** P1 exit. Seeding a market that cannot settle produces demos, not
liquidity.

A two-sided market with zero supply and zero demand does not bootstrap itself,
and no feature fixes that. The platform's advantage is that it can credibly be
its own first seller.

| Workstream | Detail |
|---|---|
| First-party supply | Twenty listings from capabilities that already run: `/filter` metered, document intelligence, compliance posture scoring, threat-intel feeds. |
| Design-partner demand | Five pilot buyer agents through real KYA to VERIFIED. Their integration friction is the next quarter's roadmap. |
| Referral loop | `warden/billing/referral.py` exists and is unwired. Agent-to-agent referral is the natural M2M growth mechanic. |
| Liquidity reporting | Weekly: listings, active agents, GMV, settled trades, fill rate, time-to-first-fill. A flat week is an incident. |
| Pricing calibration | The price list is coherent but untested against willingness to pay. The first ten transactions are an experiment. |

**Exit criteria**
- [ ] 50 live listings and 10 agents that transacted in the last 30 days.
- [ ] ≥25 settled transactions per week, sustained four consecutive weeks.
- [ ] At least one trade where neither counterparty is first-party.

---

## P4 — Service and trust operations · +7 · week 8–14

**Entry gate:** first paying customer from P1. Building support infrastructure
before there is anyone to support is the same mistake in another category.

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
| Single VPS loss before P5 | Medium | Offsite encrypted backup, restore drilled at ~17s RTO. Accepted exposure until P5; state it in the SLA rather than implying HA. |
| Compliance claims outrun the audit | Medium | The capability matrix is the control. Never state a certification, only mapped controls and their attestation status. |
| Maintainer capacity | Medium | The freeze list is the mitigation, and only works if enforced against the autonomous loop as well as human enthusiasm. |

---

## Ceiling

All six phases land the assessment at roughly **82**. The remaining gap to the
high eighties is not engineering: it is an independent SOC 2 Type II opinion with
a completed observation window, and a transaction history long enough that the
trust, dispute and settlement machinery has been exercised by adversarial
counterparties rather than by its own test suite. Both are bought with time and
customers. The purpose of this programme is to reach the point where time and
customers are the only things still missing.
