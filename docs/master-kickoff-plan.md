# Master Kickoff Plan — one sequence to start work

Date: 2026-07-18 · Status: ACTIVE · Supersedes nothing — this is the *ordering*
layer over: `fintech-grade-commerce-plan.md` (FT-\*), `fintech-development-plan.md`
(FM-\*), `fintech-architecture.md` (target structure),
`integration-research-tunnel-sac-marketplace-gsam.md` (MI-1…7 / NF-1…7),
`unified-modernization-roadmap.md` (canonical status registry).

Reality baseline (verified 2026-07-18): FM-1…FM-4 core **already shipped**;
DE-6 P1 open_db migration **in flight on `deeng/de6-p1-open-db-helper`**
(uncommitted `warden/communities/*` edits in the working tree); FT and MI/NF
**not started**; AP2 import-time key bug **confirmed live**
(`agentic_commerce/ap2.py:37-38`).

---

## Wave 0 — Hygiene & unblocking (today–tomorrow)

| # | Action | Why first |
|---|---|---|
| 0.1 | Finish/commit the in-flight DE-6 P1 batch (uncommitted `communities/*` diff), merge branch to main | Working tree must be clean before any new track opens; DE-6 is the storage substrate FT rides on |
| 0.2 | Commit the four planning docs (fintech ×3 + integration research) | They are untracked; the autonomous loop and other agents can't see them |
| 0.3 | Register **Track F — Fintech (`FT-*`)** in `unified-modernization-roadmap.md` (owner of money semantics; ledger storage C-shared with Track B) | Governance rule: no work without a track prefix |
| 0.4 | **Hotfix AP2 key handling** (pull FT-3 item forward): `_FERNET` → per-call `resolve_key("AP2_VAULT_KEY", purpose="ap2_vault")`, fail-closed, no `Fernet.generate_key()` fallback | Live signature-bypass-class hole (same class as the Phase 7 unsigned-mandate fix); 1-file fix + ratchet already exists |

## Wave 1 — Foundations (week 1)

- **FT-0** (2–3 d): `warden/ledger/money.py` (int micro-USD `Money`, Decimal at
  boundary, property-tested); money-mutation inventory checked into `docs/`;
  two ratchets — no new `REAL` money columns, no new float arithmetic on money
  paths in `billing|marketplace|commerce|finops|m2m_store`.
- **MI-1** (1 d): GSAM observation taps in `/marketplace/action`, x402
  deductions, escrow transitions, MAESTRO verdicts (fail-OPEN, metadata-only).
- **MI-2** (0.5 d): `is_quarantined()` deny in the marketplace action
  dispatcher + `x402_gate.require_payment()` (additive, single check per
  action — `already_gated` pattern).

Exit: marketplace visible to GSAM; quarantine actually stops trading; float
money can no longer grow.

## Wave 2 — Ledger core (weeks 2–4)

- **FT-1** (2–3 w): `warden/ledger/` journal + accounts + holds + rollup per
  `fintech-architecture.md` §2–3. Storage via `open_db()` + `ddl_registry` +
  `data_path("warden_ledger.db", "LEDGER_DB_PATH")` — coordinate with Track B.
- **FT-2** (2 w, overlaps): migrate writers — Flex Credits, wallet funding,
  SAC preflight holds → journal. Fold in **NF-1** (trial/bonus sub-balances as
  `promo:*` accounts — they are just accounts now) and **NF-2** (15%-of-spend
  referral kickback posting). FM-1 `available_usd()` re-pointed at the rollup.
- **MI-6** (1 d, parallel): marketplace credential handling via `/gsam/lease`.

Exit: one source of truth for balances; opening-balance backfill + drift
report at cutover.

## Wave 3 — Fail-closed money & settlement (weeks 5–6)

- **FT-3** (1–2 w): posture split (money = fail-CLOSED), `Idempotency-Key` on
  buy/fund/clear/credit endpoints, kill `INSERT OR REPLACE` on financial
  tables, escrow/order transition guards. (AP2 fix already done in Wave 0.)
- **FT-4** (2 w): settlement worker (pending x402 deductions + take-rate →
  postings, payout statements); nightly recon (journal ⟷ Lemon/Stripe ⟷ CH
  `billing_session_ledger` ⟷ Postgres mirror) — this **is** NF-3; transactional
  outbox replaces the fail-open dual-write.
- **NF-5 / MI-7 mediator** (parallel, Track B under DE-4):
  `marketplace/mediator.py` — MAESTRO flags → bounded fee-surcharge /
  reputation-penalty postings (detect → enforce).

## Wave 4 — Compliance & consolidation (weeks 7–9)

- **FT-5** (2–3 w): KYB behind KYA, sanctions at onboarding + settlement, AML
  monitors on the journal stream → `incident_register`; licensing-posture doc
  (PSP-custodied, no own custody).
- **FT-6** (2 w): single `authorize_payment()` chokepoint (autonomy → mandate
  → budget → funds → quarantine) + ratchet; one x402 impl
  (`payments/x402.py`); m2m_store/commerce order models fold into marketplace.
  **NF-6/MI-4** (402-gated agent sessions) lands here for free — preflight is
  inside the chokepoint.

## Wave 5 — Continuous / opportunistic

- **FT-7**: hypothesis money-conservation tests, chaos tests, SOC 2 mapping,
  auditor export, recon dashboard.
- **MI-5 v1**: SEP transfers consult `sovereign.router.route()`; tunnel_id +
  attestation into CTP/STIX + settlement metadata.
- **NF-4**: capability-based MasterAgent routing over A2A agent cards.
- **NF-7**: `--baseline` for `warden_github_scan.py`.
- Background (unchanged owners): DE-7 BrowserSandbox isolation, SR-2.3 pinned
  transport wiring, SR-7.2/7.3 coverage + mutation.

## Deferred / rejected (do not start)

MILP allocator (until ≥2 nodes) · on-chain escrow custody (until FT-5
licensing decision) · Prisma/NestJS/TS money services · eBPF/Kata sensors ·
MI-5 v2 real MASQUE egress (until infra exists).

## Rules of engagement

1. Track prefixes in every commit/PR (`FT-1`, `MI-2`…); never bare "Phase N".
2. One merged phase = one push to main (autodeploy rule); no batching phases.
3. Full test suite + full-tree mypy + the three governance ratchets
   (route_inventory, counterless_failopen, suppressions) before every push.
4. Shared files per the roadmap conflict table; ledger storage decisions go
   through Track B; `staff/economics.py` price-book is the only rate table.
5. FT/FM/MI logic is **additive after** fail-closed security gates — never
   weakens filter fail-open posture, STAFF-01…05, or the agentic gate.

## Start-here checklist (literal first session)

```
[ ] 0.1 commit + merge DE-6 P1 branch (test suite green first)
[ ] 0.2 git add docs/fintech-*.md docs/integration-research-*.md docs/master-kickoff-plan.md
[ ] 0.3 add Track F table to docs/unified-modernization-roadmap.md
[ ] 0.4 AP2 hotfix + test (FT-3a) → own PR → main
[ ] 1.1 FT-0 money.py + ratchets → PR
[ ] 1.2 MI-1 GSAM taps → PR ; MI-2 quarantine gate → PR
```
