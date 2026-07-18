# Fintech-Grade Commerce Plan — Business Community & Marketplace

**Track: FT-\* (Fintech Foundations)** · Status: PROPOSED · Author: architecture audit 2026-07-17
Scope: `warden/marketplace/`, `warden/business_community/agentic_commerce/`, `warden/m2m_store/`,
`warden/communities/` (SEP/peering/transfer), `warden/billing/`, `warden/payments/`, `warden/finops/`,
`warden/tokenomics/`, `warden/web3/` + `blockchain/`.

---

## 1. Current Architecture (as-built)

Three overlapping commerce stacks sit on top of the security gateway:

| Stack | Modules | What it does |
|---|---|---|
| **M2M Marketplace** | `warden/marketplace/` (40 files, ~11k LOC) | DID agents, listings, 4-stage lifecycle (register → search → negotiate → clear), escrow, x402 nanopayments, Flex Credits, KYA, L1/L2/L3 autonomy, MAESTRO threat detection, TrustRank/Sybil |
| **Agentic Commerce** | `business_community/agentic_commerce/` | UCP/AP2/MCP procurement protocols, signed spending mandates, multi-agent auction, Budget Guardian |
| **M2M Store** | `warden/m2m_store/` | Catalog/inventory/store-agent variant with its own analytics + order tables |

Supporting layers: `billing/` (tiers, add-ons, audit chain, overage, referral), `payments/l402.py`,
`finops/wallet.py` (FM-1 unified availability), `communities/` (SEP transfers, Causal Transfer Guard,
STIX tamper-evident chain), `voice/x402.py` (second x402 implementation).

Money state lives in **at least 6 separate SQLite files** (`warden_marketplace.db`,
`warden_commerce.db`, x402 DBs, SAC preflight holds, billing, m2m_store) plus Redis counters,
with an async fail-open PostgreSQL mirror for clearing.

---

## 2. Strengths (keep and build on)

1. **Security-first agent identity & authorization — ahead of the market.** Ed25519-signed offers,
   HMAC mandates via fail-closed `resolve_key()`, injection guard on negotiation messages, Sybil gate,
   KYA screening, MAESTRO (misalignment/collusion/poisoning) with auto-isolation, Confused-Deputy guard
   on the analytics SQL gate. Most fintechs bolt this on years later.
2. **Progressive autonomy + human-in-the-loop** (L1 shadow → L3 autonomous, REQUIRE_APPROVAL flow)
   matches exactly where agent-payments regulation (EU AI Act, AP2 ecosystem) is heading.
3. **Tamper-evident audit primitives already exist**: `billing/audit_chain.py` SHA-256 hash chain,
   STIX 2.1 chain for SEP transfers, x402 replay protection (nonce + ±5 min window).
4. **Deliberate Decimal math at the take-rate point** (`clearing.py`) and a documented
   "no float arithmetic in billing" intent.
5. **FM-1 unified wallet formula** — one authoritative `available = prepaid + trial + bonus − hold`,
   already fixing the "many answers to one balance question" problem at read time.
6. **Protocol breadth (x402, L402, AP2, UCP, MCP)** — genuine early-mover surface for agentic commerce.
7. **Clear ops discipline**: DDL registry, `data_path()` consolidation, ratchet tests, STAFF invariants —
   the governance machinery needed to enforce fintech invariants already exists.

## 3. Weaknesses (the fintech gap)

Ranked by severity for a money-moving product:

1. **No double-entry ledger.** Balances are mutable rows (`marketplace_credits.balance_credits`,
   Redis `DECRBY`, x402 balances, preflight holds) mutated independently. There is no journal,
   no account model, no invariant that debits equal credits, no way to prove money conservation.
   FM-1 unifies the *read*; nothing unifies the *write*.
2. **Float money end-to-end.** `amount_usd REAL`, `price_usd REAL` across escrow/listing/x402/budget;
   `finops/wallet.py` computes on Python floats with `round(x, 6)`; `ClearingResult` converts Decimal
   back to `float` for storage. Fintech baseline is integer minor units (micro-USD) or NUMERIC + Decimal
   with no float on any money path.
3. **Fail-open payment authorization.** x402 gate errors → allow (rule 13), KYA fail-open, MasterAgent
   autonomy fail-open. Fail-open is the *correct* posture for the security filter product; it is the
   *inverted* posture for money movement. An exception in the payment gate must deny, not allow.
4. **No idempotency on money endpoints.** `hooks/idempotency.py` exists but purchase/fund/clear flows
   don't require idempotency keys; `clearing.py` uses `INSERT OR REPLACE` (rewrites financial history);
   a retried webhook or double-submitted `accept_offer` can double-move value.
5. **Dual-write without reconciliation.** SQLite-first + async fail-open Postgres mirror means the audit
   copy silently diverges; Redis credit counter and SQLite row can drift; there is no recon job and no
   drift metric. Cross-DB atomicity is impossible in the current topology.
6. **No settlement layer.** `platform_fee_usd` is logged-only; x402 deductions accumulate in
   `x402_pending_deductions` with no settlement worker, no payout statements, no end-of-day
   reconciliation against Lemon Squeezy/Stripe/on-chain USDC.
7. **Escrow is simulated custody.** Default is a keccak-derived fake contract address; amounts in REAL;
   dispute flow has no SLA, no case queue, no funds actually held. Fine as a demo, not as escrow.
8. **Compliance scope is agent-level, not entity-level.** KYA screens the *agent* (ERS heuristic);
   there is no KYB/KYC of the owning legal entity, no sanctions screening bound to money flows,
   no AML transaction monitoring (velocity/structuring) on the marketplace stream, no licensing
   posture (money transmitter vs stored value vs agent-of-payee).
9. **Fragmentation.** Three order/receipt models (marketplace, m2m_store, commerce), two x402
   implementations (`marketplace/x402_gate.py`, `voice/x402.py`), credits vs wallet vs holds unified
   only at read time. Every duplicate is a future reconciliation break.
10. **AP2 key handling regression.** `ap2.py` snapshots `VAULT_MASTER_KEY` at import and silently falls
    back to `Fernet.generate_key()` — mandates become unreadable after restart, and the import-time
    snapshot violates the Phase 7 "resolve keys per call" rule.
11. **No money-invariant tests.** 71 marketplace tests are flow tests; nothing property-tests
    conservation ("sum of all postings = 0", "credits burned ≤ credits purchased").

**Fintech-readiness score: ~42/100.** (Security/authorization: 80. Ledger/settlement: 15.
Compliance: 35. Data integrity: 40.)

---

## 4. FT Roadmap — building the fintech-grade category

Design north star: **"Security gateway that can also be trusted with money"** — the moat is that no
competitor has MAESTRO/KYA/autonomy; the gap is boring fintech hygiene. Close the gap, keep the moat.

Governance: FT is a third track alongside SR-\*/DE-\*. Ledger storage is **data-layer work — coordinate
with Track B (DE-6)** per the unified roadmap; FT owns money semantics, DE owns the storage substrate.

### FT-0 · Freeze & Foundations (1 week)
- Inventory every money-mutation point (grep-able list checked into `docs/`).
- Add ratchet tests (same pattern as `test_no_new_raw_signing_key.py`):
  no new `REAL` money columns; no new float arithmetic in `billing|marketplace|commerce|finops` money paths.
- Introduce `warden/ledger/money.py`: `Money` as integer micro-USD (`int`), Decimal at the API boundary
  only. Pure, dependency-free, property-tested.

### FT-1 · Double-Entry Ledger Core (2–3 weeks)
- `warden/ledger/journal.py`: append-only journal; each transaction = balanced postings
  (Σ = 0) across typed accounts: `tenant:cash`, `tenant:credits`, `escrow:{id}`, `platform:fees`,
  `processor:clearing`, `promo:trial`, `promo:bonus`.
- Immutable rows (no UPDATE/REPLACE), hash-chained per tenant (reuse `billing/audit_chain.py` pattern),
  idempotency key UNIQUE-constrained at the journal level.
- One DB via `ddl_registry` + `data_path("warden_ledger.db", "LEDGER_DB_PATH")`; DDL-once.
- Balances become derived: `balance(account) = Σ postings` with a materialized rollup table
  (same pattern as GSAM rollup) — never a mutable counter.

### FT-2 · Migrate Balance Writers (2 weeks)
- Flex Credits, wallet funding (prepaid/trial/bonus), SAC preflight holds → journal writers.
  Two-phase hold = `pending` journal transaction, capture/void completes it.
- Redis stays as a **cache** of the rollup (invalidate-on-write), never the source of truth.
- FM-1 `resolve_wallet()` re-pointed at ledger rollup — formula unchanged, source unified.
- Backfill migration: opening-balance journal entries from current counters; drift report at cutover.

### FT-3 · Fail-Closed Money Gates + Idempotency (1–2 weeks)
- Explicit posture split, documented like the SAC rule: **security filter = fail-open,
  money authorization = fail-closed.** x402 `require_payment()`, AP2 `execute_payment`,
  autonomy check on payment actions: exception → deny (with circuit-breaker + operator metric).
- `Idempotency-Key` required on: buy/accept_offer/fund/confirm/clear/credit-purchase; replay returns
  the original result. Remove `INSERT OR REPLACE` from all financial tables.
- Order/escrow status machines get transition guards (illegal transition → 409), mirroring the
  escrow lifecycle already documented in `escrow.py`.
- Fix AP2: `_FERNET` via `resolve_key("AP2_VAULT_KEY", ...)` per call, fail-closed; no random-key fallback.

### FT-4 · Settlement & Reconciliation (2 weeks)
- Settlement worker (ARQ cron): drains `x402_pending_deductions` and take-rate fees into
  `processor:clearing` journal entries; produces per-seller payout statements.
- Nightly recon job: journal vs Lemon Squeezy/Stripe reports vs on-chain USDC vs Postgres mirror.
  Output: discrepancy report + `warden_ledger_recon_drift_usd` Prometheus gauge + Slack alert on ≠ 0.
- Replace clearing dual-write with **transactional outbox**: journal write commits an outbox row;
  a relay ships it to Postgres/STIX — at-least-once with recon, never silent divergence.

### FT-5 · Compliance Layer (2–3 weeks)
- **KYB/KYC of the owning entity** behind KYA: `kya.py` v2 gains `owner_verification` via a pluggable
  provider interface (Persona/Sumsub adapter later; manual-review queue now). Agent inherits the
  owner's status; unverified owner ⇒ autonomy capped at L1 + payout hold.
- Sanctions screening (reuse staff `screen_sanctions_list` machinery) at onboarding **and** on both
  parties of every settlement run.
- AML monitoring on the ledger stream: velocity, structuring (many sub-threshold transfers),
  circular flows (reuse trust_graph), mirror-trading between related DIDs. Hits → case in
  `incident_register` (already STIX-linked) with SAR-style draft via existing staff flow.
- Licensing posture doc (`docs/money-licensing-posture.md`): stay **agent-of-payee / PSP-custodied**
  (Lemon/Stripe/Circle hold funds; platform never takes custody) to avoid money-transmitter scope;
  escrow v2 decision gated on this.
- Data: ledger + KYB records live under `WARDEN_DATA_DIR` 0700, GDPR retention schedule added to DPIA.

### FT-6 · Consolidation (2 weeks)
- One commerce domain: `m2m_store` and `agentic_commerce` orders/receipts adopt the marketplace
  order model + ledger; delete duplicated tables.
- One x402 implementation (`payments/x402.py`), used by marketplace + voice.
- One budget/authorization chokepoint: Budget Guardian, autonomy, mandate check, and x402 gate compose
  in a single `authorize_payment()` (mirrors the `agentic_gate()` precedent) — no endpoint may move
  value without passing through it (ratchet-enforced).

### FT-7 · Assurance & Productization (ongoing)
- Property-based money-conservation tests (hypothesis): random operation sequences ⇒ Σ postings = 0,
  no negative available balance, idempotent replays are no-ops.
- Chaos tests: kill Postgres/Redis mid-flow, assert fail-closed on money + recon catches drift.
- SOC 2 control mapping for the ledger (extend `docs/soc2-evidence.md`); ledger export endpoint
  for auditors (JSONL, hash-chain verifiable — same UX as STIX export).
- Category marketing surface: "Agentic Commerce with a real ledger" — payout statements, recon
  dashboard (Streamlit + SOC dashboard page), public trust page with chain-verification.

### Sequencing & dependencies

```
FT-0 → FT-1 → FT-2 → FT-3 → FT-4 → FT-6
                     FT-5 (parallel from FT-3)
FT-7 continuous from FT-1
```

~10–12 weeks single-engineer pace. Each phase merges to main independently (deploy rule),
each adds its own ratchet so the invariant survives the autonomous loop.

## 5. What NOT to do

- Don't build real on-chain escrow custody before the FT-5 licensing decision.
- Don't weaken existing fail-open posture of the *security filter* pipeline — the split is deliberate.
- Don't open a separate DB-consolidation effort — ledger storage rides Track B's data-layer workstream.
- Don't migrate historical float rows in place; open ledger with opening balances and freeze old tables read-only.
