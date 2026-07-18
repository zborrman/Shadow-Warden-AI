# Fintech Architecture — Canonical Money-Layer Structure

Date: 2026-07-18 · Status: TARGET BLUEPRINT (structure, not roadmap)
Companions: `docs/fintech-grade-commerce-plan.md` (FT-\* roadmap),
`docs/fintech-development-plan.md` (FM-\* FinOps roadmap),
`docs/integration-research-tunnel-sac-marketplace-gsam.md` (MI/NF findings).
This document defines **what goes where** when those roadmaps execute. Ownership:
FT owns money semantics, Track B (DE) owns the storage substrate, Track C (FM)
owns cost/margin math. One structure, three tracks.

---

## 1. Layer model

```
┌────────────────────────────────────────────────────────────────────┐
│ L5  PRODUCT SURFACES   marketplace · agentic_commerce · m2m_store  │
│     (order flows)      staff agents · SOVA/Master · MCP gateway    │
├────────────────────────────────────────────────────────────────────┤
│ L4  AUTHORIZATION      authorize_payment() — single chokepoint     │
│     (fail-CLOSED)      autonomy L1/L2/L3 · mandates · budget ·     │
│                        x402/L402 · GSAM quarantine · preflight     │
├────────────────────────────────────────────────────────────────────┤
│ L3  MONEY CORE         warden/ledger/ — double-entry journal,      │
│     (source of truth)  Money(int micro-USD), holds, idempotency    │
├────────────────────────────────────────────────────────────────────┤
│ L2  SETTLEMENT & RECON outbox → Postgres/STIX · settlement worker  │
│                        payout statements · nightly recon           │
├────────────────────────────────────────────────────────────────────┤
│ L1  ANALYTICS (OLAP)   GSAM ClickHouse mv_billing_rating ·         │
│     (fail-OPEN, read)  margin alerts · BI/growth accounting        │
├────────────────────────────────────────────────────────────────────┤
│ L0  COMPLIANCE SPINE   KYB/KYC · sanctions · AML monitors ·        │
│                        audit chains (hash/STIX) · GDPR retention   │
└────────────────────────────────────────────────────────────────────┘
```

Posture rule (mirror of the SAC split): **L4/L3 fail-CLOSED** (exception ⇒
deny/503), **L1 fail-OPEN** (analytics never blocks money), L2 at-least-once
with reconciliation. The security *filter* pipeline keeps its own fail-open
posture — the two never mix.

## 2. Target package structure

```
warden/ledger/                     ← NEW (FT-0/FT-1) — the money core
    money.py        Money = int micro-USD; Decimal only at API boundary; pure
    accounts.py     chart of accounts, account-id grammar, type registry
    journal.py      append-only balanced postings (Σ=0), hash-chained,
                    UNIQUE(idempotency_key); no UPDATE/REPLACE ever
    holds.py        two-phase: pending tx → capture | void  (absorbs
                    sac/preflight semantics; preflight becomes a caller)
    rollup.py       derived balances (materialized, GSAM-rollup pattern);
                    Redis = cache of rollup, never source of truth
    outbox.py       transactional outbox → Postgres mirror / STIX relay
    recon.py        journal ⟷ processor reports ⟷ CH ledger drift jobs
    export.py       auditor JSONL export, chain-verifiable (STIX-export UX)

warden/payments/                   ← CONSOLIDATED (FT-6)
    x402.py         single x402 impl (replaces marketplace/voice copies)
    l402.py         existing
    authorize.py    authorize_payment(tenant, agent, action, amount, ctx)
                    = autonomy → mandate → budget → funds(hold) → quarantine;
                    the agentic_gate() analogue for value movement
    settlement.py   ARQ worker: pending deductions + take-rate → postings,
                    per-seller payout statements

warden/billing/                    ← EXISTING, re-pointed
    availability.py available_usd() (FM-1) reads ledger rollup
    referral.py     monetary kickback → promo:bonus postings (NF-2)
    audit_chain.py  absorbed as the journal's hash-chain primitive

warden/compliance_fin/             ← NEW (FT-5)
    kyb.py          owner-entity verification behind KYA (provider-pluggable)
    sanctions.py    reuses staff screen_sanctions_list at onboarding+settlement
    aml.py          velocity/structuring/circular-flow monitors on the
                    journal stream → incident_register (STIX-linked)

warden/marketplace/mediator.py     ← NEW (NF-5/MI) — detect→enforce:
                    MAESTRO flags → bounded fee surcharge / reputation
                    penalty, expressed as ledger postings (auditable)
```

Storage: one `warden_ledger.db` via `open_db()` + `ddl_registry` +
`data_path("warden_ledger.db", "LEDGER_DB_PATH")` — rides DE-6, no new
patterns. ClickHouse stays analytics-only; request paths never read it.

## 3. Chart of accounts

Account id grammar: `<type>:<owner>[:<segment>]`, types are closed enum.

| Account | Type | Meaning |
|---|---|---|
| `tenant:{id}:cash` | liability | prepaid deposits owed to tenant |
| `tenant:{id}:credits` | liability | Flex Credits (1 credit = 1 000 µUSD) |
| `promo:{id}:trial` / `promo:{id}:bonus` | liability (promo) | welcome trial, referral kickback — spend order trial → bonus → cash |
| `hold:{hold_id}` | contra | two-phase reservations (preflight, escrow) |
| `escrow:{order_id}` | liability | in-flight order funds |
| `platform:fees` | revenue | take-rate, surcharges (incl. mediator penalties) |
| `platform:promo_expense` | expense | funding source of trial/bonus grants |
| `processor:{name}:clearing` | asset | Lemon/Stripe/USDC receivable — recon anchor |

Canonical flows (each a balanced posting set): top-up (processor→cash),
session hold (cash→hold, then hold→platform:fees + remainder back),
marketplace purchase (cash→escrow→seller cash + platform:fees),
referral grant (promo_expense→bonus), mediator surcharge (seller cash→fees).

## 4. Invariant matrix (ratchet-enforced)

| # | Invariant | Enforcement |
|---|---|---|
| I1 | Σ postings per tx = 0; journal immutable | journal.py + property tests (hypothesis) |
| I2 | No float on money paths; no new `REAL` money columns | ratchet test (FT-0) |
| I3 | Money authorization fail-CLOSED; filter stays fail-OPEN | posture doc + contract tests |
| I4 | Every value movement passes `authorize_payment()` | route-inventory-style ratchet |
| I5 | Idempotency-Key required on buy/fund/clear/credit endpoints | journal UNIQUE + API guard |
| I6 | Keys per-call via `resolve_key()` (fixes AP2 snapshot) | existing signing-key ratchet |
| I7 | Balances derived, never mutated counters | rollup.py sole reader path |
| I8 | CH ledger ⟷ SQLite costs reconcile within 2% weekly | recon.py drift test (FM-2) |
| I9 | GDPR: ledger rows metadata-only, 0700 data dir, retention in DPIA | existing S1 guardrails |

## 5. Cross-subsystem integration (from the MI research)

- **SAC preflight** → thin adapter over `ledger/holds.py`; wallet formula
  unchanged (`available = cash + trial + bonus − holds`).
- **GSAM** → cost rating (mv_billing_rating) feeds commit amounts and margin
  alerts; quarantine is a deny input to `authorize_payment()` (MI-2).
- **Marketplace** → clearing/escrow/x402 become journal writers (MI-1 emits
  the observation, the journal records the money — two streams, one event).
- **Mediator** → game-theoretic corrections land as auditable postings, never
  hidden balance edits.
- **Tunnel/Sovereign** → settlement runs record jurisdiction + attestation id
  in posting metadata (cross-border audit trail; MI-5 v1).

## 6. Explicitly out of structure

Prisma/NestJS/TS money services, on-chain custody before the FT-5 licensing
decision, MILP allocator until ≥2 nodes, eBPF sensors, any second ledger or
balance counter outside `warden/ledger/`.
