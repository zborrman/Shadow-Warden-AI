# Money-Mutation Inventory (FT-0)

Date: 2026-07-18 · Track F · Companion to `warden/ledger/money.py`.
Purpose: the grep-able census of **every place value is created, moved, or
stored** today, so FT-1/FT-2 can migrate each to the double-entry journal and
the FT-0 ratchets can freeze the float surface. Regenerate with the commands in
§4; this is a snapshot, not a live view.

## 1. Storage of money (state that must become journal-derived)

| Store | Location | Type today | FT target |
|---|---|---|---|
| SAC wallet | `warden/sac/preflight.py` `sac_wallets(balance_micros, hold_micros)` | **integer µUSD** ✅ | thin adapter over `ledger/holds.py` (FT-2) |
| Flex Credits | `warden/marketplace/credits.py` — SQLite `marketplace_credits` + Redis `marketplace:credits:{tenant}` | integer credits, Redis `DECRBY`/`INCRBY` (l.219/228) | journal account `tenant:{id}:credits`; Redis = cache (FT-2) |
| Clearing log | `warden/marketplace/clearing.py` `marketplace_clearing_log` | `REAL` + `INSERT OR REPLACE` (l.185) | immutable postings; kill OR-REPLACE (FT-1/FT-3) |
| Escrow | `warden/marketplace/escrow.py` | `amount_usd REAL` | `escrow:{order_id}` account (FT-2) |
| x402 balances/deductions | `warden/marketplace/x402_gate.py`, `warden/voice/x402.py` | `REAL`, `x402_pending_deductions` queue | postings + settlement worker (FT-4) |
| Commerce mandates/orders | `warden/business_community/agentic_commerce/` | encrypted blobs / JSON | order model + journal (FT-6) |
| m2m_store orders | `warden/m2m_store/analytics.py` | `amount_usd REAL` | fold into one order model (FT-6) |
| Budget caps / spend | `warden/financial/budget.py`, `warden/marketplace/autonomy.py` | `REAL` | derived from journal rollup |
| Trial / bonus grants | Redis `finops:grant:*` (via `finops/wallet.py`) | integer, TTL | `promo:*` accounts (NF-1/FT-2) |

## 2. Float money surface (frozen by the FT-0 ratchet)

53 `REAL` money columns across ~20 modules. Highest concentration
(non-test): `marketplace/clearing.py` (4), `voice/x402.py` (3),
`staff/tools/growth.py` (3), `marketplace/autonomy.py` (3),
`m2m_store/analytics.py` (3), `financial/budget.py` (3), `app_factory.py` (3),
`tokenomics/outcome_pricing.py` (2), `marketplace/x402_gate.py` (2),
`billing/__init__.py` (2). Plus float arithmetic: `finops/wallet.py`
(`round(x, 6)`), `ClearingResult` Decimal→float on store.

**Ratchet rule:** no *new* `REAL` money column and no *new* float arithmetic on
a money path in `billing|marketplace|business_community|finops|m2m_store|
tokenomics|voice|financial`. Existing rows are frozen read-only and migrated via
opening-balance journal entries (FT-2) — never rewritten in place.

## 3. Idempotency / conservation gaps (fixed FT-3)

- `INSERT OR REPLACE` on financial tables rewrites history — `clearing.py:185`
  (and the broader marketplace set catalogued in the commerce plan §3.4).
- No `Idempotency-Key` requirement on buy / accept_offer / fund / clear /
  credit-purchase — a retried webhook can double-move value.
- Redis `DECRBY` (credits) and its SQLite row can drift — no reconciliation.

## 4. Regeneration commands

```bash
# REAL money columns, grouped by file
grep -rnoiE "\w*(usd|cents|credits|price|amount|budget|spend|balance|fee)\w*\s+REAL" \
  warden/ --include="*.py" | sed -E 's/:[0-9]+:.*//' | sort | uniq -c | sort -rn

# financial INSERT OR REPLACE
grep -rn "INSERT OR REPLACE" warden/marketplace warden/billing warden/voice --include="*.py"

# redis money counters
grep -rniE "decrby|incrby" warden/ --include="*.py" | grep -iE "credit|balance|spend"
```

## 5. Migration order (from the kickoff plan)

FT-1 journal core → FT-2 migrate the §1 stores (credits, wallet funding,
preflight holds; trial/bonus as `promo:*`) → FT-3 idempotency + kill
OR-REPLACE → FT-4 settlement drains x402/clearing → FT-6 fold m2m_store /
commerce order models into one. The §1 rows are opened with opening-balance
entries; §2 columns are frozen, not rewritten.
