# Shadow Warden AI — Money-Transmission Licensing Posture

**Document type:** Internal technical assessment (FT-5, Track F)
**Version:** 1.0 · **Date:** 2026-07-21
**Prepared by:** Engineering (Claude Code), for review by qualified counsel
**Review cycle:** Before any change to a money flow listed in §2; otherwise annual

---

## 0. Disclaimer

**This is not legal advice.** It is a technical description of how money and
money-denominated value move through the system, written so counsel can map
it against FinCEN MSB registration, state money-transmitter statutes, and EU
e-money/PSD2 rules without having to read source code. No conclusion in this
document should be relied on as a compliance determination. If §2's
architecture changes — especially anything that lets a tenant pull value back
out as cash — this document is stale until re-reviewed.

---

## 1. Summary Position

Shadow Warden AI's money-denominated flows are, as implemented today, a
**closed-loop, non-redeemable service-credit system**: value enters the
system only through a payment processor acting as merchant of record, is
consumed only as internal accounting units against the platform's own
services, and has **no path back out to cash, a bank account, or a third
party**. Under that architecture the system's own money handling most
resembles prepaid service credit / stored-value-for-own-goods-and-services —
a fact pattern that most US state money-transmitter statutes and FinCEN's MSB
definition explicitly carve out, and that does not fit the EU e-money
definition (no claim on the issuer redeemable at par). The exception —
platform-mediated escrow between two *different* tenants' agents in the M2M
marketplace (§2.3) — is architecturally the same closed-loop credit, not
fiat, but is flagged separately because escrow-between-third-parties is the
single fact pattern regulators scrutinize most closely, and it is the part
of the system most likely to change shape as the marketplace matures.

**This posture depends entirely on §4's invariants holding.** It is not a
static conclusion — it is conditional on nothing in the codebase ever adding
a cash-out, bank-payout, or stablecoin-redemption path for internal credits.

---

## 2. Money Flow Inventory

### 2.1 Subscription & add-on billing (fiat in)

**Code:** `warden/billing/router.py`, `warden/billing/addons.py`, `warden/billing/overage.py`

All fiat payment collection (tier subscriptions $0–$249/mo, add-ons, overage
packs) is a redirect to **Lemon Squeezy checkout**. Lemon Squeezy is the
**merchant of record** for these transactions — it collects the card/bank
payment, handles sales tax/VAT remittance, and is the counterparty on the
cardholder's statement. Shadow Warden AI never touches card numbers, bank
account numbers, or settlement funds for this flow; it only receives a
webhook confirming payment and grants entitlements (`warden/billing/router.py`
webhook handlers → `TIER_LIMITS`/addon grants). `POST/DELETE
/billing/addons/grant|revoke` require `X-Admin-Key` — no path from a tenant
request to a fiat movement without going through Lemon Squeezy first.

**Assessment:** standard SaaS billing via a payment-facilitator MoR. Not a
money-transmission fact pattern.

### 2.2 Internal service credits & SAC wallet (accounting units, not fiat)

**Code:** `warden/marketplace/credits.py`, `warden/sac/preflight.py`,
`warden/ledger/` (journal, accounts, holds, operations)

"Credits" purchased via §2.1 and the SAC preflight wallet's `balance_micros`
are internal integer micro-USD accounting units (`warden/ledger/money.py::Money`)
tracked in the platform's own SQLite/ledger tables. Grep across `warden/`
found **no** `redeem`, `payout`, `cash_out`, `bank_account`, `ach_transfer`,
or `stripe...connect` code path — confirmed 2026-07-21 as part of this
review. Credits are consumed only by:

- The SAC preflight two-phase hold (`reserve`→`commit`/`release`) metering an
  agent run's own LLM cost against the tenant's own balance.
- `platform_fees()` / `tenant_credits()` ledger accounts — both are the
  *platform's* books, not a claim any tenant can present elsewhere.

**Assessment:** this is the platform selling its own prepaid service credit,
consumed only against its own services. It is not a stored-value instrument
usable to pay third parties, and there is no redemption path. This is the
strongest and least-ambiguous part of the system's posture.

### 2.3 M2M marketplace escrow & clearing (tenant-to-tenant, still credits)

**Code:** `warden/marketplace/api_escrow.py`, `warden/marketplace/clearing.py`,
`warden/marketplace/listing.py`

The agent-to-agent marketplace holds a buyer's credits in escrow
(fund→deliver→confirm/dispute→resolve state machine) and, on clearing,
moves the winning negotiation's credits from the buyer's ledger account to
the seller's — both **internal ledger accounts on the platform's own books**
(`warden/ledger/accounts.py`: `tenant_credits`, `hold`, `platform_fees`), not
a transfer of custody over external fiat. No step in `clearing.py` or
`api_escrow.py` initiates a transfer to a bank account, card, or blockchain
address outside the platform.

**Assessment:** structurally this is escrow-and-clearing *between two
different tenants*, which is the fact pattern regulators look at hardest —
even though the underlying unit is a non-redeemable internal credit, not
fiat. Flagged as the highest-attention item in §5 because: (a) it is the one
flow where "platform's own books" could stop being true if a future feature
lets a seller cash out accumulated credits, and (b) "credits, not dollars"
is a legal characterization question, not just a technical one — this
section should be the first thing counsel reviews.

### 2.4 x402 nanopayments (metering, same accounting units)

**Code:** `warden/marketplace/x402_gate.py`, `warden/workers/x402_settlement.py`

x402 deducts credits per paid request/tool-call and settles pending
deductions from `x402_pending_deductions` into the same internal ledger
model as §2.2 — same posture, same absence of a cash-out path. `x402
fail-open` (protected invariant, `CLAUDE.md`) governs availability, not
custody of funds; it has no bearing on the licensing question.

**Assessment:** same as §2.2 — internal metering, not money transmission.

### 2.5 PQC / crypto / blockchain surfaces (not payment rails)

**Code:** `warden/crypto/pqc.py`, `warden/blockchain/`, Sepolia mandate contract

Post-quantum crypto (`HybridSigner`/`HybridKEM`) is used for signing and key
exchange, not for moving value. The Sepolia Web3 mandate contract (Agentic
Commerce, CM-40) is testnet infrastructure for AP2 mandate signatures, not a
live payment rail moving real value. Neither was found to touch fiat or a
redeemable token.

**Assessment:** out of scope for money-transmission analysis as currently
implemented; re-review if the Web3 mandate contract is ever pointed at
mainnet with real-value settlement.

---

## 3. Regulatory Frames This Maps To (for counsel, not a conclusion)

| Frame | Relevant question | Where in this doc |
|---|---|---|
| FinCEN MSB (31 CFR 1010.100(ff)) | Does the entity accept and transmit currency/funds/value on behalf of another person? | §2.2/§2.3 — internal credits only, no cash-out |
| State money-transmitter statutes (varies) | Many states carve out "stored value redeemable only for the issuer's own goods/services" | §2.2 is the strongest fit for this carve-out; §2.3 is the same carve-out but between two *different* customers |
| EU EMD2 / e-money definition | Is the instrument a claim on the issuer, redeemable at par in cash? | Credits are not redeemable at all — does not meet the e-money definition as implemented |
| PSD2 payment services | Does the platform provide payment initiation/account information services to third parties? | Not applicable — Lemon Squeezy is the payment facilitator for fiat-in; no fiat-out exists |

---

## 4. Invariants This Posture Depends On

If any of the following becomes false, this document must be re-reviewed
before shipping the change that makes it false:

1. **No redemption path.** Internal credits (marketplace, SAC wallet, x402)
   are never convertible back to fiat, a bank transfer, a card refund of
   accumulated (not just originally-paid) balance, or a transferable token.
2. **No third-party payout.** No code path sends funds to a bank account,
   card, or wallet address that isn't the platform's own payment processor
   settlement account.
3. **Fiat-in stays behind the MoR.** All card/bank collection continues to
   go through Lemon Squeezy (or an equivalent MoR) — the platform does not
   become the payment facilitator of record for card/ACH collection.
4. **Escrow settles to internal accounts only.** `clearing.py`'s buyer→seller
   movement stays a ledger-account transfer on the platform's own books, not
   a trigger for an external transfer.

`test_no_new_real_money_columns.py` and the ledger's `Money`
integer-micro-USD-only invariant (`warden/ledger/money.py`) are the closest
existing automated proxies for #1/#2, but neither is a semantic check that a
redemption feature was never added — this is a **process control**
(re-review §2.3/§2.4 in code review whenever they change), not an automated
one, and should stay that way unless a specific ratchet is designed for it.

---

## 5. Recommended Next Steps (not part of this technical review)

1. Counsel review of §2.3 (marketplace escrow) specifically — confirm the
   "own books, non-redeemable" characterization holds under the target
   jurisdictions' statutes, not just as a technical description.
2. If/when a seller cash-out feature is scoped for the marketplace, treat it
   as a **new regulatory review trigger**, not an engineering task that ships
   under the existing posture.
3. No FinCEN MSB registration or state money-transmitter license appears
   warranted for the system **as currently implemented** — pending #1.
