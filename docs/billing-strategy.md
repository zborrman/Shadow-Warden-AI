# Billing Strategy — how each plan gets paid for

**Date:** 2026-08-07 · **Status:** decided, rail split implemented
**Related:** `docs/monetization-plan.md` (what we charge), this document (how we collect it)

---

## 1. The constraint

Lemon Squeezy is a **merchant of record**. It does not process our payments — it
*makes the sale*. LS is the seller on the customer's statement, LS owns the
contract with the buyer, LS registers and remits VAT/sales tax in every
jurisdiction, and LS pays us out afterwards.

For a solo operator that is an enormous win. Selling software globally as an
individual otherwise means VAT registration in the EU, sales-tax nexus tracking
across US states, and invoicing rules per country. An MoR absorbs all of it.

It is also, by construction, incompatible with enterprise procurement:

| Enterprise buyer needs | Under a merchant of record |
|---|---|
| MSA and DPA signed **with the vendor** | The contract is with LS, not with us |
| Invoice addressed to their company, carrying their PO number | LS issues a consumer-style receipt |
| Net-30/60, paid by bank transfer from AP | Card at checkout |
| Vendor onboarding: company registration number, W-8BEN-E/W-9, sometimes insurance | Nothing to onboard — LS is the counterparty |
| Security questionnaire answered by the party under contract | The party under contract is a payments company |

**No billing configuration fixes this.** It is not a Lemon Squeezy limitation to
work around; it is what an MoR *is*. The mistake would be trying to push
Enterprise through it anyway — the first security review asks for a DPA signed
by the data processor, and there is nobody to sign it.

---

## 2. The decision: two rails

| Segment | Rail | Why |
|---|---|---|
| Starter → Pro (self-serve) | **Lemon Squeezy, MoR** | Card checkout, no tax registrations, sellable as an individual. This is the majority of transactions and exactly what MoR is good at. |
| Enterprise | **Stripe Invoicing, direct** | Company-addressed invoice, PO number, net terms, bank transfer. We are the seller of record — which is the point. |

Enterprise already had no self-serve checkout (`enterprise: { once: 'contact' }`).
That was correct; what was missing was anything behind the "contact".

### Tax consequence, stated plainly

On the Stripe rail we become merchant of record and the tax position is ours.
This is materially smaller than it sounds for the Enterprise segment:

- **EU B2B with a valid VAT ID → reverse charge.** We invoice without VAT; the
  buyer self-accounts. This covers most of the target market.
- **UK/US B2B** — B2B software sales generally do not create an immediate
  registration obligation at low volume, and Enterprise is low-volume by
  definition (a handful of deals, not a stream).
- The self-serve long tail — the part that *would* create real tax surface —
  stays on the MoR.

This is the shape of the trade: keep the MoR exactly where volume and
jurisdictional spread are high, take direct billing exactly where contract
control matters and volume is low.

---

## 3. What was built

| Change | Where |
|---|---|
| `create_enterprise_invoice()` — Stripe invoice, `collection_method="send_invoice"`, net terms, PO number in metadata, priced from the canonical list | `warden/stripe_billing.py` |
| `POST /billing/enterprise/quote` — admin-gated; prices a deal, optionally raises the invoice | `warden/billing/router.py` |
| `pqc_pack` (+$19/mo) and `sovereign_pack` (+$25/mo) — Pro+ add-ons unlocking `pqc_enabled` / `sovereign_enabled` | `warden/billing/addons.py` |
| 18 tests | `warden/tests/test_enterprise_billing.py` |

Two deliberate details:

**The invoice is finalised but not sent by default.** Finalising turns a draft
into a numbered document with a hosted payment page; sending puts it into the
buyer's AP system, where it cannot be quietly corrected. Those are different
acts and the code keeps them separate (`auto_send=False`).

**An unconfigured Stripe returns the quote, not a 500.** Stripe not being set up
is an operator state; the price is correct regardless. The caller gets the quote
with `invoice_error` attached rather than losing the whole response.

### Unbundling PQC and Sovereign

These were reachable only by buying Enterprise — a plan with no self-serve
checkout. The two most differentiated features in the product were therefore
unpurchasable by anyone able to click "buy". As Pro+ add-ons they are payable by
card on the MoR rail; Enterprise keeps them bundled.

Pro + both packs = **$143.99/mo** against Enterprise at $249. That gap is
intentional: the packs are features, Enterprise is features *plus* a contract,
an SLA and a signature. If the packs ever priced close to Enterprise they would
cannibalise it rather than feed it.

---

## 4. When to register a legal entity

Not yet — but the trigger is specific.

A sole proprietor is a legal person and can sign contracts. The blocker is not
legal capacity, it is **supplier onboarding**: corporate procurement portals
generally require a company registration number, a tax form matching a legal
entity, and often liability insurance. An individual frequently cannot be
created as a vendor record at all, regardless of what was negotiated.

**Register when there are 2–3 real Enterprise leads in the pipeline** — not
before. Cost is roughly $300–1 500/yr (Estonia OÜ, UK Ltd, US LLC). Registering
speculatively buys an accounting obligation and nothing else.

Registering also unlocks the AWS / Azure / Google Cloud marketplaces (BL-21),
where the marketplace itself is the merchant and handles procurement — the
cleanest enterprise motion available, and closed to individuals.

---

## 5. Sequence

1. **Now** — Enterprise deals close as Stripe invoices via
   `POST /billing/enterprise/quote`. PQC and Sovereign sell self-serve at Pro.
   Advertise only what can be delivered: no SOC 2 attestation language, no
   uptime SLA that has not been agreed.
2. **At 2–3 Enterprise leads** — register the entity. Move the Enterprise rail
   under it; self-serve stays on LS.
3. **Once the entity exists** — evaluate cloud marketplaces. Also reconsider
   consolidating self-serve onto Stripe: LS was acquired by Stripe, so the two
   rails converge on one vendor, though the MoR/direct distinction remains real
   and is the thing that matters here.

---

## 6. Open — blocks revenue today

**`site/src/config/lemonsqueezy.ts` still ships placeholder variant IDs**
(`100002`…`200006`), the sequential dummies its own header says to replace once
the products exist in the LS dashboard. Server-side variant IDs come from env
and default to empty, which is correct; the site's are hardcoded.

If those were never swapped for real IDs, **every self-serve checkout button on
the marketing site leads to a dead link** — which outranks every pricing
question in this document and in the monetization plan. Verifying needs access
to the Lemon Squeezy dashboard.

One upside if true: nothing has been sold through that path yet, so the cost of
choosing rails now is close to zero.
