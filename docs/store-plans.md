# Store plans — tariffs, limits, bonuses and the architecture behind them

Status: **limits and entitlements are built and enforced. Prices, discounts and
bonuses are a hypothesis** — nothing can be bought, and no surface publishes
them. Decided 2026-11-14, after `docs/surface-decision-2026-11-14.md`.

## Why this exists

The shop is the primary product (owner decision, 2026-11-12). Until this change
it had no price, no limits and no row in `warden/billing/pricing.py`: the whole
ladder there sells gateway requests. A product with no plan cannot be piloted
honestly — there is nothing to tell a seller about what is free and what is not.

## The ladder

| | `store_free` | `store_seller` | `store_business` |
|---|---|---|---|
| Price / month (hypothesis) | $0 | $15 | $39 |
| Price / year (derived, −15%) | — | $153.00 | $397.80 |
| Stores | 1 | 1 | 5 |
| Products | 25 | 500 | 5,000 |
| Storefront languages | 2 | 5 | 5 |
| Photos per product | 8 | 8 | 8 |
| Order requests | unlimited | unlimited | unlimited |
| Monthly inference budget | $0.50 | $3.75 | $9.75 |

Two things are **deliberately unlimited on every plan**:

* **Order requests.** A cap on orders punishes a seller for succeeding, and the
  platform moves no money, so there is nothing to meter.
* **Photos.** A thin storefront sells nothing and makes the free plan a bad
  advertisement for the paid one.

The inference budget is the existing formula, `price × (1 − TARGET_GROSS_MARGIN)`,
so "what we charge" and "what we may spend serving it" remain one decision. It
is defined but **not yet consumed**: nothing in the store calls a model today.

### Planned limits — not in the table until the feature exists

CRM contacts and label prints (R8), category analyses (R9). An allowance for a
feature a plan cannot deliver is a promise the product does not keep; these
enter `STORE_PLAN_LIMITS` in the PR that ships the feature, not before.

## Bonuses

| Bonus | What the seller gets | Abuse control | State |
|---|---|---|---|
| **Trial** | 14 days of `store_seller`, no card | One per tenant for the life of the tenant — a PRIMARY KEY insert, so a second attempt loses in the database. A refused attempt does not burn it. Never overrides an active plan. | **built** |
| **Founding seller** | An operator grant (`source: founding`), for the pilot | Operator-only, audited, expiry optional | **built** |
| **Annual** | −15% for paying yearly | Derived from the monthly price; never typed in | designed — needs a payment rail |
| **Referral** | One free month for both sides | Credited only after the referred seller's **first paid invoice**; clawed back on refund; at most 6 free months per seller per year; self-referral refused by payment fingerprint | designed — needs a payment rail |
| **Activation** | A one-off top-up of the inference budget on publishing a store with five products | Once per tenant; bounded by the platform cost centre | designed — needs a consumer of the budget |

Bonuses do not stack beyond one free month at a time, and none of them is
published until a real charge has settled: a discount on a price nobody can pay
is a claim.

## Architecture

### The entitlement is a local row

`m2m_store_plans` holds one row per tenant: plan, source, who granted it, when
it expires. A plan is **never** resolved from a payment provider at read time.
Whoever sells the plan only *writes* that row — the operator today
(`PUT /m2m-store/admin/plans/{tenant_id}`), a verified subscription webhook once
a rail exists.

Consequences:

* A provider outage can delay an upgrade. It cannot lock a paying seller out of
  their own shop.
* Nothing a caller sends can raise a plan. No seller-facing route takes a plan
  name; the trial route ignores its body.
* Adding the payment rail later changes **one writer**, not the read path, the
  limits or the tests.

### Decisions, by criterion

| Criterion | Decision |
|---|---|
| **Authorization** | The tenant is always the one the route resolved from its own credentials. Only the operator may act on a named tenant, through an admin dependency that answers 503 — not open — when `ADMIN_KEY` is unset. |
| **Concurrency** | Each limit is one conditional `INSERT … SELECT … WHERE (SELECT COUNT(*)) < ?`. Production runs four workers; count-then-insert in Python lets all four see room for the last slot. |
| **Secure by default** | Enforcement lives in the functions that write the rows (`storefront.create_store`, `inventory.add_product`), not in the routes. A new caller cannot forget it. |
| **Fail-safe resolution** | No row, an expired row, or a row naming a plan that no longer exists resolves to the default plan — never to an error, never to "unlimited". |
| **Data safety** | Going over a limit (downgrade, expired trial) blocks only *new* stores and products. Nothing is deleted, unpublished or hidden; export keeps working. |
| **Auditability** | Every grant, revoke and trial start appends to `m2m_store_plan_events` with the actor. The operator reads it back with `GET /m2m-store/admin/plans/{tenant_id}`. |
| **Privacy** | The plan tables hold a tenant id and a plan name. No personal data, nothing to seal. |
| **Claims** | No route returns a price. Paid plans cannot be bought, so a served price would be a public claim (capability matrix). A test pins this. |
| **Single source** | Limits and prices live in `pricing.py` and nowhere else; the annual price is derived. A test asserts the ladder is monotone. |
| **Surface** | Five routes inside the existing store router; no new router, package or frontend. |
| **Reversibility** | `DELETE /m2m-store/admin/plans/{tenant_id}` returns a tenant to the default plan with its data intact. |

### What the refusal looks like

```
HTTP 403
{"detail": {"error": "plan_limit", "limit": "products", "max": 25, "plan": "store_free"}}
```

403 rather than 402, following the add-on gate's convention: 403 is "your plan
does not include this", 402 is "your plan allows it and it is unpaid".

## Not built here, on purpose

* **Checkout.** There is no payment rail and no legal entity.
* **A take rate.** The store's `PAID` status is the seller's own word; turnover
  is not visible to the platform and cannot be audited. A commission needs
  payments on the platform first.
* **Portal UI** for the plan card and the upgrade prompt — the API carries
  everything it needs (`GET /m2m-store/plan`).
* **A "powered by" badge** on free storefronts.
* **Metering of the inference budget.**

## Exit condition for the hypothesis

The prices above are tested by the seller pilot, not by this document. If fewer
than two of five pilot sellers publish a store within 30 days, the problem is
the product, not the price, and R8 (CRM, labels) is not built.
