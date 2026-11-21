# Seller monetization — ladder and decisions (2026-11-21)

Source: the owner's monetization brief (2026-11-21). This file records what was
adopted, what was deferred and what was refused, and why. Canonical numbers
live in `warden/billing/pricing.py`; nothing here is a published price.

## Value metric

Sellers pay for what they protect — **catalog size (products) and channels
(stores)** — never a share of revenue. Printed labels are metered only on the
free plan (`labels_month`), because labels are the paid plans' everyday tool.

## Ladder (internal key → name)

| Key | Name | Price hypothesis (USD/mo) | Stores | Products | Languages | Labels / month |
|---|---|---|---|---|---|---|
| `store_free` | Free | 0 | 1 | 25 | 2 | 30 |
| `store_seller` | Guardian | 29 | 1 | 100 | 5 | unlimited |
| `store_business` | Shield | 79 | 3 | 500 | 5 | unlimited |
| `store_fortress` | Fortress | 199 | 10 | 5,000 | 5 | unlimited |

Annual prices are **derived** (`monthly × 12 × (1 − ANNUAL_DISCOUNT)`), never
typed; the brief's 10×-monthly figures are not used.

Departures from the brief, deliberately:
* Free keeps **25 products**, not 10. The storefront is also the free plan's
  advertisement; a ten-item shop sells nothing.
* Guardian holds **100** products, not 50, for the same reason, and because the
  limit gates the storefront too, not only compliance checks.

## Status: hypothesis, not a price list

`docs/capability-matrix.md` forbids publishing a store price until a payment
rail has settled a real charge. There is no registered company and no payment
rail for store plans, so these prices appear on **no** public surface. A plan
is reached today only by an operator grant or the single 14-day trial.

## Built now

* The ladder above, enforced on every store/product write (existing seam).
* `POST /m2m-store/labels/usage` — the free plan's label meter: one
  conditional upsert per calendar month, 403 `plan_limit` when over. The
  portal asks before it draws a PDF.

## Deferred (needs something that does not exist yet)

| Item from the brief | Waits for |
|---|---|
| Plan features: compliance audit, flat-file fixes, Telegram/WhatsApp alerts, VoC/NCX analysis, seats, several Seller Central accounts | The features themselves. A plan may only gate what is built |
| Rescue Pack ($49 one-off review) | A payment rail. Until then the free, manual catalog check on `/sellers` is the lead magnet |
| Affiliate revenue (EU responsible person, EPR, label printers) | Signed partner agreements, and disclosure next to every link |
| Lifetime early access ($99–149) | The owner's decision with an accountant: taking money as a private person, and in which country, is a tax and liability question, not a code one |
| Stripe Billing | The registered company (stage 4) |

## Refused

* **Crypto payments** for early access: no compliance story, and nothing in
  the stack verifies them.
* **A browser "local bridge" into Seller Central**: Amazon's 2026 agent policy
  routes automation through SP-API; scraping risks the seller's account.
* **The 12-month financial model as published numbers**: customer counts, ARPU
  and the "< $1.80 per user" cost are projections nobody measured. Unit cost is
  measured with `scripts/finops_report.py` once there is traffic.
