/**
 * Canonical list prices, mirrored from `warden/billing/pricing.py`.
 *
 * Not a second opinion — a mirror. The Python table is what the billing system
 * actually charges; TypeScript cannot import it, so the numbers are duplicated
 * here and `warden/tests/test_dashboard_pricing_mirror.py` fails if the two
 * ever disagree. Without that pin this file would be a fourth price list, and
 * the repo already had three that did not agree with each other (FM-7).
 *
 * The drift this replaced was not cosmetic: `roi/page.tsx` divided savings by
 * $69 to produce an "ROI Multiple", so every multiple on the page was inflated
 * by about 45% against the $99.99 the customer is billed.
 *
 * Annual prices are derived, never typed — same rule as the Python side.
 */

export const TIER_MONTHLY_USD = {
  starter: 0,
  individual: 5,
  community_business: 39.99,
  pro: 99.99,
  enterprise: 249,
} as const;

export type TierId = keyof typeof TIER_MONTHLY_USD;

/** Annual billing discount applied to 12x the monthly list price. */
export const ANNUAL_DISCOUNT = 0.15;

export function monthlyPriceUsd(tier: TierId): number {
  return TIER_MONTHLY_USD[tier];
}

/**
 * Annual list price, or `null` where there is no annual plan to sell.
 *
 * `null`, not 0. `warden/billing/pricing.py::annual_price_usd` returns None for
 * a zero-priced tier, and a mirror that returns 0 lets a caller render — or
 * submit — a "$0/year" plan that does not exist. Mirroring the numbers and not
 * the contract is only half a mirror.
 */
export function annualPriceUsd(tier: TierId): number | null {
  const monthly = TIER_MONTHLY_USD[tier];
  if (!monthly) return null;
  return Math.round(monthly * 12 * (1 - ANNUAL_DISCOUNT) * 100) / 100;
}

/** `$99.99/mo`, or `Free` for a zero-priced tier. */
export function formatMonthly(tier: TierId): string {
  const p = TIER_MONTHLY_USD[tier];
  return p === 0 ? "Free" : `$${p}/mo`;
}
