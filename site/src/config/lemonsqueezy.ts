/** Lemon Squeezy store configuration — update IDs after creating products in LS dashboard */

export const LS_STORE = 'shadowwarden';

/** Variant IDs (not product IDs) — each billing period is a separate variant */
export const VARIANT_IDS: Record<string, { monthly?: string; annual?: string; once?: string }> = {
  starter:           { once:    '100001' },          // free tier, direct link
  individual:        { monthly: '100002', annual: '100003' },
  communityBusiness: { monthly: '100004', annual: '100005' },
  pro:               { monthly: '100006', annual: '100007' },
  enterprise:        { once:    'contact' },          // contact sales

  // Add-ons (one-time or monthly)
  addonShadowAi:     { monthly: '200001' },
  addonXai:          { monthly: '200002' },
  addonSecretsVault: { monthly: '200003' },
  addonOnPrem:       { monthly: '200004' },
  addonSeats:        { monthly: '200005' },
  addonPowerBundle:  { monthly: '200006' },
};

export const CHECKOUT_BASE   = `https://${LS_STORE}.lemonsqueezy.com/checkout/buy`;
export const BILLING_PORTAL  = `https://${LS_STORE}.lemonsqueezy.com/billing`;
export const WORKER_API      = 'https://billing.shadow-warden-ai.workers.dev';

/** Build a Lemon Squeezy checkout URL with recommended params */
export function checkoutUrl(variantId: string, opts: { embed?: boolean; customerId?: string } = {}): string {
  if (variantId === 'contact') return 'mailto:sales@shadow-warden-ai.com';
  const url = new URL(`${CHECKOUT_BASE}/${variantId}`);
  if (opts.embed) { url.searchParams.set('embed', '1'); url.searchParams.set('media', '0'); }
  url.searchParams.set('logo', '0');
  url.searchParams.set('desc', '0');
  url.searchParams.set('discount', '0');
  url.searchParams.set('checkout[success_url]', 'https://shadow-warden-ai.com/thank-you?order_id={order_number}');
  if (opts.customerId) url.searchParams.set('checkout[custom][customer_id]', opts.customerId);
  return url.toString();
}
