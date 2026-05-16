/**
 * Shadow Warden AI — Billing Worker
 * Handles Lemon Squeezy webhooks and exposes a subscription status API.
 *
 * Setup:
 *   npx wrangler kv:namespace create BILLING_KV
 *   npx wrangler secret put LEMONSQUEEZY_WEBHOOK_SECRET
 *   npx wrangler deploy
 */

interface Env {
  BILLING_KV: KVNamespace;
  LEMONSQUEEZY_WEBHOOK_SECRET: string;
  ALLOWED_ORIGIN: string;
}

interface SubscriptionRecord {
  plan: string;
  variantName: string;
  status: string;           // active | cancelled | paused | past_due | expired
  renewsAt: string | null;
  endsAt: string | null;
  customerId: string;
  email: string;
  addons: string[];
  updatedAt: string;
}

// ── HMAC-SHA256 signature verification ───────────────────────────────────────

async function verifySignature(secret: string, body: string, signature: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const sigBytes = hexToBytes(signature);
  const bodyBytes = new TextEncoder().encode(body);
  return crypto.subtle.verify('HMAC', key, sigBytes, bodyBytes);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ── CORS helpers ──────────────────────────────────────────────────────────────

function corsHeaders(origin: string, allowedOrigin: string): Record<string, string> {
  const allowed = origin === allowedOrigin || origin === 'http://localhost:4321'
    ? origin
    : allowedOrigin;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

// ── Webhook event handler ─────────────────────────────────────────────────────

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const body = await request.text();
  const signature = request.headers.get('x-signature') ?? '';

  if (!signature) {
    return new Response('Missing signature', { status: 400 });
  }

  const valid = await verifySignature(env.LEMONSQUEEZY_WEBHOOK_SECRET, body, signature);
  if (!valid) {
    return new Response('Invalid signature', { status: 401 });
  }

  let payload: any;
  try { payload = JSON.parse(body); } catch {
    return new Response('Invalid JSON', { status: 400 });
  }

  const eventName: string  = payload.meta?.event_name ?? '';
  const attrs              = payload.data?.attributes ?? {};
  const customerId: string = String(attrs.customer_id ?? '');
  const email: string      = attrs.user_email ?? attrs.email ?? '';

  if (!customerId) {
    return new Response('No customer_id', { status: 422 });
  }

  // Read existing record (for addons merging)
  let existing: SubscriptionRecord | null = null;
  try {
    existing = await env.BILLING_KV.get<SubscriptionRecord>(`user:${customerId}`, 'json');
  } catch {}

  const record: SubscriptionRecord = {
    plan:        attrs.product_name  ?? existing?.plan        ?? 'Unknown',
    variantName: attrs.variant_name  ?? existing?.variantName ?? 'Unknown',
    status:      attrs.status        ?? existing?.status       ?? 'unknown',
    renewsAt:    attrs.renews_at     ?? attrs.next_billing_date ?? null,
    endsAt:      attrs.ends_at       ?? null,
    customerId,
    email:       email || (existing?.email ?? ''),
    addons:      existing?.addons ?? [],
    updatedAt:   new Date().toISOString(),
  };

  // Handle different event types
  switch (eventName) {
    case 'order_created':
      // One-time purchase or first order
      record.status = 'active';
      break;
    case 'subscription_created':
    case 'subscription_updated':
    case 'subscription_resumed':
      record.status = attrs.status ?? 'active';
      break;
    case 'subscription_cancelled':
      record.status = 'cancelled';
      record.endsAt = attrs.ends_at ?? null;
      break;
    case 'subscription_paused':
      record.status = 'paused';
      break;
    case 'subscription_expired':
      record.status = 'expired';
      break;
    case 'subscription_payment_success':
      record.status = 'active';
      record.renewsAt = attrs.next_billing_date ?? record.renewsAt;
      break;
    case 'subscription_payment_failed':
      record.status = 'past_due';
      break;
    default:
      // Unknown event — store but don't error
      break;
  }

  // Persist
  await env.BILLING_KV.put(
    `user:${customerId}`,
    JSON.stringify(record),
    { expirationTtl: 60 * 60 * 24 * 365 * 3 }  // 3 years
  );

  // Also index by email for lookups
  if (email) {
    await env.BILLING_KV.put(`email:${email.toLowerCase()}`, customerId);
  }

  return new Response(JSON.stringify({ ok: true, event: eventName }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Subscription status API ───────────────────────────────────────────────────

async function handleGetSubscription(
  request: Request,
  env: Env,
  customerId: string
): Promise<Response> {
  const origin = request.headers.get('Origin') ?? '';
  const headers = {
    'Content-Type': 'application/json',
    ...corsHeaders(origin, env.ALLOWED_ORIGIN),
  };

  if (!customerId || customerId.length > 64) {
    return new Response(JSON.stringify({ error: 'invalid_id' }), { status: 400, headers });
  }

  const data = await env.BILLING_KV.get<SubscriptionRecord>(`user:${customerId}`, 'json');
  if (!data) {
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers });
  }

  return new Response(JSON.stringify(data), { status: 200, headers });
}

async function handleLookupByEmail(
  request: Request,
  env: Env,
  email: string
): Promise<Response> {
  const origin = request.headers.get('Origin') ?? '';
  const headers = {
    'Content-Type': 'application/json',
    ...corsHeaders(origin, env.ALLOWED_ORIGIN),
  };

  const customerId = await env.BILLING_KV.get(`email:${email.toLowerCase()}`);
  if (!customerId) {
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers });
  }

  const data = await env.BILLING_KV.get<SubscriptionRecord>(`user:${customerId}`, 'json');
  if (!data) {
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers });
  }

  return new Response(JSON.stringify(data), { status: 200, headers });
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url    = new URL(request.url);
    const origin = request.headers.get('Origin') ?? '';
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin, env.ALLOWED_ORIGIN),
      });
    }

    // POST /webhook
    if (method === 'POST' && url.pathname === '/webhook') {
      return handleWebhook(request, env);
    }

    // GET /api/subscription/:customerId
    const subMatch = url.pathname.match(/^\/api\/subscription\/([^/]+)$/);
    if (method === 'GET' && subMatch) {
      return handleGetSubscription(request, env, subMatch[1]);
    }

    // GET /api/lookup?email=...
    if (method === 'GET' && url.pathname === '/api/lookup') {
      const email = url.searchParams.get('email') ?? '';
      if (!email) {
        return new Response(JSON.stringify({ error: 'email required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin, env.ALLOWED_ORIGIN) },
        });
      }
      return handleLookupByEmail(request, env, email);
    }

    // Health
    if (method === 'GET' && url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true, ts: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};
