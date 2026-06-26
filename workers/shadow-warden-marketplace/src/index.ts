// shadow-warden-marketplace — Cloudflare Worker v1.0
// Agentic M2M Marketplace: agent registry, listings, negotiations, clearing, ADP
// Patterns: same as shadow-warden-billing (KV state, CORS helper, X-Admin-Key, /health)

const VERSION = "1.0.0";
const TAKE_RATE = 0.015; // 1.5% platform fee — logged only, no on-chain settlement in v1
const SPONSORED_BOOST = 0.15; // +15% similarity boost, applied in memory (not in KV sort)
const MAX_LISTING_INDEX = 1000;
const MAX_NEGOTIATION_ROUNDS = 10;

// ── Types ──────────────────────────────────────────────────────────────────

interface Env {
  MARKETPLACE_KV: KVNamespace;
  ADMIN_KEY?: string;
  ALLOWED_ORIGIN?: string;
  WARDEN_BACKEND_URL?: string;
  WARDEN_API_KEY?: string;
}

interface AgentRecord {
  did: string;
  name: string;
  capabilities: string[];
  pubkey: string;
  registered_at: string;
  updated_at: string;
  trust_score: number;
  is_sponsored: boolean;
}

interface ListingRecord {
  id: string;
  title: string;
  description: string;
  asset_type: string;
  price_usd: number;
  seller_did: string;
  tags: string[];
  is_sponsored: boolean;
  sponsored_until: string | null;
  sponsored_boost: number; // always SPONSORED_BOOST or 0 — never in SQL ORDER BY
  created_at: string;
  updated_at: string;
}

interface OfferRecord {
  from_did: string;
  amount_usd: number;
  message: string;
  timestamp: string;
}

interface NegotiationRecord {
  id: string;
  listing_id: string;
  buyer_did: string;
  seller_did: string;
  status: "pending" | "offered" | "accepted" | "rejected" | "cleared";
  offers: OfferRecord[];
  created_at: string;
  updated_at: string;
}

interface ClearingResult {
  negotiation_id: string;
  listing_id: string;
  buyer_did: string;
  seller_did: string;
  agreed_price_usd: number;
  platform_fee_usd: number; // TAKE_RATE × agreed_price — logged only in v1
  seller_net_usd: number;
  cleared_at: string;
  settlement_status: "logged"; // always "logged" in v1; "settled" in v2 (Circle)
}

// ── Helpers ────────────────────────────────────────────────────────────────

function json(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...extra },
  });
}

function corsHeaders(origin: string, allowed: string): Record<string, string> {
  const o =
    origin === allowed || origin === "http://localhost:4321" || origin === "http://localhost:3000"
      ? origin
      : allowed;
  return {
    "Access-Control-Allow-Origin": o,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key, Authorization, X-Agent-DID",
    "Access-Control-Max-Age": "86400",
  };
}

function nanoid(len = 14): string {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const buf = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(buf, (b) => alphabet[b % 62]).join("");
}

// Precise take-rate math without Decimal library: work in integer microdollars
function computeFee(agreedUsd: number): { fee: number; net: number } {
  const micro = Math.round(agreedUsd * 1_000_000);
  const feeMicro = Math.round(micro * TAKE_RATE);
  const netMicro = micro - feeMicro;
  return {
    fee: feeMicro / 1_000_000,
    net: netMicro / 1_000_000,
  };
}

async function incrKV(kv: KVNamespace, key: string): Promise<number> {
  const val = await kv.get(key);
  const n = (val ? parseInt(val, 10) : 0) + 1;
  await kv.put(key, String(n));
  return n;
}

function requireAdmin(req: Request, env: Env): Response | null {
  if (!env.ADMIN_KEY) return null; // no key configured → open
  const key = req.headers.get("X-Admin-Key") ?? "";
  if (key !== env.ADMIN_KEY) return json({ error: "unauthorized" }, 401);
  return null;
}

// ── Agent handlers ─────────────────────────────────────────────────────────

async function registerAgent(req: Request, env: Env): Promise<Response> {
  let body: { did?: string; name?: string; capabilities?: string[]; pubkey?: string };
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }

  if (!body.did || !body.pubkey) return json({ error: "did and pubkey required" }, 400);
  if (body.did.length > 128) return json({ error: "did too long" }, 400);

  const now = new Date().toISOString();
  const existing = (await env.MARKETPLACE_KV.get(`agent:${body.did}`, "json")) as AgentRecord | null;

  const record: AgentRecord = {
    did: body.did,
    name: (body.name ?? "Unnamed Agent").slice(0, 128),
    capabilities: (body.capabilities ?? []).slice(0, 32),
    pubkey: body.pubkey.slice(0, 512),
    registered_at: existing?.registered_at ?? now,
    updated_at: now,
    trust_score: existing?.trust_score ?? 0.5,
    is_sponsored: existing?.is_sponsored ?? false,
  };

  await env.MARKETPLACE_KV.put(`agent:${body.did}`, JSON.stringify(record), {
    expirationTtl: 60 * 60 * 24 * 365, // 1 year
  });
  if (!existing) await incrKV(env.MARKETPLACE_KV, "stats:agents_total");

  return json({ ok: true, agent: record }, existing ? 200 : 201);
}

async function getAgent(env: Env, did: string): Promise<Response> {
  const agent = await env.MARKETPLACE_KV.get(`agent:${did}`, "json");
  return agent ? json(agent) : json({ error: "not found" }, 404);
}

// ── Listing handlers ───────────────────────────────────────────────────────

async function createListing(req: Request, env: Env): Promise<Response> {
  let body: {
    title?: string; description?: string; asset_type?: string;
    price_usd?: number; seller_did?: string; tags?: string[];
  };
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }

  if (!body.title || !body.seller_did || body.price_usd == null) {
    return json({ error: "title, seller_did, price_usd required" }, 400);
  }
  if (body.price_usd < 0) return json({ error: "price_usd must be >= 0" }, 400);

  const seller = await env.MARKETPLACE_KV.get(`agent:${body.seller_did}`, "json");
  if (!seller) return json({ error: "seller_did not registered — call POST /agents/register first" }, 403);

  const id = nanoid(14);
  const now = new Date().toISOString();

  const listing: ListingRecord = {
    id,
    title: body.title.slice(0, 256),
    description: (body.description ?? "").slice(0, 2048),
    asset_type: (body.asset_type ?? "data").slice(0, 64),
    price_usd: body.price_usd,
    seller_did: body.seller_did,
    tags: (body.tags ?? []).slice(0, 20).map((t) => t.slice(0, 64)),
    is_sponsored: false,
    sponsored_until: null,
    sponsored_boost: 0,
    created_at: now,
    updated_at: now,
  };

  await env.MARKETPLACE_KV.put(`listing:${id}`, JSON.stringify(listing), {
    expirationTtl: 60 * 60 * 24 * 90, // 90 days
  });

  // Prepend to index, cap at MAX_LISTING_INDEX
  const raw = await env.MARKETPLACE_KV.get("listing:index");
  const index: string[] = raw ? JSON.parse(raw) : [];
  index.unshift(id);
  if (index.length > MAX_LISTING_INDEX) index.splice(MAX_LISTING_INDEX);
  await env.MARKETPLACE_KV.put("listing:index", JSON.stringify(index));

  await incrKV(env.MARKETPLACE_KV, "stats:listings_total");

  return json({ ok: true, listing }, 201);
}

async function searchListings(url: URL, env: Env): Promise<Response> {
  const q = url.searchParams.get("q")?.toLowerCase() ?? "";
  const typeFilter = url.searchParams.get("type") ?? "";
  const sellerFilter = url.searchParams.get("seller_did") ?? "";
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "20", 10), 100);
  const offset = parseInt(url.searchParams.get("offset") ?? "0", 10);

  const raw = await env.MARKETPLACE_KV.get("listing:index");
  const index: string[] = raw ? JSON.parse(raw) : [];

  // Fetch candidates (max 200) in parallel
  const candidates = (
    await Promise.all(
      index.slice(0, 200).map((id) =>
        env.MARKETPLACE_KV.get(`listing:${id}`, "json") as Promise<ListingRecord | null>
      )
    )
  ).filter((l): l is ListingRecord => l !== null);

  // Filter
  let results = candidates.filter((l) => {
    if (q) {
      const hay = `${l.title} ${l.description} ${l.tags.join(" ")}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (typeFilter && l.asset_type !== typeFilter) return false;
    if (sellerFilter && l.seller_did !== sellerFilter) return false;
    // Expire sponsored_until
    if (l.is_sponsored && l.sponsored_until && new Date(l.sponsored_until) < new Date()) {
      l.is_sponsored = false;
      l.sponsored_boost = 0;
    }
    return true;
  });

  // Sponsored boost applied in memory — never in storage sort (keeps index neutral)
  results.sort((a, b) => {
    const scoreA = a.is_sponsored ? SPONSORED_BOOST : 0;
    const scoreB = b.is_sponsored ? SPONSORED_BOOST : 0;
    return scoreB - scoreA;
  });

  const page = results.slice(offset, offset + limit).map((l) => ({
    ...l,
    sponsored: l.is_sponsored, // explicit field for UI "Ad" label
  }));

  return json({ results: page, total: results.length, limit, offset });
}

async function getListing(env: Env, id: string): Promise<Response> {
  const listing = await env.MARKETPLACE_KV.get(`listing:${id}`, "json");
  return listing ? json(listing) : json({ error: "not found" }, 404);
}

async function sponsorListing(req: Request, env: Env, id: string): Promise<Response> {
  const denied = requireAdmin(req, env);
  if (denied) return denied;

  let body: { days?: number };
  try { body = await req.json(); } catch { body = {}; }
  const days = Math.min(body.days ?? 30, 365);

  const listing = (await env.MARKETPLACE_KV.get(`listing:${id}`, "json")) as ListingRecord | null;
  if (!listing) return json({ error: "listing not found" }, 404);

  listing.is_sponsored = true;
  listing.sponsored_until = new Date(Date.now() + days * 86_400_000).toISOString();
  listing.sponsored_boost = SPONSORED_BOOST;
  listing.updated_at = new Date().toISOString();

  await env.MARKETPLACE_KV.put(`listing:${id}`, JSON.stringify(listing), {
    expirationTtl: 60 * 60 * 24 * 90,
  });

  return json({ ok: true, listing });
}

// ── Negotiation handlers ───────────────────────────────────────────────────

async function startNegotiation(req: Request, env: Env): Promise<Response> {
  let body: { listing_id?: string; buyer_did?: string; initial_offer_usd?: number; message?: string };
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }

  if (!body.listing_id || !body.buyer_did || body.initial_offer_usd == null) {
    return json({ error: "listing_id, buyer_did, initial_offer_usd required" }, 400);
  }

  const listing = (await env.MARKETPLACE_KV.get(`listing:${body.listing_id}`, "json")) as ListingRecord | null;
  if (!listing) return json({ error: "listing not found" }, 404);

  const id = nanoid(16);
  const now = new Date().toISOString();

  const neg: NegotiationRecord = {
    id,
    listing_id: body.listing_id,
    buyer_did: body.buyer_did,
    seller_did: listing.seller_did,
    status: "offered",
    offers: [
      {
        from_did: body.buyer_did,
        amount_usd: body.initial_offer_usd,
        message: (body.message ?? "").slice(0, 512),
        timestamp: now,
      },
    ],
    created_at: now,
    updated_at: now,
  };

  await env.MARKETPLACE_KV.put(`neg:${id}`, JSON.stringify(neg), {
    expirationTtl: 60 * 60 * 24 * 7, // 7 days
  });
  await incrKV(env.MARKETPLACE_KV, "stats:negotiations_total");

  return json({ ok: true, negotiation: neg }, 201);
}

async function getNegotiation(env: Env, id: string): Promise<Response> {
  const neg = await env.MARKETPLACE_KV.get(`neg:${id}`, "json");
  return neg ? json(neg) : json({ error: "not found" }, 404);
}

async function sendOffer(req: Request, env: Env, negId: string): Promise<Response> {
  let body: { from_did?: string; amount_usd?: number; message?: string };
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }

  const neg = (await env.MARKETPLACE_KV.get(`neg:${negId}`, "json")) as NegotiationRecord | null;
  if (!neg) return json({ error: "negotiation not found" }, 404);
  if (neg.status === "accepted" || neg.status === "cleared") {
    return json({ error: `negotiation already ${neg.status}` }, 409);
  }
  if (neg.status === "rejected") return json({ error: "negotiation rejected" }, 409);
  if (neg.offers.length >= MAX_NEGOTIATION_ROUNDS) {
    return json({ error: `max ${MAX_NEGOTIATION_ROUNDS} rounds reached` }, 422);
  }

  neg.offers.push({
    from_did: body.from_did ?? "unknown",
    amount_usd: body.amount_usd ?? 0,
    message: (body.message ?? "").slice(0, 512),
    timestamp: new Date().toISOString(),
  });
  neg.status = "offered";
  neg.updated_at = new Date().toISOString();

  await env.MARKETPLACE_KV.put(`neg:${negId}`, JSON.stringify(neg), {
    expirationTtl: 60 * 60 * 24 * 7,
  });

  return json({ ok: true, negotiation: neg });
}

async function acceptOffer(_req: Request, env: Env, negId: string): Promise<Response> {
  const neg = (await env.MARKETPLACE_KV.get(`neg:${negId}`, "json")) as NegotiationRecord | null;
  if (!neg) return json({ error: "negotiation not found" }, 404);
  if (neg.status !== "offered") return json({ error: `cannot accept — status is '${neg.status}'` }, 409);

  neg.status = "accepted";
  neg.updated_at = new Date().toISOString();

  await env.MARKETPLACE_KV.put(`neg:${negId}`, JSON.stringify(neg), {
    expirationTtl: 60 * 60 * 24 * 7,
  });

  return json({ ok: true, negotiation: neg });
}

async function rejectOffer(_req: Request, env: Env, negId: string): Promise<Response> {
  const neg = (await env.MARKETPLACE_KV.get(`neg:${negId}`, "json")) as NegotiationRecord | null;
  if (!neg) return json({ error: "negotiation not found" }, 404);
  if (neg.status === "cleared") return json({ error: "cannot reject a cleared negotiation" }, 409);

  neg.status = "rejected";
  neg.updated_at = new Date().toISOString();

  await env.MARKETPLACE_KV.put(`neg:${negId}`, JSON.stringify(neg), {
    expirationTtl: 60 * 60 * 24 * 7,
  });

  return json({ ok: true, negotiation: neg });
}

// ── Clearing handler ───────────────────────────────────────────────────────

async function clearNegotiation(req: Request, env: Env): Promise<Response> {
  let body: { negotiation_id?: string };
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }
  if (!body.negotiation_id) return json({ error: "negotiation_id required" }, 400);

  const neg = (await env.MARKETPLACE_KV.get(`neg:${body.negotiation_id}`, "json")) as NegotiationRecord | null;
  if (!neg) return json({ error: "negotiation not found" }, 404);
  if (neg.status !== "accepted") {
    return json({ error: `cannot clear — status is '${neg.status}' (must be 'accepted')` }, 409);
  }

  const lastOffer = neg.offers[neg.offers.length - 1];
  const agreedUsd = lastOffer?.amount_usd ?? 0;
  const { fee, net } = computeFee(agreedUsd);

  const result: ClearingResult = {
    negotiation_id: neg.id,
    listing_id: neg.listing_id,
    buyer_did: neg.buyer_did,
    seller_did: neg.seller_did,
    agreed_price_usd: agreedUsd,
    platform_fee_usd: fee, // logged only — no on-chain transfer in v1
    seller_net_usd: net,
    cleared_at: new Date().toISOString(),
    settlement_status: "logged",
  };

  neg.status = "cleared";
  neg.updated_at = result.cleared_at;

  await Promise.all([
    env.MARKETPLACE_KV.put(`neg:${neg.id}`, JSON.stringify(neg), {
      expirationTtl: 60 * 60 * 24 * 365,
    }),
    env.MARKETPLACE_KV.put(`clear:${neg.id}`, JSON.stringify(result), {
      expirationTtl: 60 * 60 * 24 * 365,
    }),
    incrKV(env.MARKETPLACE_KV, "stats:cleared_total"),
  ]);

  return json({ ok: true, clearing: result });
}

// ── Stats handler ──────────────────────────────────────────────────────────

async function getStats(req: Request, env: Env): Promise<Response> {
  const denied = requireAdmin(req, env);
  if (denied) return denied;

  const [agents, listings, negotiations, cleared] = await Promise.all([
    env.MARKETPLACE_KV.get("stats:agents_total"),
    env.MARKETPLACE_KV.get("stats:listings_total"),
    env.MARKETPLACE_KV.get("stats:negotiations_total"),
    env.MARKETPLACE_KV.get("stats:cleared_total"),
  ]);

  return json({
    agents_total: parseInt(agents ?? "0", 10),
    listings_total: parseInt(listings ?? "0", 10),
    negotiations_total: parseInt(negotiations ?? "0", 10),
    cleared_total: parseInt(cleared ?? "0", 10),
    take_rate: TAKE_RATE,
    version: VERSION,
    ts: new Date().toISOString(),
  });
}

// ── ADP — Agent Discovery Protocol ────────────────────────────────────────

function agentDiscovery(): Response {
  return new Response(
    JSON.stringify(
      {
        "@context": "https://schema.org",
        "@type": "Service",
        name: "Shadow Warden AI Agentic Marketplace",
        version: VERSION,
        protocol: "M2M/1.0",
        capabilities: ["search", "negotiate", "clear", "register"],
        endpoints: {
          health: "/health",
          register: "POST /agents/register",
          agent_get: "GET /agents/:did",
          listings_create: "POST /listings",
          listings_search: "GET /listings",
          listings_get: "GET /listings/:id",
          listings_sponsor: "POST /listings/:id/sponsor",
          negotiations_start: "POST /negotiations",
          negotiations_get: "GET /negotiations/:id",
          offer_send: "POST /negotiations/:id/offer",
          offer_accept: "POST /negotiations/:id/accept",
          offer_reject: "POST /negotiations/:id/reject",
          clear: "POST /clear",
          stats: "GET /stats",
        },
        fee: {
          take_rate: TAKE_RATE,
          currency: "USD",
          model: "take_rate",
          note: "Platform fee is logged; on-chain settlement in v2 via Circle Gateway",
        },
        sponsored: {
          boost: SPONSORED_BOOST,
          applied: "in-memory after index fetch",
          label: "sponsored field on every search result",
        },
        auth: {
          type: "DID",
          scheme: "did:shadow:{base62(sha256(pubkey)[:32])}",
          admin: "X-Admin-Key header for privileged endpoints",
        },
      },
      null,
      2
    ),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
        "Access-Control-Allow-Origin": "*",
      },
    }
  );
}

// ── Main router ────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname.replace(/\/$/, "") || "/";
    const origin = request.headers.get("Origin") ?? "";
    const cors = corsHeaders(origin, env.ALLOWED_ORIGIN ?? "*");

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // ── ADP (no auth, cacheable)
    if (method === "GET" && path === "/.well-known/agent.json") {
      return agentDiscovery();
    }

    // ── Health
    if (method === "GET" && path === "/health") {
      return json({ ok: true, version: VERSION, ts: new Date().toISOString() });
    }

    // ── Agents
    if (method === "POST" && path === "/agents/register") {
      const res = await registerAgent(request, env);
      return addCors(res, cors);
    }
    if (method === "GET" && path.startsWith("/agents/")) {
      const did = decodeURIComponent(path.slice("/agents/".length));
      return addCors(await getAgent(env, did), cors);
    }

    // ── Listings
    if (method === "POST" && path === "/listings") {
      return addCors(await createListing(request, env), cors);
    }
    if (method === "GET" && path === "/listings") {
      return addCors(await searchListings(url, env), cors);
    }
    // GET /listings/:id
    if (method === "GET" && /^\/listings\/[^/]+$/.test(path)) {
      const id = path.split("/")[2];
      return addCors(await getListing(env, id), cors);
    }
    // POST /listings/:id/sponsor
    if (method === "POST" && /^\/listings\/[^/]+\/sponsor$/.test(path)) {
      const id = path.split("/")[2];
      return addCors(await sponsorListing(request, env, id), cors);
    }

    // ── Negotiations
    if (method === "POST" && path === "/negotiations") {
      return addCors(await startNegotiation(request, env), cors);
    }
    if (method === "GET" && /^\/negotiations\/[^/]+$/.test(path)) {
      const id = path.split("/")[2];
      return addCors(await getNegotiation(env, id), cors);
    }
    if (method === "POST" && /^\/negotiations\/[^/]+\/offer$/.test(path)) {
      const id = path.split("/")[2];
      return addCors(await sendOffer(request, env, id), cors);
    }
    if (method === "POST" && /^\/negotiations\/[^/]+\/accept$/.test(path)) {
      const id = path.split("/")[2];
      return addCors(await acceptOffer(request, env, id), cors);
    }
    if (method === "POST" && /^\/negotiations\/[^/]+\/reject$/.test(path)) {
      const id = path.split("/")[2];
      return addCors(await rejectOffer(request, env, id), cors);
    }

    // ── Clear
    if (method === "POST" && path === "/clear") {
      return addCors(await clearNegotiation(request, env), cors);
    }

    // ── Stats (admin)
    if (method === "GET" && path === "/stats") {
      return addCors(await getStats(request, env), cors);
    }

    return addCors(json({ error: "not found", path }, 404), cors);
  },
};

// Attach CORS headers to any Response
function addCors(res: Response, cors: Record<string, string>): Response {
  const next = new Response(res.body, res);
  Object.entries(cors).forEach(([k, v]) => next.headers.set(k, v));
  return next;
}
