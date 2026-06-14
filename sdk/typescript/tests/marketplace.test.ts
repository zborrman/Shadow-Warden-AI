/**
 * sdk/typescript/tests/marketplace.test.ts
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Tests for marketplace, agent, health, and retry features of WardenClient.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

import { WardenClient } from "../src/client.js";
import { WardenGatewayError } from "../src/errors.js";
import type { MktAgent, MktAgentTrust, MktListing, MktPurchase, MktStats } from "../src/types.js";

const BASE = "http://localhost:8001";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// ── Fixtures ──────────────────────────────────────────────────────────────────

const AGENT_FIXTURE: MktAgent = {
  agent_id: "did:shadow:abc123",
  community_id: "c1",
  tenant_id: "t1",
  capabilities: ["marketplace_sell", "marketplace_buy"],
  status: "active",
  mandate_id: "m-001",
  created_at: "2026-06-01T00:00:00Z",
};

const LISTING_FIXTURE: MktListing = {
  listing_id: "l-001",
  seller_agent_id: "did:shadow:abc123",
  community_id: "c1",
  asset_type: "rule",
  title: "Prompt Injection Detector v2",
  description: "Regex + ML rule",
  price_usd: 29.99,
  pricing_strategy: "fixed",
  status: "active",
  created_at: "2026-06-02T00:00:00Z",
};

const PURCHASE_FIXTURE: MktPurchase = {
  purchase_id: "p-001",
  listing_id: "l-001",
  buyer_agent_id: "did:shadow:buyer01",
  seller_agent_id: "did:shadow:abc123",
  price_paid: 29.99,
  status: "completed",
  escrow_id: "e-001",
  purchased_at: "2026-06-03T00:00:00Z",
};

const TRUST_FIXTURE: MktAgentTrust = {
  agent_id: "did:shadow:abc123",
  trust_score: 0.87,
  trust_rank: 0.91,
  sybil_flag: false,
  sybil_reason: "",
  transitive_peers: [{ agent_id: "did:shadow:peer01", trust_rank: 0.75, transitive_trust: 0.68 }],
};

const STATS_FIXTURE: MktStats = {
  total_listings: 42,
  active_listings: 31,
  total_trades: 118,
  total_volume_usd: 3482.5,
  registered_agents: 15,
  avg_price_usd: 29.51,
};

// ── marketplace.agents.list() ─────────────────────────────────────────────────

describe("marketplace.agents.list()", () => {
  const client = new WardenClient({ gatewayUrl: BASE, apiKey: "sk_test" });

  it("returns list of agents", async () => {
    server.use(http.get(`${BASE}/marketplace/agents`, () => HttpResponse.json([AGENT_FIXTURE])));
    const agents = await client.marketplace.agents.list();
    expect(agents).toHaveLength(1);
    expect(agents[0]?.agent_id).toBe("did:shadow:abc123");
  });

  it("forwards query params", async () => {
    let capturedUrl = "";
    server.use(
      http.get(`${BASE}/marketplace/agents`, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([]);
      })
    );
    await client.marketplace.agents.list({ community_id: "c1", status: "active" });
    expect(capturedUrl).toContain("community_id=c1");
    expect(capturedUrl).toContain("status=active");
  });

  it("throws WardenGatewayError on 401", async () => {
    server.use(http.get(`${BASE}/marketplace/agents`, () => HttpResponse.json({}, { status: 401 })));
    await expect(client.marketplace.agents.list()).rejects.toThrow(WardenGatewayError);
  });
});

// ── marketplace.agents.register() ────────────────────────────────────────────

describe("marketplace.agents.register()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns registered agent", async () => {
    server.use(http.post(`${BASE}/marketplace/agents/register`, () => HttpResponse.json(AGENT_FIXTURE, { status: 201 })));
    const agent = await client.marketplace.agents.register({
      tenant_id: "t1",
      community_id: "c1",
      public_key: "base64pubkey==",
      capabilities: ["marketplace_sell"],
    });
    expect(agent.agent_id).toBe("did:shadow:abc123");
    expect(agent.capabilities).toContain("marketplace_sell");
  });

  it("throws on 403 (sybil gate)", async () => {
    server.use(
      http.post(`${BASE}/marketplace/agents/register`, () =>
        HttpResponse.json({ detail: "Agent is flagged" }, { status: 403 })
      )
    );
    const err = await client.marketplace.agents.register({
      tenant_id: "t1", community_id: "c1", public_key: "key", capabilities: [],
    }).catch((e) => e);
    expect(err).toBeInstanceOf(WardenGatewayError);
    expect((err as WardenGatewayError).statusCode).toBe(403);
  });
});

// ── marketplace.agents.getTrust() ─────────────────────────────────────────────

describe("marketplace.agents.getTrust()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns trust data", async () => {
    server.use(
      http.get(`${BASE}/marketplace/agents/did%3Ashadow%3Aabc123/trust`, () =>
        HttpResponse.json(TRUST_FIXTURE)
      )
    );
    const trust = await client.marketplace.agents.getTrust("did:shadow:abc123");
    expect(trust.trust_score).toBeCloseTo(0.87);
    expect(trust.sybil_flag).toBe(false);
    expect(trust.transitive_peers).toHaveLength(1);
  });
});

// ── marketplace.listings.list() ───────────────────────────────────────────────

describe("marketplace.listings.list()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns list of listings", async () => {
    server.use(http.get(`${BASE}/marketplace/listings`, () => HttpResponse.json([LISTING_FIXTURE])));
    const listings = await client.marketplace.listings.list();
    expect(listings[0]?.listing_id).toBe("l-001");
    expect(listings[0]?.price_usd).toBe(29.99);
  });
});

// ── marketplace.listings.create() ────────────────────────────────────────────

describe("marketplace.listings.create()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("creates a listing and returns it", async () => {
    server.use(http.post(`${BASE}/marketplace/listings`, () => HttpResponse.json(LISTING_FIXTURE, { status: 201 })));
    const listing = await client.marketplace.listings.create({
      seller_agent_id: "did:shadow:abc123",
      community_id: "c1",
      asset_type: "rule",
      title: "Prompt Injection Detector v2",
      price_usd: 29.99,
    });
    expect(listing.listing_id).toBe("l-001");
  });
});

// ── marketplace.listings.purchase() ──────────────────────────────────────────

describe("marketplace.listings.purchase()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns purchase record", async () => {
    server.use(
      http.post(`${BASE}/marketplace/listings/l-001/purchase`, () =>
        HttpResponse.json(PURCHASE_FIXTURE, { status: 201 })
      )
    );
    const purchase = await client.marketplace.listings.purchase("l-001", {
      buyer_agent_id: "did:shadow:buyer01",
    });
    expect(purchase.purchase_id).toBe("p-001");
    expect(purchase.status).toBe("completed");
  });
});

// ── marketplace.stats() ───────────────────────────────────────────────────────

describe("marketplace.stats()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns stats object", async () => {
    server.use(http.get(`${BASE}/marketplace/stats`, () => HttpResponse.json(STATS_FIXTURE)));
    const stats = await client.marketplace.stats();
    expect(stats.total_listings).toBe(42);
    expect(stats.total_volume_usd).toBe(3482.5);
  });
});

// ── client.agent() ────────────────────────────────────────────────────────────

describe("client.agent()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns agent response", async () => {
    server.use(
      http.post(`${BASE}/agent/sova`, () =>
        HttpResponse.json({
          session_id: "ses-001",
          reply: "Current threat level is LOW.",
          tool_calls: 2,
          iterations: 1,
        })
      )
    );
    const reply = await client.agent("What is our threat level?");
    expect(reply.session_id).toBe("ses-001");
    expect(reply.reply).toContain("LOW");
    expect(reply.tool_calls).toBe(2);
  });

  it("forwards session_id in payload", async () => {
    let capturedBody: Record<string, unknown> | null = null;
    server.use(
      http.post(`${BASE}/agent/sova`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ session_id: "ses-001", reply: "ok", tool_calls: 0, iterations: 1 });
      })
    );
    await client.agent("hello", { sessionId: "my-session" });
    expect(capturedBody?.["session_id"]).toBe("my-session");
  });
});

// ── client.health() ───────────────────────────────────────────────────────────

describe("client.health()", () => {
  const client = new WardenClient({ gatewayUrl: BASE });

  it("returns health dict", async () => {
    server.use(
      http.get(`${BASE}/health`, () =>
        HttpResponse.json({ status: "ok", version: "5.6", pipeline: "ready" })
      )
    );
    const h = await client.health();
    expect(h["status"]).toBe("ok");
    expect(h["version"]).toBe("5.6");
  });

  it("throws on error", async () => {
    server.use(http.get(`${BASE}/health`, () => HttpResponse.json({}, { status: 503 })));
    await expect(client.health()).rejects.toThrow(WardenGatewayError);
  });
});

// ── retry logic ───────────────────────────────────────────────────────────────

describe("retry logic", () => {
  it("retries on 429 and succeeds", async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE}/filter`, () => {
        calls++;
        if (calls < 3) {
          return HttpResponse.json({ detail: "rate limited" }, { status: 429 });
        }
        return HttpResponse.json({
          allowed: true, risk_level: "low", filtered_content: "test",
        });
      })
    );
    const client = new WardenClient({ gatewayUrl: BASE, retry: { maxRetries: 3, backoffMs: 1 } });
    const result = await client.filter("test");
    expect(result.allowed).toBe(true);
    expect(calls).toBe(3);
  });

  it("throws after exhausting retries on 500", async () => {
    server.use(http.post(`${BASE}/filter`, () => HttpResponse.json({ detail: "server error" }, { status: 500 })));
    const client = new WardenClient({ gatewayUrl: BASE, retry: { maxRetries: 2, backoffMs: 1 } });
    await expect(client.filter("test")).rejects.toThrow(WardenGatewayError);
  });
});
