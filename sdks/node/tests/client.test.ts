/**
 * sdks/node/tests/client.test.ts
 * Vitest unit tests for the Shadow Warden Node SDK.
 * All HTTP calls are mocked — no real API needed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ShadowWardenClient, ShadowWardenError } from "../src/client.js";

// ── fetch mock helpers ────────────────────────────────────────────────────────

function mockFetch(body: unknown, status = 200): void {
  global.fetch = vi.fn().mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as unknown as Response);
}

function captureRequest(): { url: string; init: RequestInit } {
  let captured: { url: string; init: RequestInit } = { url: "", init: {} };
  global.fetch = vi.fn().mockImplementationOnce(async (url: string, init: RequestInit) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true }),
    } as unknown as Response;
  });
  return captured;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("ShadowWardenClient — initialization", () => {
  it("throws when apiKey is empty", () => {
    expect(() => new ShadowWardenClient({ apiKey: "" })).toThrow("apiKey is required");
  });

  it("constructs with a valid apiKey", () => {
    const client = new ShadowWardenClient({ apiKey: "sw-test-key" });
    expect(client).toBeDefined();
    expect(client.community).toBeDefined();
    expect(client.marketplace).toBeDefined();
    expect(client.compliance).toBeDefined();
    expect(client.semantic).toBeDefined();
    expect(client.documents).toBeDefined();
  });

  it("strips trailing slash from baseUrl", async () => {
    const client = new ShadowWardenClient({
      apiKey: "sw-key",
      baseUrl: "https://api.example.com/",
    });
    const req = captureRequest();
    await client.health().catch(() => {});
    expect(req.url).not.toMatch(/\/\//);
  });
});

describe("ShadowWardenClient — filter()", () => {
  it("sends content and tenant_id in request body", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.filter("test content", "acme").catch(() => {});
    const body = JSON.parse(req.init.body as string);
    expect(body.content).toBe("test content");
    expect(body.tenant_id).toBe("acme");
  });

  it("returns a FilterResult on success", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    mockFetch({ allowed: true, blocked: false, risk_level: "low", risk_score: 0.1, flags: [], processing_ms: 2, request_id: "r1", action: "allow" });
    const result = await client.filter("hello world");
    expect(result.allowed).toBe(true);
    expect(result.risk_level).toBe("low");
  });
});

describe("ShadowWardenClient — error handling", () => {
  it("throws ShadowWardenError on 401", async () => {
    const client = new ShadowWardenClient({ apiKey: "bad-key" });
    mockFetch({ detail: "Unauthorized" }, 401);
    await expect(client.health()).rejects.toThrow(ShadowWardenError);
  });

  it("ShadowWardenError carries status code", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    mockFetch({ detail: "Not found" }, 404);
    try {
      await client.health();
    } catch (e) {
      expect(e).toBeInstanceOf(ShadowWardenError);
      expect((e as ShadowWardenError).status).toBe(404);
    }
  });
});

describe("CommunityResource", () => {
  it("list() calls GET /communities with tenant_id param", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.community.list("tenant-x").catch(() => {});
    expect(req.url).toContain("/communities");
    expect(req.url).toContain("tenant_id=tenant-x");
  });

  it("create() posts to /communities/create", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.community.create({
      name: "Test Org",
      tenant_id: "t1",
    }).catch(() => {});
    const body = JSON.parse(req.init.body as string);
    expect(req.url).toContain("/communities/create");
    expect(body.name).toBe("Test Org");
  });
});

describe("MarketplaceResource", () => {
  it("registerAgent() posts to /marketplace/agents/register", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.marketplace.registerAgent({
      tenant_id: "t1",
      community_id: "c1",
      public_key: "base64pubkey==",
      capabilities: ["marketplace_sell"],
    }).catch(() => {});
    expect(req.url).toContain("/marketplace/agents/register");
    const body = JSON.parse(req.init.body as string);
    expect(body.capabilities).toContain("marketplace_sell");
  });

  it("createListing() includes chain field", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.marketplace.createListing({
      asset_id: "a1",
      seller_agent_id: "did:shadow:abc",
      community_id: "c1",
      tenant_id: "t1",
      price_usd: 5.0,
      chain: "polygon_amoy",
    }).catch(() => {});
    const body = JSON.parse(req.init.body as string);
    expect(body.chain).toBe("polygon_amoy");
  });

  it("stats() calls GET /marketplace/stats", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.marketplace.stats().catch(() => {});
    expect(req.url).toContain("/marketplace/stats");
  });
});

describe("SemanticResource", () => {
  it("query() posts correct QueryObject shape", async () => {
    const client = new ShadowWardenClient({ apiKey: "sw-key" });
    const req = captureRequest();
    await client.semantic.query({
      model_id: "filter_events",
      metrics: ["request_count"],
      dimensions: ["risk_level"],
    }).catch(() => {});
    const body = JSON.parse(req.init.body as string);
    expect(body.model_id).toBe("filter_events");
    expect(body.metrics).toContain("request_count");
  });
});
