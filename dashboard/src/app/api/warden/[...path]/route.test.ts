/**
 * Tests for the SOC dashboard's fail-closed proxy (see the module docstring in
 * `route.ts`). This route holds a full-privilege gateway credential, so every
 * invariant documented there gets an assertion here — this is the first
 * Vitest suite in the repo (plan-85 M-1): the dashboard had zero test
 * coverage, and this is the file that most needed it.
 *
 * `DASHBOARD_API_KEY` / `WARDEN_API_KEY` are read from `process.env` inside
 * the handlers on every call (not cached at module load), so tests can set
 * them per-case with no module reset required.
 */
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DELETE, GET, POST } from "./route";

const ORIGINAL_ENV = { ...process.env };

function req(
  path: string,
  opts: { cookie?: string; body?: string; headers?: Record<string, string> } = {},
): NextRequest {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.cookie) headers.cookie = opts.cookie;
  return new NextRequest(`https://dashboard.example/api/warden${path}`, {
    method: opts.body === undefined ? "GET" : "POST",
    headers,
    ...(opts.body === undefined ? {} : { body: opts.body }),
  });
}

function params(path: string): { params: { path: string[] } } {
  return { params: { path: path.split("/").filter(Boolean) } };
}

async function fetchMockResponse(body: string, init: ResponseInit = {}) {
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  process.env = { ...ORIGINAL_ENV };
  delete process.env.DASHBOARD_API_KEY;
  delete process.env.WARDEN_API_KEY;
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe("session gate — fails closed", () => {
  it("401s an allowed path when DASHBOARD_API_KEY is unset, even with a cookie", async () => {
    process.env.WARDEN_API_KEY = "gw-key";
    const res = await GET(req("/health", { cookie: "warden_auth=anything" }), params("health"));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Not authenticated" });
  });

  it("401s when DASHBOARD_API_KEY is set but no cookie is present", async () => {
    process.env.DASHBOARD_API_KEY = "secret";
    const res = await GET(req("/health"), params("health"));
    expect(res.status).toBe(401);
  });

  it("401s when the cookie value does not match", async () => {
    process.env.DASHBOARD_API_KEY = "secret";
    const res = await GET(req("/health", { cookie: "warden_auth=wrong" }), params("health"));
    expect(res.status).toBe(401);
  });

  it("401s on a length mismatch (the constant-time compare must not throw)", async () => {
    process.env.DASHBOARD_API_KEY = "a-much-longer-secret-value";
    const res = await GET(req("/health", { cookie: "warden_auth=short" }), params("health"));
    expect(res.status).toBe(401);
  });
});

describe("path allowlist", () => {
  beforeEach(() => {
    process.env.DASHBOARD_API_KEY = "secret";
    process.env.WARDEN_API_KEY = "gw-key";
  });

  it("404s a path not on the GET allowlist", async () => {
    const res = await GET(
      req("/not/a/real/route", { cookie: "warden_auth=secret" }),
      params("not/a/real/route"),
    );
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Route not proxied" });
  });

  it("404s a GET-allowed path when called as DELETE (lists are not shared)", async () => {
    const res = await DELETE(req("/health", { cookie: "warden_auth=secret" }), params("health"));
    expect(res.status).toBe(404);
  });

  it("404s path traversal instead of forwarding it upstream", async () => {
    const fetchSpy = vi.spyOn(global, "fetch");
    const res = await GET(
      req("/../secrets", { cookie: "warden_auth=secret" }),
      params("../secrets"),
    );
    expect(res.status).toBe(404);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("allows a listed GET route through to fetch", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(await fetchMockResponse('{"ok":true}')));
    const res = await GET(req("/health", { cookie: "warden_auth=secret" }), params("health"));
    expect(res.status).toBe(200);
    expect(global.fetch).toHaveBeenCalledOnce();
  });
});

describe("gateway credential gate", () => {
  it("503s an allowed, authenticated request when WARDEN_API_KEY is unset", async () => {
    process.env.DASHBOARD_API_KEY = "secret";
    const fetchSpy = vi.spyOn(global, "fetch");
    const res = await GET(req("/health", { cookie: "warden_auth=secret" }), params("health"));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "Gateway credential not configured" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("forwarding — the client never reaches the upstream call directly", () => {
  beforeEach(() => {
    process.env.DASHBOARD_API_KEY = "secret";
    process.env.WARDEN_API_KEY = "server-side-key";
  });

  it("sends the server's key, never the caller's X-API-Key/Authorization/cookie", async () => {
    const fetchMock = vi.fn().mockResolvedValue(await fetchMockResponse("{}"));
    vi.stubGlobal("fetch", fetchMock);

    await GET(
      req("/health", {
        cookie: "warden_auth=secret",
        headers: {
          "x-api-key": "attacker-supplied-key",
          authorization: "Bearer attacker-token",
        },
      }),
      params("health"),
    );

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = init.headers as Record<string, string>;
    expect(sent["X-API-Key"]).toBe("server-side-key");
    expect(sent).not.toHaveProperty("Authorization");
    expect(sent).not.toHaveProperty("cookie");
  });

  it("routes /api/v1/* to the analytics service, everything else to the gateway", async () => {
    const fetchMock = vi.fn().mockResolvedValue(await fetchMockResponse("{}"));
    vi.stubGlobal("fetch", fetchMock);

    await GET(req("/api/v1/stats", { cookie: "warden_auth=secret" }), params("api/v1/stats"));
    const analyticsUrl = (fetchMock.mock.calls[0] as [string])[0];
    expect(analyticsUrl).toContain("analytics:8002");

    fetchMock.mockClear();
    await GET(req("/health", { cookie: "warden_auth=secret" }), params("health"));
    const gatewayUrl = (fetchMock.mock.calls[0] as [string])[0];
    expect(gatewayUrl).toContain("api.shadow-warden-ai.com");
  });

  it("forwards X-Tenant-ID when the session is valid", async () => {
    const fetchMock = vi.fn().mockResolvedValue(await fetchMockResponse("{}"));
    vi.stubGlobal("fetch", fetchMock);

    await GET(
      req("/health", { cookie: "warden_auth=secret", headers: { "x-tenant-id": "acme" } }),
      params("health"),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["X-Tenant-ID"]).toBe("acme");
  });

  it("POSTs the body through with a JSON content type", async () => {
    const fetchMock = vi.fn().mockResolvedValue(await fetchMockResponse('{"queued":true}'));
    vi.stubGlobal("fetch", fetchMock);

    const res = await POST(
      req("/filter", { cookie: "warden_auth=secret", body: '{"content":"hi"}' }),
      params("filter"),
    );

    expect(res.status).toBe(200);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("POST");
    expect(init.body).toBe('{"content":"hi"}');
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("passes a 204 through without constructing a body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    const res = await DELETE(
      req("/settings/api-keys/abc123", { cookie: "warden_auth=secret" }),
      params("settings/api-keys/abc123"),
    );
    expect(res.status).toBe(204);
  });

  it("defaults to application/json when the upstream omits Content-Type", async () => {
    // The Web `Response` constructor auto-assigns `text/plain;charset=UTF-8`
    // to a string body, so the only way to reach the `?? "application/json"`
    // fallback is to strip the header back off afterwards.
    const upstream = new Response("plain", { status: 200 });
    upstream.headers.delete("Content-Type");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(upstream));
    const res = await GET(req("/health", { cookie: "warden_auth=secret" }), params("health"));
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });

  it("502s when the upstream fetch throws (network error, DNS, timeout, ...)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    const res = await GET(req("/health", { cookie: "warden_auth=secret" }), params("health"));
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "Gateway unreachable" });
  });
});
