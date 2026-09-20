// shadow-warden-marketplace — edge proxy for marketplace.shadow-warden-ai.com
//
// This Worker used to be a *second implementation* of the marketplace: agents,
// listings, negotiations and clearing, over Cloudflare KV, in TypeScript,
// sharing no code, no database and no guard with `warden/marketplace/*`.
//
// That cost more than it earned. Every guard had to be written twice, and the
// copy nobody remembered shipped the defect:
//
//   * `registerAgent()` rebound an existing DID's public key while keeping the
//     victim's trust score, unauthenticated, answering 200 — the takeover the
//     Python side closed in #463 (fixed here in #506).
//   * `requireAdmin()` was `if (!env.ADMIN_KEY) return null` — the empty-secret
//     anti-pattern, wide open when the secret was never set (also #506).
//   * `GET /listings` served a demo listing — "Threat Intel Feed - APT-42",
//     $0.05, `did:shadow:seller001` — to anyone who asked, on the public host
//     agents discover. `docs/capability-matrix.md` says marketplace activity of
//     any kind is `FABRICATED` if implied. It was implied, publicly, for
//     months.
//   * It published its own `/.well-known/agent.json`, a second discovery
//     document competing with the gateway's, with a different capability list.
//
// None of that was a coding mistake so much as a consequence: two
// implementations of one market disagree, and the disagreement is invisible
// until someone reads both. So there is now one. This Worker keeps the edge —
// TLS termination on the hostname, CORS, and Cloudflare in front — and forwards
// every request to the gateway, which owns identity, signatures, KYA, autonomy
// and escrow.
//
// The KV namespace is deliberately no longer bound. Its contents (the demo
// listing among them) stop being served the moment this deploys.

const VERSION = "2.0.0";

interface Env {
  /** Gateway origin, e.g. https://api.shadow-warden-ai.com. No default. */
  WARDEN_BACKEND_URL?: string;
  ALLOWED_ORIGIN?: string;
}

/** Marketplace routes live under this prefix on the gateway. */
const GATEWAY_PREFIX = "/v1/marketplace";

/** Forwarded as-is rather than under the marketplace prefix. */
const PASSTHROUGH = new Set(["/.well-known/agent.json", "/.well-known/mcp.json"]);

/**
 * Hop-by-hop and edge-owned headers that must not be copied to the origin.
 * `host` especially: sending the edge hostname would make the gateway build
 * self-referential URLs pointing back at this Worker.
 */
const STRIP_REQUEST = new Set([
  "host", "connection", "keep-alive", "transfer-encoding", "upgrade",
  "proxy-authorization", "proxy-authenticate", "te", "trailer",
  "cf-connecting-ip", "cf-ray", "cf-visitor", "cf-ipcountry",
  // Identity headers a client must never author. The gateway's
  // `get_client_ip()` trusts these *because* the peer is inside
  // TRUSTED_PROXY_CIDRS — which this proxy is. Forwarding a caller's own
  // `X-Forwarded-For` would therefore let them key ERS, shadow ban and rate
  // limiting on somebody else. Stripped here and re-set below from
  // `CF-Connecting-IP` only, so the value is always Cloudflare's, never the
  // caller's. Absent that header nothing is sent and the gateway falls back to
  // the socket peer.
  "x-forwarded-for", "x-real-ip",
]);

const STRIP_RESPONSE = new Set([
  "connection", "keep-alive", "transfer-encoding", "upgrade", "trailer",
]);

/**
 * The header names to drop, including any the `Connection` header nominates.
 *
 * RFC 9110 §7.6.1: `Connection` lists further headers that are hop-by-hop for
 * this connection only. A fixed deny-list misses them, so a client could name
 * a header there and have it cross the proxy boundary to the gateway — or the
 * gateway could leak one back. Cloudflare manages `Connection` itself, which
 * makes this narrow rather than absent; narrow is still worth closing at a
 * boundary whose whole job is deciding what crosses.
 */
function dropSet(headers: Headers, base: Set<string>): Set<string> {
  const drop = new Set(base);
  const conn = headers.get("connection");
  if (conn) {
    for (const token of conn.split(",")) {
      const name = token.trim().toLowerCase();
      if (name) drop.add(name);
    }
  }
  return drop;
}

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
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Admin-Key, Authorization, X-Agent-DID, X-Agent-ID, X-Tenant-ID, PAYMENT-SIGNATURE, Idempotency-Key",
    "Access-Control-Max-Age": "86400",
  };
}

/** The gateway path this request maps to, or null when the path is not proxied. */
export function targetPath(path: string): string | null {
  if (PASSTHROUGH.has(path)) return path;
  if (path === "/" || path === "") return null;
  if (path.startsWith("/.well-known/")) return null;   // not ours to answer or invent
  return GATEWAY_PREFIX + path;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url     = new URL(request.url);
    const method  = request.method;
    const allowed = env.ALLOWED_ORIGIN ?? "https://shadow-warden-ai.com";
    const cors    = corsHeaders(request.headers.get("Origin") ?? "", allowed);

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // Edge health. Answers for the Worker itself and says nothing about the
    // gateway — a proxy reporting its upstream healthy without asking is the
    // kind of claim this project removes.
    if (method === "GET" && url.pathname === "/health") {
      return addCors(
        json({ ok: true, version: VERSION, role: "proxy", ts: new Date().toISOString() }),
        cors,
      );
    }

    const backend = (env.WARDEN_BACKEND_URL ?? "").replace(/\/+$/, "");
    if (!backend) {
      // Fail closed and loudly. Serving anything from the edge while the origin
      // is unreachable is how the demo listing survived: an answer that looks
      // like the market is worse than an error that says it is unavailable.
      return addCors(
        json(
          {
            error: "backend_not_configured",
            detail: "set WARDEN_BACKEND_URL with `wrangler secret put`",
          },
          503,
        ),
        cors,
      );
    }

    const target = targetPath(url.pathname);
    if (target === null) {
      return addCors(json({ error: "not found", path: url.pathname }, 404), cors);
    }

    const dropReq = dropSet(request.headers, STRIP_REQUEST);
    const headers = new Headers();
    request.headers.forEach((value, key) => {
      if (!dropReq.has(key.toLowerCase())) headers.set(key, value);
    });
    // The gateway resolves the caller with `get_client_ip`, which trusts these
    // only from an allow-listed peer. Passing the real client through is what
    // keeps ERS, shadow ban and rate limiting keyed on the caller rather than
    // on one constant for the whole internet.
    const clientIp = request.headers.get("CF-Connecting-IP");
    if (clientIp) {
      headers.set("X-Forwarded-For", clientIp);
      headers.set("X-Real-IP", clientIp);
    }

    let upstream: Response;
    try {
      upstream = await fetch(backend + target + url.search, {
        method,
        headers,
        body: method === "GET" || method === "HEAD" ? undefined : request.body,
        redirect: "manual",
      });
    } catch (err) {
      return addCors(
        json({ error: "backend_unreachable", detail: String(err) }, 502),
        cors,
      );
    }

    const dropRes = dropSet(upstream.headers, STRIP_RESPONSE);
    const out = new Headers();
    upstream.headers.forEach((value, key) => {
      if (!dropRes.has(key.toLowerCase())) out.set(key, value);
    });
    Object.entries(cors).forEach(([k, v]) => out.set(k, v));

    return new Response(upstream.body, { status: upstream.status, headers: out });
  },
};

function addCors(res: Response, cors: Record<string, string>): Response {
  const next = new Response(res.body, res);
  Object.entries(cors).forEach(([k, v]) => next.headers.set(k, v));
  return next;
}
