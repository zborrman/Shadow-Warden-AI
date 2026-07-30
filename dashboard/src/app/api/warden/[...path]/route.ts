import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

/**
 * Same-origin proxy from the SOC dashboard to the Warden API.
 *
 * The dashboard is entirely client-rendered, so `src/lib/api.ts` runs in the
 * browser. It previously called the Warden API cross-origin with no credentials
 * — `get()` sent no headers at all and `post()` sent a literal `X-API-Key: ""`.
 * Every gated route therefore answered 401 in production (the whole Community
 * Hub, the sandbox `/filter` page), and the fix cannot be a `NEXT_PUBLIC_*` key
 * because Next.js inlines those into the JavaScript bundle it serves to every
 * visitor.
 *
 * So the key stays on the server and the browser talks to this route instead.
 *
 * Two things guard it, because it holds a full-privilege API key:
 *
 *   1. The dashboard session is re-checked here, not merely in `middleware.ts`.
 *      That middleware deliberately fails OPEN when `DASHBOARD_API_KEY` is unset
 *      ("no auth configured → open access"), which is a reasonable default for a
 *      dashboard that could only ever show anonymous data — but it is not a
 *      reasonable default in front of a privileged credential. This handler
 *      fails CLOSED instead: no `DASHBOARD_API_KEY`, no proxying.
 *
 *   2. An explicit path allowlist. Without it this would be an open relay to
 *      every route on the gateway — including the write endpoints closed in
 *      #244/#245/#247/#248 — reachable by anyone who can reach the dashboard.
 *      Adding a page means adding its path here, on purpose.
 *
 * Client-supplied `X-API-Key`, `Authorization` and cookies are never forwarded;
 * the upstream identity is the server's, not the caller's.
 */

const WARDEN = process.env.WARDEN_API_URL ?? "https://api.shadow-warden-ai.com";
const ANALYTICS = process.env.WARDEN_ANALYTICS_URL ?? "http://localhost:8002";

/** One path segment: matches an id, never a `/`. */
const SEG = "[^/]+";

/** Readable routes, anchored. Mirrors the call sites in `src/lib/api.ts`. */
const GET_ALLOW: RegExp[] = [
  // Analytics service
  /^\/api\/v1\/stats$/,
  /^\/api\/v1\/events$/,
  new RegExp(`^/api/v1/events/${SEG}$`),
  /^\/api\/v1\/threats$/,
  /^\/api\/v1\/compliance\/roi$/,

  // Gateway — platform
  /^\/health$/,
  /^\/deploy\/status$/,
  new RegExp(`^/xai/explain/${SEG}$`),

  // Compliance — JSON plus the downloadable report bundles linked from the UI
  /^\/compliance\/(posture|history|iso27001)$/,
  /^\/compliance\/soc2-bundle$/,
  /^\/compliance\/(smb-report|iso27001|nis2|hipaa)\/html$/,

  // Settings and semantic layer (read-only views)
  /^\/settings$/,
  /^\/semantic-layer\/models$/,

  // Governance and finance
  /^\/vendor-gov\/(stats|vendors)$/,
  /^\/vendor-gov\/dpa\/expiring$/,
  /^\/incidents$/,
  /^\/incidents\/stats$/,
  /^\/financial\/allocation\/(summary|departments)$/,
  /^\/financial\/budget\/status$/,
  new RegExp(`^/supplier-risk/report/${SEG}$`),
  /^\/prompt-library$/,
  /^\/training\/compliance-report$/,
  /^\/business-intelligence\/(usage|threats|compliance|predictions)$/,
  /^\/document-intel\/stats$/,
  /^\/smb-suite\/health$/,

  // Marketplace
  /^\/marketplace\/analytics\/(summary|volume|agents)$/,
  /^\/marketplace\/agents$/,
  new RegExp(`^/marketplace/agents/${SEG}/trust$`),
  /^\/marketplace\/listings$/,
  /^\/marketplace\/escrow$/,
  new RegExp(`^/marketplace/escrow/${SEG}$`),
  /^\/marketplace\/trust\/(graph|leaderboard)$/,
  /^\/marketplace\/stats$/,

  // Community
  /^\/sep\/ueciids\/search$/,
  /^\/sep\/audit-chain$/,
  new RegExp(`^/community-intel/${SEG}$`),
  new RegExp(`^/community-intel/${SEG}/oauth/summary$`),
  /^\/communities$/,
  /^\/communities\/stats$/,
  new RegExp(`^/communities/${SEG}$`),
  new RegExp(`^/communities/${SEG}/(members|data|compliance)$`),
  new RegExp(`^/communities/${SEG}/evolution/(stats|bundles)$`),
];

/**
 * Writable routes. Every entry is an action the dashboard performs with the
 * server's credential, so each one is a decision rather than a default.
 *
 * The marketplace entries move money or settle disputes. They are here because
 * the buttons already exist in the UI and have simply been failing; behind the
 * dashboard login the caller is the operator, who holds this key anyway. If that
 * is not the intended trust boundary, remove these four lines — the pages will
 * go back to erroring rather than doing something unintended.
 *
 * `PATCH /config` is deliberately absent: it retunes live detection sensitivity
 * for the whole gateway.
 */
const POST_ALLOW: RegExp[] = [
  /^\/filter$/,
  /^\/agent\/sova\/community\/lookup$/,
  /^\/smb-suite\/provision$/,
  /^\/semantic-layer\/query\/intent$/,

  // Operator actions
  /^\/marketplace\/listings$/,
  new RegExp(`^/marketplace/listings/${SEG}/purchase$`),
  new RegExp(`^/marketplace/escrow/${SEG}/dispute/vote$`),
  new RegExp(`^/marketplace/disputes/${SEG}/resolve$`),
];

/** Constant-time compare that tolerates unequal lengths. */
function secretsMatch(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Whether the caller holds a valid dashboard session.
 *
 * Fails closed when no `DASHBOARD_API_KEY` is configured: an unconfigured
 * deployment must not turn this route into an anonymous, authenticated relay to
 * the gateway.
 */
function sessionOk(req: NextRequest): boolean {
  const expected = process.env.DASHBOARD_API_KEY;
  if (!expected) return false;
  const token = req.cookies.get("warden_auth")?.value;
  return typeof token === "string" && secretsMatch(token, expected);
}

/** Rebuild the upstream path from routed segments; reject traversal. */
function resolvePath(segments: string[] | undefined): string | null {
  if (!segments || segments.length === 0) return null;
  for (const s of segments) {
    if (!s || s === "." || s === ".." || s.includes("/") || s.includes("\\")) {
      return null;
    }
  }
  return `/${segments.join("/")}`;
}

function upstreamFor(path: string): string {
  return path.startsWith("/api/v1/") ? ANALYTICS : WARDEN;
}

async function forward(
  req: NextRequest,
  segments: string[] | undefined,
  allow: RegExp[],
  body?: string,
): Promise<NextResponse> {
  if (!sessionOk(req)) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const path = resolvePath(segments);
  if (!path || !allow.some(rx => rx.test(path))) {
    return NextResponse.json({ error: "Route not proxied" }, { status: 404 });
  }

  const apiKey = process.env.WARDEN_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "Gateway credential not configured" },
      { status: 503 },
    );
  }

  const url = new URL(`${upstreamFor(path)}${path}`);
  req.nextUrl.searchParams.forEach((v, k) => url.searchParams.set(k, v));

  const headers: Record<string, string> = { "X-API-Key": apiKey };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  // `X-Tenant-ID` selects which tenant's record to read; it is not the
  // authenticator — see `warden/communities/router.py::_get_tenant`, which no
  // longer accepts it as one. Forwarded so the governance pages can address a
  // tenant, and safe only because the operator already holds this key.
  const tenant = req.headers.get("X-Tenant-ID");
  if (tenant) headers["X-Tenant-ID"] = tenant;

  try {
    const res = await fetch(url.toString(), {
      method: body === undefined ? "GET" : "POST",
      headers,
      ...(body === undefined ? {} : { body }),
      cache: "no-store",
    });
    const text = await res.text();
    return new NextResponse(text, {
      status: res.status,
      headers: {
        "Content-Type": res.headers.get("Content-Type") ?? "application/json",
      },
    });
  } catch {
    return NextResponse.json({ error: "Gateway unreachable" }, { status: 502 });
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: { path: string[] } },
): Promise<NextResponse> {
  return forward(req, params.path, GET_ALLOW);
}

export async function POST(
  req: NextRequest,
  { params }: { params: { path: string[] } },
): Promise<NextResponse> {
  return forward(req, params.path, POST_ALLOW, await req.text());
}
