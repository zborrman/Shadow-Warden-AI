// Vercel Edge Middleware. Two jobs, split by path:
//
//   /api/*  — re-assert the true client IP across the server-side rewrite of
//             same-origin API calls (www.* → Vercel → api.shadow-warden-ai.com).
//   pages   — content negotiation for `Accept: text/markdown`
//             (https://acceptmarkdown.com), plus a markdown 404 body.
//
// ── /api/* ───────────────────────────────────────────────────────────────────
// A `vercel.json` rewrite proxies /api/auth/* (and the other /api/* entries) to
// the warden API. Because that is a server-to-server hop, warden would otherwise
// see Vercel's egress IP for every browser request — collapsing all logins into
// one rate-limit bucket. This middleware forwards the real client IP in a
// dedicated header, proven by a shared secret (VERCEL_PROXY_SECRET) so a
// direct-to-origin attacker cannot forge it. warden trusts the header only when
// the secret matches (see warden/client_ip.py::get_client_ip).
//
// No secret configured → headers are omitted and warden falls back to its
// existing behaviour. Never fail the request over this.
//
// ── pages ────────────────────────────────────────────────────────────────────
// Negotiation happens on the same URL that serves HTML, and every page response
// carries `Vary: Accept` so a CDN cannot hand an agent the HTML variant that a
// browser warmed (or the reverse). Clients that send `*/*` — curl, most
// crawlers — keep getting HTML: a wildcard is not a request for markdown.
//
// Every failure path falls through to `next()`. A negotiation bug must not be
// able to take the marketing site down.

import { next } from "@vercel/edge";

import {
  PROBE_HEADER,
  notAcceptableBody,
  planAfterProbe,
  planRequest,
} from "./edge/negotiate.mjs";

export const config = {
  matcher: [
    // The proxied API paths need client-IP re-assertion.
    "/api/:path*",
    // Every page route. Anything with a file extension (/llms.txt, /index.md,
    // /openapi.json, /sitemap-0.xml, /favicon.ico) and every built asset is
    // excluded: those are served straight from the CDN, and excluding them is
    // also what stops the internal probe below from re-entering middleware.
    "/((?!api/|_astro/|.*[.][a-zA-Z0-9]{1,8}$).*)",
  ],
};

const MARKDOWN_HEADERS = {
  "content-type": "text/markdown; charset=utf-8",
  vary: "Accept",
  "cache-control": "public, max-age=0, must-revalidate",
};

function clientIpMiddleware(request: Request) {
  const secret = process.env.VERCEL_PROXY_SECRET;
  if (!secret) {
    return next();
  }

  // Vercel populates x-real-ip / x-forwarded-for with the true client at the edge.
  const clientIp =
    request.headers.get("x-real-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim();

  if (!clientIp) {
    return next();
  }

  const headers = new Headers(request.headers);
  headers.set("x-warden-proxy-secret", secret);
  headers.set("x-warden-client-ip", clientIp);

  return next({ request: { headers } });
}

/** HTML, with the Vary that keeps a CDN from crossing the two variants. */
function htmlResponse() {
  return next({ headers: { Vary: "Accept" } });
}

function markdownResponse(body: string, status: number) {
  return new Response(body, { status, headers: MARKDOWN_HEADERS });
}

/** Fetch one of our own static files. Never throws — null means "could not". */
async function fetchSelf(url: URL): Promise<Response | null> {
  try {
    return await fetch(url, { headers: { [PROBE_HEADER]: "1" }, redirect: "manual" });
  } catch {
    return null;
  }
}

async function serveMarkdown(file: string, base: URL, status: number): Promise<Response> {
  const response = await fetchSelf(new URL(file, base));
  if (response && response.ok) {
    return markdownResponse(await response.text(), status);
  }
  // The file should exist — warden/tests/test_site_agent_readiness.py asserts
  // every mapped route has one. If it somehow does not, HTML beats an error.
  return status === 404
    ? markdownResponse("# 404 Not Found\n\nSee https://shadow-warden-ai.com/llms.txt\n", 404)
    : htmlResponse();
}

export default async function middleware(request: Request) {
  const url = new URL(request.url);

  if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
    return clientIpMiddleware(request);
  }

  try {
    const accept = request.headers.get("accept");
    const plan = planRequest({
      method: request.method,
      pathname: url.pathname,
      accept,
      isProbe: request.headers.get(PROBE_HEADER) !== null,
    });

    switch (plan.action) {
      case "pass":
        return next();
      case "html":
        return htmlResponse();
      case "not-acceptable":
        return markdownResponse(notAcceptableBody(), 406);
      case "markdown":
        return await serveMarkdown(plan.file, url, plan.status ?? 200);
      case "probe": {
        // Does this path exist at all? A 404 deserves a markdown body that
        // tells the agent where to go instead of an HTML shell it cannot read.
        const probe = await fetchSelf(url);
        const after = planAfterProbe({ accept, status: probe?.status ?? 200 });
        if (after.action === "markdown") {
          return await serveMarkdown(after.file, url, after.status ?? 200);
        }
        if (after.action === "not-acceptable") {
          return markdownResponse(notAcceptableBody(), 406);
        }
        return htmlResponse();
      }
      default:
        return next();
    }
  } catch {
    // A negotiation bug must never be able to take the site down.
    return next();
  }
}
