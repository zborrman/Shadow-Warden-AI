// Vercel Edge Middleware — re-assert the true client IP across the server-side
// rewrite of same-origin API calls (www.* → Vercel → api.shadow-warden-ai.com).
//
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

import { next } from "@vercel/edge";

export const config = {
  // Only the proxied API paths need client-IP re-assertion.
  matcher: ["/api/:path*"],
};

export default function middleware(request: Request) {
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
