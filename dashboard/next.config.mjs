// Response headers are set here, in the app, on purpose. Public traffic reaches
// this container through the Cloudflare Tunnel; Caddy is not on that path, so
// the `(security_headers)` snippet in docker/Caddyfile never reached a browser
// and this app answered with no HSTS, no nosniff and no framing rule at all.
//
// The CSP carries structural directives only. A script-src needs a per-request
// nonce in Next and is a separate piece of work; these three cannot break a
// page and they close framing (clickjacking), <base> hijacking and plugins.
const SECURITY_HEADERS = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  {
    key: "Content-Security-Policy",
    value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
  },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
  // The image optimizer is an anonymous endpoint (/_next/image) that decodes
  // caller-chosen files. Nothing in this app uses next/image, so it stays
  // switched off after the move to 15.5.29 (which carries the fixes for
  // GHSA-2464-fhr4-w9xw / GHSA-2xp9-vwfh-vxw4 / GHSA-p293-qw3h-jr36): an
  // endpoint nobody uses is not worth keeping reachable.
  // docker/Caddyfile refuses the path as well, so a config regression here
  // does not reopen it.
  images: { unoptimized: true },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com",
    NEXT_PUBLIC_ANALYTICS_URL: process.env.NEXT_PUBLIC_ANALYTICS_URL ?? "http://localhost:8002",
    // OB-F21: no default host for a loopback-only service. Each of these was
    // a different guess in a different file, and every guess was wrong once
    // OB-7 bound them to 127.0.0.1. Empty means "not published", and the UI
    // renders the tunnel command instead of a link that cannot work. See
    // src/lib/internal-links.ts.
    NEXT_PUBLIC_GRAFANA_URL: process.env.NEXT_PUBLIC_GRAFANA_URL ?? "",
    NEXT_PUBLIC_JAEGER_URL: process.env.NEXT_PUBLIC_JAEGER_URL ?? "",
    NEXT_PUBLIC_PROMETHEUS_URL: process.env.NEXT_PUBLIC_PROMETHEUS_URL ?? "",
    NEXT_PUBLIC_MINIO_URL: process.env.NEXT_PUBLIC_MINIO_URL ?? "",
  },
};

export default nextConfig;
