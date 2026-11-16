// Response headers are set here, in the app, on purpose. Public traffic reaches
// this container through the Cloudflare Tunnel; Caddy is not on that path, so
// the `(security_headers)` snippet in docker/Caddyfile never reached a browser
// and this app answered with no HSTS, no nosniff and no framing rule at all.
//
// The CSP carries structural directives only. A script-src needs a per-request
// nonce in Next and is a separate piece of work; these three cannot break a
// page and they close framing (clickjacking), <base> hijacking and plugins.
const SECURITY_HEADERS = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Content-Security-Policy',
    value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
  },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',   // Node.js server — required for /api/hub/* server-side proxy
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: SECURITY_HEADERS }];
  },
  trailingSlash: true,    // /dashboard → /dashboard/index.html
  images: { unoptimized: true },
  // Next 15 streams metadata on a dynamic render: the tags are appended to
  // <body> once generateMetadata resolves. A storefront needs its description
  // and canonical in <head> for every reader, so metadata blocks for all user
  // agents. Lighthouse SEO fell to 0.92 on the catalog page without this.
  htmlLimitedBots: /.*/,
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'https://api.shadow-warden-ai.com',
  },
}

module.exports = nextConfig
