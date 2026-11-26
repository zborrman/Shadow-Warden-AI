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
  output: 'standalone',   // Node.js server: the storefront renders on request (ISR)
  poweredByHeader: false,
  async headers() {
    return [
      { source: '/:path*', headers: SECURITY_HEADERS },
      // The Listing Preflight simulator is the one document the portal frames,
      // and only from itself (/preflight/ shows it in a sandboxed iframe). Later
      // rules override earlier ones for the same key, so this narrows nothing
      // else. Being static, it can carry a full CSP without a nonce.
      {
        source: '/preflight/sim.html',
        headers: [
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; " +
              "font-src https://fonts.gstatic.com; img-src data: blob:; connect-src 'none'; form-action 'none'; " +
              "base-uri 'none'; frame-ancestors 'self'",
          },
        ],
      },
      // Pages are prerendered, and Next answers them with only
      // `s-maxage=31536000`, which leaves a browser free to reuse its copy
      // heuristically. After a deploy that is the old page. `no-cache` makes
      // the browser revalidate every document; hashed /_next/static assets are
      // excluded so they keep their immutable caching.
      {
        source: '/((?!_next/static|_next/image|favicon|logo|accessibility-widget).*)',
        headers: [{ key: 'Cache-Control', value: 'no-cache, must-revalidate' }],
      },
    ];
  },
  // Screens retired on 2026-11-26 (owner decision): they did not work with a
  // seller's session, and the compliance one showed the platform's own data to
  // every seller. Old links land on Overview instead of a 404.
  async redirects() {
    const retired = ['communities', 'community-hub', 'compliance', 'cost-allocation', 'deployment',
      'doc-scanner', 'extension', 'hub', 'incidents', 'intelligence', 'prompts', 'supplier-risk',
      'training', 'vendor-governance', 'settings/agents', 'settings/api-keys', 'settings/compliance',
      'settings/notifications', 'settings/secrets'];
    return retired.flatMap(r => [
      { source: `/${r}`, destination: '/dashboard/', permanent: false },
      { source: `/${r}/:rest*`, destination: '/dashboard/', permanent: false },
    ]);
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
