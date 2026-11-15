/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',   // Node.js server — required for /api/hub/* server-side proxy
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
