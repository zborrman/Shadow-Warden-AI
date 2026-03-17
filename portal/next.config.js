/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',       // static export — served by nginx as plain files
  trailingSlash: true,    // /dashboard → /dashboard/index.html
  images: { unoptimized: true },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'https://api.shadow-warden-ai.com',
  },
}

module.exports = nextConfig
