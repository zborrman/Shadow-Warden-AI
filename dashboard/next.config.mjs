/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
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
