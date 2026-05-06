/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com",
    NEXT_PUBLIC_ANALYTICS_URL: process.env.NEXT_PUBLIC_ANALYTICS_URL ?? "http://localhost:8002",
    NEXT_PUBLIC_GRAFANA_URL: process.env.NEXT_PUBLIC_GRAFANA_URL ?? "http://localhost:3000",
    NEXT_PUBLIC_JAEGER_URL: process.env.NEXT_PUBLIC_JAEGER_URL ?? "http://localhost:16686",
  },
};

export default nextConfig;
