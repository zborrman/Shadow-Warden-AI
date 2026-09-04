FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1

# OB-F21: Next inlines every NEXT_PUBLIC_* at BUILD time, so anything supplied
# only as a runtime `environment:` entry never reaches the browser bundle.
# docker-compose.yml had been passing NEXT_PUBLIC_GRAFANA_URL at runtime since
# the dashboard was written, and it had no effect whatsoever — the value that
# actually shipped came from next.config.mjs's fallback.
#
# That matters most for the case that does not exist yet: when the Grafana
# vhost behind Cloudflare Access is up, someone will set GRAFANA_PUBLIC_URL in
# the host .env, redeploy, and see nothing change. A setting that looks applied
# and is not is the whole defect class this repo keeps finding, so wire the
# build args now rather than leaving the trap armed.
#
# Empty defaults are deliberate: an unset service renders its SSH tunnel
# command instead of a link that cannot resolve. See src/lib/internal-links.ts.
ARG NEXT_PUBLIC_API_URL=https://api.shadow-warden-ai.com
ARG NEXT_PUBLIC_ANALYTICS_URL=
ARG NEXT_PUBLIC_GRAFANA_URL=
ARG NEXT_PUBLIC_JAEGER_URL=
ARG NEXT_PUBLIC_PROMETHEUS_URL=
ARG NEXT_PUBLIC_MINIO_URL=
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL     NEXT_PUBLIC_ANALYTICS_URL=$NEXT_PUBLIC_ANALYTICS_URL     NEXT_PUBLIC_GRAFANA_URL=$NEXT_PUBLIC_GRAFANA_URL     NEXT_PUBLIC_JAEGER_URL=$NEXT_PUBLIC_JAEGER_URL     NEXT_PUBLIC_PROMETHEUS_URL=$NEXT_PUBLIC_PROMETHEUS_URL     NEXT_PUBLIC_MINIO_URL=$NEXT_PUBLIC_MINIO_URL

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
RUN mkdir -p ./public
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3002
ENV PORT=3002
ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
