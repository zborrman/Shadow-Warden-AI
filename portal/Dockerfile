# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

# API URL baked at build time (public — safe for browser)
ARG NEXT_PUBLIC_API_URL=https://api.shadow-warden-ai.com
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

# ── Stage 2: standalone Node.js server ────────────────────────────────────────
# output: 'standalone' produces .next/standalone — a minimal self-contained
# Node server that supports API routes (required for /api/hub/* proxy).
FROM node:20-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001

# Copy standalone bundle + static assets
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

EXPOSE 3001

CMD ["node", "server.js"]
