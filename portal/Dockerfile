# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:26-alpine AS builder
WORKDIR /app

# Install exactly what package-lock.json records, not a fresh resolution.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# API URL baked at build time (public — safe for browser)
ARG NEXT_PUBLIC_API_URL=https://api.shadow-warden-ai.com
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

# ── Stage 2: standalone Node.js server ────────────────────────────────────────
# output: 'standalone' produces .next/standalone — a minimal self-contained
# Node server that supports API routes (required for /api/hub/* proxy).
FROM node:26-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001

# Copy standalone bundle + static assets.
# `output: 'standalone'` does NOT bundle .next/static or public/ — both must be
# copied explicitly or every /logo.png, /favicon.ico, ... 404s at runtime.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

# Non-root (the image's built-in `node`, uid 1000). The app owns its files so
# the ISR cache under .next/cache stays writable.
USER node

EXPOSE 3001

CMD ["node", "server.js"]
