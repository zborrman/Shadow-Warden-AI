# Shadow Warden Installer Worker — Deployment Guide

Serves `install.sh` at `https://get.shadowwarden.ai/install` via Cloudflare Workers.

## Prerequisites

- Cloudflare account with `shadowwarden.ai` zone
- Node.js ≥ 18 and `wrangler` CLI

```bash
npm install -g wrangler
wrangler login          # opens browser → authorize
```

---

## Step 1 — Create KV namespaces

```bash
cd cloudflare/installer-worker

# Production namespace
wrangler kv:namespace create INSTALL_STATS
# → outputs: id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Preview namespace (used by wrangler dev)
wrangler kv:namespace create INSTALL_STATS --preview
# → outputs: preview_id = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
```

Open `wrangler.toml` and replace the placeholder IDs:

```toml
[[kv_namespaces]]
binding    = "INSTALL_STATS"
id         = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"   # ← paste production id
preview_id = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"   # ← paste preview id
```

---

## Step 2 — Set the stats secret

This token protects `GET /stats`. Choose a strong random value:

```bash
wrangler secret put STATS_TOKEN
# Paste a random token when prompted, e.g.: openssl rand -hex 32
```

---

## Step 3 — Deploy

```bash
npm install          # installs wrangler locally (optional if already global)
wrangler deploy
```

Expected output:
```
Uploaded shadow-warden-installer (X.XXs)
Published shadow-warden-installer (X.XXs)
  https://shadow-warden-installer.<your-subdomain>.workers.dev
```

---

## Step 4 — Custom domain: get.shadowwarden.ai

In the Cloudflare dashboard:

1. **Workers & Pages** → `shadow-warden-installer` → **Settings** → **Domains & Routes**
2. Click **Add Custom Domain**
3. Enter: `get.shadowwarden.ai`
4. Cloudflare will automatically create a CNAME DNS record.

> No separate DNS record is required — Cloudflare handles it.

---

## Step 5 — Verify

```bash
# Health check
curl https://get.shadowwarden.ai/health

# Serve the installer (trial)
curl -sSL "https://get.shadowwarden.ai/install?plan=trial" | head -5

# Stats (replace TOKEN with what you set in Step 2)
curl -H "X-Stats-Token: TOKEN" https://get.shadowwarden.ai/stats
```

---

## Local development

```bash
wrangler dev
# → http://localhost:8787/install
# → http://localhost:8787/health
```

KV reads/writes hit the preview namespace during `wrangler dev`.

---

## Environment variables (wrangler.toml [vars])

| Variable          | Default | Description                          |
|-------------------|---------|--------------------------------------|
| `SCRIPT_VERSION`  | `2.9`   | Echoed in `X-Script-Version` header  |
| `GITHUB_RAW_URL`  | (set)   | Source of `install.sh` on GitHub     |

`STATS_TOKEN` is a **secret** (set via `wrangler secret put`, never in toml).

---

## KV key schema

| Key                       | Value  | TTL     |
|---------------------------|--------|---------|
| `stats:total`             | number | none    |
| `stats:trial`             | number | none    |
| `stats:paid`              | number | none    |
| `stats:country:{CC}`      | number | none    |
| `stats:date:{YYYY-MM-DD}` | number | 90 days |
| `ratelimit:{ip}`          | number | 1 hour  |

---

## Updating the installer script

The Worker fetches `install.sh` fresh from GitHub (cached 5 min at edge).
Just push a new commit to `scripts/install.sh` — no Worker redeploy needed.

To bump the displayed version, edit `SCRIPT_VERSION` in `wrangler.toml` and run `wrangler deploy`.
