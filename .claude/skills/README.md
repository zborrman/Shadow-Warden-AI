# Skills — Shadow Warden AI

Which Claude Code skill to reach for, and when. Every entry below was checked
against this repo — the "Anchor" column is the file or directory that justifies
it. If an anchor disappears, drop the skill from this list.

Skills come from three places:

| Source | Scope | Portable with the repo? |
|--------|-------|--------------------------|
| `.claude/skills/` (this directory) | project | **yes** — tracked in git |
| plugins (`cloudflare:`, `stripe:`, `figma:`, …) | machine | no — installed per machine |
| built-ins (`security-review`, `dataviz`, …) | machine | no — ship with Claude Code |

Only the four in this directory travel with a checkout. Everything else has to
be installed on whatever machine is running the session.

---

## Project skills (this directory)

| Skill | Use when |
|-------|----------|
| `run-warden` | Verifying a change against the real running gateway — boot, `/health`, `/filter` pipeline, route presence. Use this instead of assuming the test suite covers it. |
| `site-health-check` | Frontend audit of `site/` — Playwright smoke, WebMCP attributes, Lighthouse Agentic Browsing, `llms.txt` + `agent.json` reachability. |
| `design-recon` | Extracting a design system (color/type/spacing/motion) from a reference site or Figma file and adapting it to our tokens. |
| `shadow-warden-design` | Writing any UI — the canonical dark/indigo token set and component patterns. Read before hand-rolling CSS. |

## Core toolkit

| Skill | Anchor | Use when |
|-------|--------|----------|
| `claude-api` | `anthropic` in `warden/requirements.txt` | Any work in `warden/agent/*`, `warden/staff/*`, or `warden/brain/evolve.py` — model IDs, pricing, prompt caching, tool-use loops, cost accounting. Read it before editing model routing; do not answer model/pricing questions from memory. |
| `wrangler`, `workers-best-practices` | `worker/`, `cloudflare/installer-worker/`, `cloudflare/preflight-worker/`, `workers/shadow-warden-marketplace/` | Editing or deploying any of the four Workers. All four bind KV only — there are no Durable Object, D1, or Queue bindings, so `durable-objects` does not apply. |
| `cloudflare` | `cloudflared` service in `docker-compose.yml`, `docker/Caddyfile` | Edge posture work — WAF rules, rate limits, DNS, origin lockdown. |
| `cloudflare-one` | Zero Trust / Tunnel / Access | Putting an internal service behind Access. The Jaeger endpoint (`127.0.0.1:16686`, no auth) is the open case. |
| `terraform` (MCP) | `infra/terraform/main.tf` | Any change under `infra/terraform/`. Get explicit confirmation before `create_run` / `apply_run`. |
| `stripe-best-practices`, `stripe-docs`, `explain-error` | `warden/stripe_billing.py`, `warden/tests/test_stripe_billing_v25.py` | Billing work. Note this repo runs **two** providers — Stripe and Lemon Squeezy (`warden/lemon_billing.py`, `site/src/config/lemonsqueezy.ts`); confirm which path you are in before changing either. |
| `mcp-server-dev:build-mcp-server` | `warden/mcp/gateway.py`, `.mcp.json` | Extending the paid MCP gateway or the ACP protocol surface. |
| `playwright` (MCP) | `site/playwright.config.ts` | Driving a browser directly. The 32 site assertions are a protected loop invariant — never weaken one to make a run go green. |
| `dataviz` | Recharts in `dashboard/` + `portal/`, Streamlit `warden/analytics/pages/`, Grafana | **Before** writing any chart, stat tile, or dashboard layout, in any of the three frontends. |
| `web-perf`, `chrome-devtools` | `site/` (Astro) | Core Web Vitals, Lighthouse, render-blocking and layout-shift work. `site-health-check` already wraps the Lighthouse pass — reach for these when you need to go deeper. |
| `impeccable`, `ui-ux-pro-max`, `frontend-design` | `DESIGN.md`, `.impeccable/`, `packages/ui/` | UI/UX design and polish across `site/`, `dashboard/`, `portal/`. Pair with `shadow-warden-design` so the tokens stay ours. |
| `security-review`, `coderabbit:code-review`, `simplify` | `.github/workflows/claude-security-review.yml` | Before opening a PR, especially one touching the security-critical file list that triggers the Opus audit. |
| `loop`, `schedule`, `update-config` | `.github/workflows/autonomous-security-loop.yml` | Recurring or scheduled work, and any hook/permission/settings change. The nightly 02:00 UTC audit is exactly this shape. |

## Deliberately not used

Named here so they do not get re-evaluated every session.

| Skill / cluster | Why not |
|-----------------|---------|
| `durable-objects`, `sandbox-sdk`, `agents-sdk` | The four Workers bind KV only; no DO, no sandbox, and SOVA runs in FastAPI, not on Workers. |
| `supabase` (2), `prisma`, `base44` (3) | Not in the stack — storage is Postgres + Redis + per-module SQLite + MinIO. |
| `figma` (10) | No Figma files in the workflow; `design-recon` already covers extracting a design system from a reference. |
| `canva` (6), `gamma` | Marketing collateral, no code path. |
| wiki cluster (13: `wiki-*`, `cross-linker`, `tag-taxonomy`, `llm-wiki`, `*-ingest`) | Personal Obsidian knowledge management. Unrelated to `obsidian-plugin/` and `warden/integrations/obsidian/`, which are product features. |
| most `slack:*` | Slack is an alert **sink** here (`warden/alerting.py`), not a workspace we read. `slack:block-kit` is the exception — useful for formatting alert payloads. |
| `agent-sdk-dev` | The autonomous loop shells out to `claude --print`; it is not an Agent SDK application. |
| `cloudflare-email-service`, `cloudflare-one-migrations` | No transactional email path; no Zscaler/legacy SASE migration. |

## Open candidate

`turnstile-spin` has **zero** references in the repo, but `POST /auth/signup` is
public and Cloudflare Bot Fight Mode has repeatedly broken legitimate flows
(see `docs/cloudflare-waf.md`). This is the one uninstalled skill that maps to a
real open problem.
