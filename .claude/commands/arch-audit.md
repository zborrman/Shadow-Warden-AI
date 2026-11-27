---
description: Fact-based architecture audit of Shadow Warden — coupling, tech debt, security posture and AI-readiness
---

Run a strict engineering audit of this repository. Facts from the code only: every finding names a file
(and a line where it matters). Answer in the language the user writes in.

### Step 1. Collect data (cheap first)
1. `node scripts/analyze-arch.mjs` — the snapshot (git-tracked files only; Python included; vendored
   `.agents/`, `skills/` and generated `landing/` excluded). Read `summary`, `byArea`, `largestFiles`,
   `circularDependencies` (check `resolvedLocalImports` is non-zero before trusting a zero cycle count)
   and `aiReadiness`.
2. Read the rules the audit is measured against: `CLAUDE.md` (Feature Freeze, SP-01…SP-07, Claims Rule,
   Branch Hygiene) and `warden/CLAUDE.md` (engine architecture).
3. Configs: `site/astro.config.mjs`, `portal/next.config.js`, `dashboard/next.config.mjs`, each `tsconfig.json`,
   `pyproject.toml`, `docker-compose.yml` (service list only).
4. Open only the top 5 of `largestFiles`, and only far enough to say what makes each one large.

### Step 2. Score five axes (1–10), each with file references
1. **Modularity** — layer boundaries in `warden/` (routers vs services vs data layer: `open_db()` seam,
   DDL registry); god files (> 300 lines); cycles; the four frontends (`site/`, `portal/`, `dashboard/`,
   Streamlit) staying within their remit (no fifth frontend).
2. **Performance & rendering** — static vs server rendering per frontend, `'use client'` spread, fonts
   and images. Never give a latency or Core Web Vitals number nobody measured; say "unmeasured" (Claims Rule).
3. **AI-readiness / GEO** — `site/public/llms.txt`, `robots.txt` AI-crawler policy, sitemap, JSON-LD on
   both layouts, `Accept: text/markdown` negotiation (`edge/negotiate.mjs`, `MARKDOWN_ROUTES`),
   `/.well-known/*`, `openapi.json` freshness. Cite `warden/tests/test_site_agent_readiness*.py`.
4. **Security & reliability** — the ratchets are the evidence: anonymous read/write probes, tenant
   isolation baseline, signing keys via `resolve_key`, client IP via `get_client_ip`, GDPR content-never-logged,
   fail-closed vs fail-open choices. TypeScript `strict` and `any` count; ruff/mypy status if cheap.
5. **Maintainability (DX)** — duplication, dead code and dependencies, design-token consistency
   (`portal/src/styles/shell.css` must equal the site's — `test_portal_shell_parity.py`).

Optional, when a site build is being served: `cd site && npx playwright test -c playwright.integrity.config.ts`
(every static route: HTTP status, broken same-origin requests, console errors, uncaught exceptions,
secrets in `window` / Web Storage). Report its result as an axis-4 fact.

### Step 3. Output
1. **Score table** — Axis | Score | Main blocker (file).
2. **P0** — what is broken or exposed right now (security first: cross-tenant reads, auth bypass,
   secrets). Check `git log origin/main` and open PRs first so a fixed issue is not reported as open.
3. **Plan** — 3–5 steps by return on effort: what to touch, why, expected effect. Respect the Feature
   Freeze: a step that adds a subsystem, router or frontend is out unless a numbered phase calls for it;
   say which rule blocks it rather than dropping it silently. Files shared by both modernization tracks
   (`causal_arbiter.py`, the data layer, `staff_dispatch`, `net_guard`, key hygiene) are flagged as
   "needs a phase", not "quick fix".
