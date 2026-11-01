# Site page map (S0)

Phase S0 of the site concept rebuild: one decision per page, and the redirect
map the later phases apply. Nothing here changes the site by itself — S1 to S3
execute it, and each of those PRs ticks its rows off.

Inventory of `site/src/pages` on 2026-11-01: **59 page files plus 4 `[slug]`
templates that expand to 21 routes** (79 distinct routes once the collision below is counted once). (The plan
said 57; pages were added since.) One template route collides with a static
file: `/cyber-security/document-intelligence` exists both ways and the static
page wins.

## Hubs (S1, shipped in #638)

| Hub | Landing | Owns |
|---|---|---|
| Protect | `/cyber-security` | the filter pipeline and detection |
| Govern | `/trust` | compliance, evidence, status, dashboards |
| Trade | `/agentic` | marketplace, commerce, communities, tunnels |
| Build | `/doc` | API docs, SDK, CLI, MCP, roadmap |
| Account | `/price` | pricing, sign-up, account |

## Decisions

`keep` stays as is. `merge → X` folds the content into X and leaves a 308.
`app` is a signed-in or interactive surface, kept but taken out of the
sitemap and marked `noindex` in S3. `utility` is a flow page (errors,
confirmations), same treatment. `redirect` already answers with a redirect.

"In" is the number of links to the page from elsewhere in `site/src`.

### Protect

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/cyber-security` | 97 | 13 | keep — hub; rebuilt on the hub template in S2 |
| `/cyber-security/security-pipeline` | slug | nav | keep |
| `/cyber-security/agentic-soc` | slug | nav | keep |
| `/cyber-security/cryptography` | slug | nav | keep |
| `/cyber-security/ai-research-evolution` | slug | nav | keep |
| `/cyber-security/document-intelligence` | 324 | 1 | keep (static page shadows the slug route) |
| `/playground` | 207 | 2 | keep |
| `/fraud-score` | 696 | 1 | keep |

### Govern

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/trust` | 708 | 8 | keep — hub |
| `/cyber-security/compliance-privacy` | slug | nav | keep |
| `/doc/compliance` | 38 | 12 | keep (Build docs page, linked from the footer) |
| `/doc/testing-quality` | 26 | 1 | merge → `/trust` |
| `/smb` | 479 | 1 | keep |
| `/dashboard` | 134 | 4 | keep |
| `/dashboard/analytics` | slug | 0 | merge → `/dashboard` |
| `/dashboard/dashboards-portals` | slug | 0 | merge → `/dashboard` |
| `/dashboard/frontend-product-surfaces` | slug | 0 | merge → `/dashboard` |
| `/dashboard/infrastructure` | slug | 0 | merge → `/dashboard` |
| `/dashboard/infrastructure-devops` | slug | 0 | merge → `/dashboard` |
| `/dashboard/observability` | slug | 0 | merge → `/dashboard` |
| `/dashboard/soc-dashboard` | slug | 0 | merge → `/dashboard` |
| `/dashboard/tenant-portal` | slug | 0 | merge → `/dashboard` |
| `/analytics` | 330 | 0 | merge → `/dashboard` |
| `/status` | 750 | 2 | keep |

### Trade

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/agentic` | 888 | 12 | keep — hub |
| `/marketplace` | 357 | 5 | keep (live listings read from the API; `/agentic` is the product page) |
| `/business-community` | 726 | 8 | keep |
| `/business-community/agentic-commerce` | slug | nav | merge → `/business-community` (nav item goes in S3) |
| `/business-community/business-intelligence` | slug | 0 | merge → `/business-community` |
| `/business-community/community-collaboration` | slug | 0 | merge → `/business-community` |
| `/business-community/integrations` | slug | 0 | merge → `/business-community` |
| `/business-community/m2m-store` | 168 | 0 | merge → `/agentic` |
| `/tunnel` | 252 | 3 | keep |
| `/tunnel/masque-tunnels` | slug | nav | merge → `/tunnel` (nav item goes in S3) |
| `/tunnel/per-tenant-routing` | slug | 0 | merge → `/tunnel` |
| `/tunnel/sovereign-ai-cloud` | slug | 0 | merge → `/tunnel` |
| `/community` | 3 | 76 | redirect (301 → `/agentic` already) |
| `/community/view` | 1414 | 16 | app |
| `/community/new` | 998 | 4 | app |
| `/community/members` | 451 | 4 | app |
| `/community/integrations` | 431 | 4 | app |
| `/community/tunnel` | 291 | 4 | app |
| `/community/settings` | 222 | 4 | app |
| `/community/activity` | 210 | 3 | app |
| `/community/portal` | 589 | 0 | merge → `/community/view` |

The `/community/*` pages keep their data in `localStorage` and simulate the
E2EE key exchange; they are a demo surface and must stay labelled as such
(capability matrix: SIMULATED).

### Build

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/doc` | 63 | 52 | keep — hub |
| `/doc/quick-start` | 134 | 11 | keep |
| `/doc/api-reference` | 144 | 8 | keep |
| `/doc/authentication` | 143 | 4 | keep |
| `/doc/rate-limits` | 131 | 5 | keep |
| `/doc/versioning` | 102 | 1 | keep |
| `/doc/changelog` | 69 | 4 | keep |
| `/developers` | 201 | 6 | merge → `/doc` (has a markdown variant: update `MARKDOWN_ROUTES`, `site/public/developers.md` and the apex matcher in the same PR) |
| `/sdk` | 312 | 4 | keep |
| `/cli` | 102 | 3 | keep |
| `/mcp` | 170 | 4 | keep |
| `/roadmap` | 207 | 4 | keep |

### Account

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/price` | 875 | 22 | keep — hub |
| `/pricing` | 596 | 8 | merge → `/price` (S1 tail). Both pages carry a cost calculator; port anything `/price` lacks before the redirect. `pricing.md` already answers both URLs. |
| `/signup` | 351 | 3 | app |
| `/login` | 292 | 2 | app |
| `/account` | 279 | 9 | app |
| `/account/privacy` | 122 | 2 | app |
| `/account/storage` | 191 | 2 | app |
| `/settings` | 1749 | 5 | app |

### Company and legal (footer)

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/` | 960 | — | keep |
| `/about` | 90 | 1 | keep |
| `/contact` | 123 | 4 | keep |
| `/enterprise-guide` | 658 | 10 | keep (LICENSE points here; its `<title>` is "FinTech / Banking" and needs fixing) |
| `/enterprise` | 6 | 1 | redirect (301 → `/enterprise-guide` already) |
| `/terms` | 123 | 2 | keep |
| `/privacy` | 153 | 3 | keep |
| `/refund` | 104 | 2 | keep |
| `/bot` | 35 | 0 | keep (the user agent string links here; the URL must not move) |

### Utility

| Route | Lines | In | Decision |
|---|---:|---:|---|
| `/404` | 42 | — | utility |
| `/logout` | 41 | 1 | utility |
| `/goodbye` | 38 | 1 | utility |
| `/thank-you` | 70 | 1 | utility |
| `/incident` | 179 | 0 | utility (shareable incident card, reached by link) |

## Result

| | Routes |
|---|---:|
| keep (indexable) | 38 |
| app + utility (noindex, out of sitemap) | 18 |
| merge → 308 | 21 |
| already a redirect | 2 |
| **total routes** | **79** |

38 indexable pages, not the plan's ~25. Getting lower than this means merging
pages that each have their own audience today (for example `/smb` into
`/trust`, or `/sdk`, `/cli` and `/mcp` into `/doc`); that is a call for S3
with the hub pages from S2 in front of us, not for this map.

## Redirect map (applied in S3)

Every redirect is a 308, added in **both** `vercel.json` (www) and
`docker/Caddyfile` (apex) — the two surfaces serve the site separately.

| From | To |
|---|---|
| `/pricing` | `/price` |
| `/developers` | `/doc` |
| `/developer` | `/doc` (today `/developer` → `/developers`; collapse the chain) |
| `/doc/testing-quality` | `/trust` |
| `/analytics` | `/dashboard` |
| `/dashboard/analytics` | `/dashboard` |
| `/dashboard/dashboards-portals` | `/dashboard` |
| `/dashboard/frontend-product-surfaces` | `/dashboard` |
| `/dashboard/infrastructure` | `/dashboard` |
| `/dashboard/infrastructure-devops` | `/dashboard` |
| `/dashboard/observability` | `/dashboard` |
| `/dashboard/soc-dashboard` | `/dashboard` |
| `/dashboard/tenant-portal` | `/dashboard` |
| `/business-community/agentic-commerce` | `/business-community` |
| `/business-community/business-intelligence` | `/business-community` |
| `/business-community/community-collaboration` | `/business-community` |
| `/business-community/integrations` | `/business-community` |
| `/business-community/m2m-store` | `/agentic` |
| `/tunnel/masque-tunnels` | `/tunnel` |
| `/tunnel/per-tenant-routing` | `/tunnel` |
| `/tunnel/sovereign-ai-cloud` | `/tunnel` |
| `/community/portal` | `/community/view` |

## Findings outside the plan

- **The sitemap lists every page**, including `/login`, `/account/*`,
  `/goodbye` and the `/community/*` app pages. `@astrojs/sitemap` has no
  `filter` in `site/astro.config.mjs`. S3 adds one for the app and utility rows
  above.
- **Eight links still point at `/pricing`** (`/analytics`, `/sdk`,
  `/doc/authentication`, `/settings`, `/business-community/m2m-store`) while
  the nav points at `/price`. They move to `/price` with the S1 tail.
- **`/enterprise-guide` has the title "FinTech / Banking".**
