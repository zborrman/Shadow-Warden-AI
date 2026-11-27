---
description: Find and fix technical-SEO gaps on the Shadow Warden site (titles, descriptions, canonical, OpenGraph, h1, alt, JSON-LD, sitemap, IndexNow)
argument-hint: [production origin, default https://www.shadow-warden-ai.com]
---

Implement the missing technical-SEO layer for `${ARGUMENTS:-https://www.shadow-warden-ai.com}`.
Answer in the language the user writes in; everything written to the repo is English.

### Step 1. Measure on the built site (not the source)
1. `cd site && npm run build` — titles, canonical, OpenGraph and JSON-LD come from `BaseLayout` props,
   so only the build shows what a crawler gets.
2. `node scripts/audit-seo.mjs` (defaults `site/dist`, `site/public`). Read `globalArtifacts`, `issueCount`
   and group `issues` by kind before touching anything.

### Step 2. Fix through the existing seams
- **Per page**: pass `title` (≤ 65 chars) and `description` (70–170 chars) to `BaseLayout`; never hand-write
  `<title>`/`<meta>` in a page. Canonical, OpenGraph and the Organization/WebPage `@graph` are emitted by the
  layout (trailing-slash-normalised canonical — keep it that way).
- **Headings and images**: exactly one `<h1>` per page; meaningful `alt` (empty `alt=""` only for decoration).
- **Structured data**: add page nodes through the layout's `jsonLd` prop (Product/SoftwareApplication,
  FAQPage, BreadcrumbList). Prices in JSON-LD stay pinned to `warden.billing.pricing`
  (`test_pricing_coherence.py`). Never invent an address, rating, review or `sameAs` link (CLAUDE.md:
  Organization JSON-LD asserts only the country).
- **Copy**: every title and description is a public claim — it must fit `docs/capability-matrix.md` and avoid
  its `banned-claims` phrases; seller copy follows SP-06 (risk, never a verdict).
- **Sitemap**: `@astrojs/sitemap` in `site/astro.config.mjs` builds it; exclude pages with `noindex` and
  redirect stubs rather than writing a sitemap by hand. `robots.txt` already declares it.
- **IndexNow** (Bing, Yandex, Seznam…): `scripts/ping-indexnow.mjs`. Generate a key once
  (`node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"`), publish it as
  `site/public/<key>.txt` containing only the key, then ping after a deploy. Pinging is an outward action —
  ask the user before the first live run; use `--dry-run` otherwise.

### Step 3. Verify
1. Rebuild, re-run `node scripts/audit-seo.mjs`: no `missing`, warnings explained or fixed.
2. `pytest warden/tests/test_site_agent_readiness.py warden/tests/test_public_claims_reconciled.py warden/tests/test_pricing_coherence.py`.
3. `landing/` must match a fresh build: take it from the PR's Linux `site-dist` artifact (CLAUDE.md).
4. Report changed files and the manual steps: Google Search Console, Bing Webmaster Tools, Yandex Webmaster
   (submit `/sitemap-index.xml`).
