---
description: Make the Shadow Warden site readable and citable by AI search (llms.txt, AI-bot policy, no-JS content, entity grounding, FAQ)
argument-hint: [production origin, default https://www.shadow-warden-ai.com]
---

Implement AI-search readiness (ChatGPT Search, Perplexity, Claude, Google AI Overviews) for
`${ARGUMENTS:-https://www.shadow-warden-ai.com}`. Answer in the user's language; repo content is English.

The site already has much of this — `site/public/llms.txt`, markdown twins served on `Accept: text/markdown`
(`edge/negotiate.mjs`), `/.well-known/*`, JSON-LD on both layouts. Extend it; do not rebuild it.

### Step 1. Measure
`cd site && npm run build`, then `node scripts/audit-ai-search.mjs`. Most AI crawlers do not run
JavaScript; `noJsContent` measures the text inside `<main>` of the built HTML.

### Step 2. robots.txt — name the bots, separate search from training
Edit `site/public/robots.txt` (keep the existing `Disallow`s, the `Sitemap:` line and the agent-discovery lines):
- Search / answer bots get an explicit `Allow: /`: `OAI-SearchBot`, `ChatGPT-User`, `PerplexityBot`,
  `Claude-SearchBot`, `Claude-User`, `Applebot`.
- Training bots (`GPTBot`, `ClaudeBot`, `Google-Extended`, `CCBot`, `Applebot-Extended`): state a policy
  explicitly. Default `Allow: /` unless the user decides otherwise — that is the owner's call, ask.

### Step 3. llms.txt and llms-full.txt (llmstxt.org)
- `llms.txt` keeps its shape: `# Title`, `> summary`, `## sections` with absolute links. Add new product pages
  as they ship; remove retired ones.
- `llms-full.txt`: generate it by concatenating the markdown twins in `site/public/*.md` (already reviewed
  under the Claims Rule) in product order — never write new claims for it. Add a test that it stays in step
  with the twins, like `test_site_agent_readiness.py` does for the routes.

### Step 4. Barriers and grounding
1. **No-JS content**: a page in `thinWithoutJs` must render its text statically (Astro does by default; a
   client-only island holding the copy is the usual cause).
2. **Entity grounding**: `sameAs` lists only profiles that exist and are ours — currently the GitHub repo.
   Never add placeholder URLs; published identity data is what a compliance review checks.
3. **Citable answers**: where a page has a real FAQ (e.g. `/sellers`), emit `FAQPage` JSON-LD through the
   layout's `jsonLd` prop from the same data the page renders, so the two cannot disagree. Facts in answers
   must fit the capability matrix; thresholds carry their date (SP-07).

### Step 5. Verify
Rebuild, re-run `node scripts/audit-ai-search.mjs`, run the site readiness and claims tests, rebuild
`landing/` from the PR's Linux artifact, and list changed files plus any owner decision left open
(training-bot policy, new `sameAs` profiles).
