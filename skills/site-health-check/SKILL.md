---
name: site-health-check
description: Runs the full Playwright E2E test suite, Astro build process, and checks for broken links, console errors, or hydration mismatches. Use this after any frontend modification.
---

# Site Health Check Skill

Trigger this skill with `/site-health-check` after any change to `site/`, `dashboard/`, or `portal/`, or after a backend change that could affect the frontend (nav data, SSE stream, marketplace APIs).

---

## Step 1 — Astro Build Verification

```bash
cd site && npm run build 2>&1
```

**Pass criteria:** Build completes with "X page(s) built" and no TypeScript errors.

**On failure:**
- Look for TypeScript errors in the output (e.g., `Type 'X' is not assignable to type 'Y'`).
- Look for missing imports or broken `src/data/*.json` references.
- Fix the root cause in the Astro page/component, do NOT suppress with `// @ts-ignore`.
- Re-run the build to confirm the fix.

After a successful build, copy the dist:

```bash
cp -r site/dist/* landing/
```

---

## Step 2 — Playwright E2E Suite

Install browsers if not already present (one-time per environment):

```bash
cd site && npx playwright install chromium --with-deps 2>&1 | tail -5
```

Run the full suite against production:

```bash
cd site && npx playwright test --reporter=list 2>&1
```

Run against local dev server (if testing an unreleased change):

```bash
# Terminal 1 (keep running): npm run dev
# Terminal 2:
cd site && PLAYWRIGHT_BASE_URL=http://localhost:4321 npx playwright test --reporter=list 2>&1
```

**Pass criteria:** All tests in `tests/e2e/marketplace.spec.ts` pass (0 failures).

**On test failure — diagnosis procedure:**

1. Read the terminal output to identify the failing test name and assertion.
2. Common failure patterns and fixes:

   | Failure | Root Cause | Fix |
   |---------|-----------|-----|
   | `#btn-create` not found | Wizard DOM ID renamed | Restore ID in `site/src/pages/community/new.astro` |
   | Dropdown not visible after hover | CSS `.group-hover:visible` broken | Check Tailwind config or BaseLayout `group` class |
   | `chart-fairness` canvas missing | Canvas ID changed | Restore canvas ID in `site/src/pages/agentic.astro` |
   | `agent-protocol` link missing | Removed from BaseLayout | Restore in `site/src/layouts/BaseLayout.astro` |
   | `/marketplace` not redirecting | 301 redirect removed | Re-add redirect in Caddy config or Astro routing |
   | `#rv-name` shows `—` | Review table not populated | Check `populateReview()` in community/new.astro |
   | Launch doesn't redirect | `btn-create` handler missing | Check `addEventListener` in community/new.astro |

3. Apply the fix following `workflows/bug-fix.md` conventions.
4. Re-run only the failing test to confirm: `npx playwright test --grep "failing test name"`.
5. Run the full suite again to confirm no regressions.

---

## Step 3 — Console Error Check

After the Playwright run, check for browser console errors logged during tests:

```bash
cd site && npx playwright test --reporter=html 2>&1
# Then open: site/playwright-report/index.html
```

Look for:
- JavaScript errors in the console (red entries in trace viewer)
- Failed network requests to `/marketplace/analytics/stream` or `/marketplace/analytics/fairness`
- `Chart is not defined` (CDN failed to load)
- Hydration errors (`Uncaught Error: Hydration failed`)

**Hydration errors** only occur if someone added an Astro island (React/Vue/Svelte) without `client:*` directive, or if Chart.js was imported as an npm module instead of CDN. Fix: revert to CDN injection pattern (see `rules/frontend-maintenance.md §2`).

---

## Step 4 — SSE Stream Health

After any change to `warden/marketplace/api.py` or `analytics.py`, verify the SSE stream is healthy:

```bash
curl -N --max-time 10 https://api.shadow-warden-ai.com/marketplace/analytics/stream 2>&1 | head -5
```

**Expected output** (within 2s):
```
id: 0
data: {"ts":..., "communities":..., "assets":..., "trades":...}
```

If no data arrives within 5s: check `warden` container logs:

```bash
ssh root@91.98.234.160 "docker logs shadow-warden-warden-1 --tail 30 2>&1"
```

---

## Step 5 — Deploy (if all checks pass)

```bash
# Commit the build output
git add landing/
git commit -m "chore(landing): sync Astro dist [skip ci]"
GIT_TERMINAL_PROMPT=0 git push origin main

# Deploy to server
ssh root@91.98.234.160 "cd /opt/shadow-warden && git pull origin main && docker compose restart proxy"
```

---

## Quick Reference — Key Test IDs

These DOM IDs are locked by `rules/frontend-maintenance.md`. If a test fails because an ID is missing, the frontend broke the contract — fix the page, not the test.

```
Wizard: #panel-0…5, #next-0…4, #btn-create, #back-1…5
        #f-name, #rc-public, #rc-marketplace, #t-e2e, #t-pqc
        #f-maxmembers, #t-sova, #tag-input, #rv-name
Charts: canvas#chart-volume, canvas#chart-fairness, canvas#chart-tiers
Stats:  #stat-communities, #stat-assets, #stat-trades, #stat-auto
Nav:    #navbar, #mobile-btn, #mobile-menu, #nav-signin
ADP:    link[rel="agent-protocol"]
```
