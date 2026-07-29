---
name: site-health-check
description: Full frontend health audit — Playwright smoke tests, WebMCP attribute validation, Lighthouse Agentic Browsing audit, llms.txt presence, and agent.json reachability.
---

# Site Health Check

Runs a structured audit of the Shadow Warden AI frontend for both human and AI-agent readiness.

## When to use

- Before any production deploy
- After frontend changes in `site/` or `dashboard/`
- As the Heartbeat step in `workflows/autonomous-security-loop.md`
- On demand: `/site-health-check`

## Steps

### 1. Playwright Smoke Tests (32 assertions)

```bash
cd site && npm run build && npx playwright test --reporter=list
```

All 32 assertions must pass. Any failure blocks deploy.

### 2. Agent Discovery Endpoints

```bash
# ADP manifest reachable
curl -sf http://localhost:4321/.well-known/agent.json | python -m json.tool | head -5

# llms.txt reachable and well-formed (must start with "# ")
curl -sf http://localhost:4321/llms.txt | head -3
```

Both must return 200. `llms.txt` must begin with `# Shadow Warden AI`.

### 3. WebMCP Attribute Validation

Check that the community creation wizard exposes WebMCP attributes:

```bash
curl -sf http://localhost:4321/community/new | grep -c 'toolname\|toolparamdescription'
```

Expected: ≥ 10 matches (toolname on form + toolparamdescription on each annotated input).

If `chrome-devtools-mcp` is available, prefer:

```
lighthouse_audit("http://localhost:4321/community/new", categories=["accessibility"])
get_accessibility_tree("http://localhost:4321/community/new")
```

Check that `<form toolname="createCommunity">` is present in the accessibility tree.

### 4. Lighthouse Agentic Browsing Audit

Requires `chrome-devtools-mcp` in `.mcp.json` (already configured) or Lighthouse CLI:

```bash
# Via CLI (Lighthouse 13.3+)
npx lighthouse http://localhost:4321 \
  --only-categories=accessibility,best-practices \
  --output=json \
  --output-path=/tmp/lh-report.json \
  --chrome-flags="--headless" \
  --quiet

# Parse Agentic Browsing pass-ratio
python -c "
import json, sys
r = json.load(open('/tmp/lh-report.json'))
ab = r.get('categories', {}).get('agentic-browsing', {})
score = ab.get('score', None)
print(f'Agentic Browsing: {score}')
sys.exit(0 if score is None or score >= 0.6 else 1)
"
```

**Pass threshold:** score ≥ 0.6 (or category absent in Lighthouse < 13.3 — skip gracefully).

What Lighthouse Agentic Browsing checks:
- Accessibility tree completeness (ARIA labels, roles)
- Layout Stability (CLS ≤ 0.1)
- `llms.txt` presence at root
- `<link rel="agent-protocol">` in `<head>`
- WebMCP `toolname` / `toolparamdescription` attributes on forms

### 5. Protected Invariants Check

The following must never be broken. Grep for them before reporting pass:

```bash
# <link rel="agent-protocol"> still present
grep -c 'rel="agent-protocol"' site/src/layouts/BaseLayout.astro

# toolname="createCommunity" still on the community form
grep -c 'toolname="createCommunity"' site/src/pages/community/new.astro

# llms.txt exists
test -f site/public/llms.txt && echo "llms.txt: OK"
```

All three must pass (count ≥ 1 for grep checks).

## Reporting

Output a summary table:

| Check | Status | Notes |
|-------|--------|-------|
| Playwright (32) | PASS / FAIL | # failed |
| ADP /.well-known/agent.json | PASS / FAIL | HTTP status |
| llms.txt | PASS / FAIL | First line |
| WebMCP attributes | PASS / FAIL | Match count |
| Lighthouse Agentic | PASS / SKIP / FAIL | Score |
| Protected invariants | PASS / FAIL | Which failed |

If any check FAILS, open a GitHub PR with the fix before deploying. Never deploy with a FAIL on Playwright, ADP, or Protected invariants.

## Integration with Autonomous Security Loop

The `Heartbeat` step in `workflows/autonomous-security-loop.md` runs:
1. Playwright 32 tests
2. `ruff check` + `mypy`

After those pass, this skill adds the Agentic Web checks (steps 2–5 above) as a post-heartbeat gate. If the Agentic Web gate fails, the loop treats it as DEGRADED (not UNHEALTHY) — it logs the failure and continues without blocking the security audit.
