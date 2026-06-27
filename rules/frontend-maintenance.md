# Frontend Maintenance Rule — Shadow Warden AI

Applies to: `site/`, `dashboard/`, `portal/` and any file that touches UI, styles, navigation, or client-side JavaScript.

---

## 1. Color System — Never Override These

| Token | Value | Used for |
|-------|-------|---------|
| Background primary | `#050c19` / `oklch(0.11 0.025 250)` | Page body, canvas bg |
| Surface elevated | `#0d1220` / `oklch(0.16 0.02 250)` | Cards, modals |
| Border muted | `rgba(255,255,255,0.08)` | Card borders, dividers |
| Accent cyan | `#06b6d4` | Primary action, links, step indicators |
| Accent green | `#10b981` | Success, "done" states, cleared trades |
| Accent purple | `#8b5cf6` | Business Community category |
| Accent red | `#ef4444` | Cyber Security category |
| Text primary | `#f1f5f9` | Headings, key data |
| Text muted | `#64748b` | Secondary labels, status text |

**Rule:** When editing any Astro or CSS file, never introduce a new background color outside this palette without explicit approval. The cream/sand/warm-neutral family is permanently banned.

---

## 2. Chart.js — Mandatory Patterns

Chart.js is always loaded via CDN with `<script>` injection to avoid Astro SSR hydration crashes:

```typescript
// CORRECT — dynamic CDN inject (never import Chart.js as an npm package in Astro pages)
const _cjs = document.createElement('script');
_cjs.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.9/dist/chart.umd.min.js';
_cjs.onload = _buildCharts;
document.head.appendChild(_cjs);
```

**Destroy before re-render** — always call `.destroy()` on existing instances:

```typescript
if (_vChart) { _vChart.destroy(); _vChart = null; }
_vChart = new Chart(vc, { ... });
```

**SSE-driven updates** — use `chart.update('none')` for data-only refreshes (no animation), `.destroy()` + recreate only when the chart type or config changes.

**Canvas IDs** — never rename these; the E2E test suite and SSE handler depend on them:
- `chart-volume` — 7-day trade volume line chart
- `chart-fairness` — fairness radar chart
- `chart-tiers` — model cost doughnut chart

---

## 3. Agent Discovery Protocol — Never Remove

The `<link rel="agent-protocol">` tag in `site/src/layouts/BaseLayout.astro` is a hard requirement. It drives:
- SSE base-URL resolution in `_startSSE()` on `/agentic`
- SOVA Tool #31 `visual_diff` baseline URL detection
- Machine-to-machine agent capability discovery (IETF draft)

```html
<!-- BaseLayout.astro <head> — DO NOT REMOVE -->
<link rel="agent-protocol" href="/.well-known/agent.json" type="application/json">
```

---

## 4. Astro Architecture Rules

- **SSG only** — Shadow Warden's Astro site is static. Never add `output: 'server'` or SSR adapters.
- **`is:inline` for client logic** — inline `<script>` blocks run after hydration; never rely on module-scope side effects.
- **No Astro framework adapters** — do not add React, Vue, or Svelte islands to `site/`. The site uses vanilla TypeScript in `<script>` tags.
- **BaseLayout wraps every page** — every new `.astro` page in `site/src/pages/` must use `<BaseLayout>`.
- **Agent-protocol link** — always present in `<head>` via BaseLayout (see §3).

---

## 5. Navigation Invariants

The desktop nav in `BaseLayout.astro` uses CSS `:hover` groups (Tailwind `group` / `group-hover:`). These rules are inviolable:

- The three dropdown categories are **Business Community**, **Cyber Security**, and **Tunnel** — their `href` values, sub-item slugs, and colors must not change without updating the E2E test suite.
- Sub-items are derived from `site/src/data/roadmap.json` via `category` + `subcategory` fields. Never hardcode nav items directly.
- `id="navbar"` must remain on the `<header>` element — the E2E suite locates elements relative to it.

---

## 6. Community Wizard — DOM Contract

`/community/new` state machine uses these stable IDs. Never rename them:

| ID | Element | Step |
|----|---------|------|
| `panel-0` … `panel-5` | Step panels | all |
| `next-0` … `next-4`, `btn-create` | Forward buttons | all |
| `back-1` … `back-5` | Back buttons | 2–6 |
| `sc-0` … `sc-5` | Step circles | all |
| `f-name`, `f-desc`, `f-url` | Step 1 inputs | 1 |
| `rc-public`, `rc-private`, `rc-marketplace`, `rc-security`, `rc-research`, `rc-enterprise` | Visibility/type cards | 2 |
| `t-e2e`, `t-pqc`, `t-disappear`, `t-approval` | Security toggles | 3 |
| `f-maxmembers`, `f-role`, `t-charter`, `t-gdpr` | Governance | 4 |
| `t-market`, `t-sova`, `t-slack`, `tag-input`, `tags-wrap` | Integrations | 5 |
| `rv-name`, `rv-vis`, `rv-type`, `rv-enc`, `rv-pqc`, `rv-members`, `rv-market` | Review table | 6 |
| `pqc-badge` | Enterprise badge | 3 |
| `btn-create` | Launch button | 6 |

`btn-create` writes to `localStorage` (key `sw_communities`) and redirects to `/community/view?id=...&created=1`. There is no backend POST — do not add one without updating the E2E suite.

---

## 7. SSE Live-Metrics Contract

`GET /marketplace/analytics/stream` pushes JSON every 30s. The frontend (`/agentic`) consumes it via `EventSource`. These element IDs are SSE update targets — never rename them:

- `stat-communities`, `stat-assets`, `stat-trades`, `stat-auto`
- `gov-fairness`, `gov-alternatives`, `gov-trades`

---

## 8. Before Any Frontend PR

Run the health-check skill:

```
/site-health-check
```

This verifies the Astro build succeeds and all E2E tests pass. Do not merge a frontend PR if either fails.
