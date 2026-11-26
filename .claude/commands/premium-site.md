---
description: Blueprint a premium page or site section for Shadow Warden — design system, GEO/agent readiness, claims-safe copy
argument-hint: <page or section, audience, the one action it should lead to>
---

Design the architecture and design spec for: `$ARGUMENTS`.

This is not a greenfield site. Shadow Warden already has a design system, a shell, a claims policy and an
agent-readiness layer; the blueprint extends them and never replaces them unless the user asks for a
redesign. Answer in the language the user writes in; anything written into the repo is English.

### Ground rules (binding)
1. **Product and claims** — the only product is seller protection for Amazon sellers (`CLAUDE.md`,
   `docs/seller-protection-programme.md`). Every claim must fit its row in `docs/capability-matrix.md`;
   phrases in its `banned-claims` block never appear. SP-06: risk, never a verdict — no promise to prevent a
   suspension or win a reinstatement. No customer, revenue or usage numbers (there are none). Performance
   targets below are build goals, never published figures.
2. **Design system first** — tokens in `site/src/styles/global.css` (light default, `html.dark` opt-in;
   the portal mirrors them in `portal/src/styles/tokens.css`), shell in `site/src/styles/shell.css`.
   Load the `impeccable` and `shadow-warden-design` skills before visual decisions, and `dataviz` before any
   chart or stat tile.
3. **Anti-slop** — no default purple-blue gradients, decorative bento grids, identical icons in circles,
   stock 3D art, or vague headlines ("Revolutionize your business"). Required: one display + one text face
   with `clamp()` sizes; a real grid; a colour budget (neutrals ~80%, structure ~15%, one accent ~5%);
   status colours only beside a written label; motion only with `prefers-reduced-motion` respected.
4. **GEO and agents** — static or server-rendered content; every new route gets its `site/public/*.md`
   twin, a `MARKDOWN_ROUTES` entry, the page's `markdown=` prop and the apex matcher
   (`warden/tests/test_site_agent_readiness.py` checks all four); JSON-LD through the layout's `jsonLd`
   prop; semantic landmarks; quotable fact blocks (tables, dated thresholds with sources — SP-07).
5. **Quality bar** — WCAG 2.2 AA (contrast >= 4.5:1, visible focus, keyboard paths); goals LCP < 1.5 s,
   INP < 100 ms, CLS < 0.05, checked with the CI Lighthouse/axe jobs where they exist.

### Deliverable — five sections
1. **Stack and rendering** — which surface (`site/` Astro, `portal/` Next, `dashboard/` Next) and why;
   static vs ISR vs client; no new frontend, router or subsystem (Feature Freeze).
2. **Information architecture and GEO layer** — routes, markdown twins, JSON-LD nodes, what an LLM should
   be able to quote from the page.
3. **Design spec** — the existing tokens it uses, any new token (with contrast checked in both themes),
   type scale, grid and spacing, motion budget (what moves, duration, easing).
4. **Wireframe spec** — block by block (hero, proof, product, how it works, CTA) with the content each block
   needs and the capability-matrix row each claim rests on.
5. **Implementation plan** — files to add or change, tests to add (agent readiness, claims, a11y), and the
   order of PRs.
