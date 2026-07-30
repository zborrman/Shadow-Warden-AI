# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

The React Native app at `mobile/` (`ShadowWardenSOC` — RN 0.73, push notifications via Firebase Messaging, `@react-navigation` stack) is an existing companion alert client, not a surface this design system governs. It must not be restyled without a separate brief. `[inferred]`

## Users

Security engineers, CISOs, compliance officers, and developers building AI-powered pipelines who need a hardened perimeter between their systems and adversarial LLM inputs. They operate under regulatory scrutiny (GDPR, SOC 2, ISO 27001) and have zero tolerance for data leaks. They evaluate tools skeptically — trust is earned through technical specificity, not marketing promises. They use Shadow Warden at the infrastructure layer, so the interface is read under stress: reviewing alerts, auditing decisions, onboarding a new service.

## Product Purpose

Shadow Warden AI is a self-contained AI security gateway that intercepts every AI request before it reaches a model. It blocks jailbreak attempts, strips secrets and PII, and self-improves via Claude Opus — all without sending sensitive data to third parties. Success means a security team that deploys in 60 seconds, never sees a compliance gap, and trusts the system enough to stop thinking about it.

## Positioning

The gateway runs entirely inside the customer's own infrastructure. Detection is a nine-layer pipeline that executes locally — topological analysis of an n-gram point cloud (β₀/β₁ Betti numbers), recursive obfuscation decoding, entropy-based secret redaction, a rule engine, a MiniLM embedding guard blended into hyperbolic space, and a Bayesian causal arbiter for the gray zone — so no prompt, secret, or PII is shipped to a third-party scoring API to reach a verdict. Competitors that call a hosted classifier cannot truthfully make that claim; it is the one thing a neighboring product cannot copy without rebuilding its architecture.

The second differentiator is that the system improves itself: HIGH/BLOCK verdicts feed an Evolution Engine that generates new detection rules, and an intel bridge synthesizes attack examples from newly published ArXiv papers into the live corpus. The product also runs its own security loop against itself nightly — the audit posture it sells is the audit posture it operates under.

## Operating Context

- **Deployment surface:** Docker Compose, eleven services, self-hosted. The evaluation moment is a `docker compose up`, not a signup flow.
- **Integration surface:** a single `POST /filter` call, an OpenAI-compatible `/v1/chat/completions` drop-in proxy, a LangChain callback, an MCP config, a browser extension, and language SDKs. Adoption means a one-line change in someone else's request path.
- **Reading environment:** dark rooms and dark screens — SOC walls, terminal sessions, Grafana next to Jaeger, incident response at 02:00. Interfaces are read under time pressure with an audit trail as the output.
- **Governed web surfaces:** the Astro marketing site (`site/`, 54 pages), the Next.js customer portal (`portal/`), the Next.js SOC dashboard (`dashboard/`, port 3002), and the Streamlit analytics dashboards (`warden/analytics/pages/`, port 8501). The shared design system lives in `packages/ui/` (DS-01, 10 components + ThemeProvider). `[inferred from repo]`
- **Buying context:** procurement under audit. Documentation, evidence artifacts, and compliance mapping are part of the sale, not post-sale collateral.

## Capabilities and Constraints

- Nine-stage synchronous filter pipeline with a sub-50ms P99 budget; latency is a product feature and design must never obscure it.
- Autonomous agent layer: SOVA (single operator, ~30 tools), MasterAgent (four specialized sub-agents, HMAC-bound task tokens, human-in-the-loop approval gate), and a Digital Staff subsystem. Every agentic tool call passes one gate; every high-impact action can require human approval.
- Compliance and governance modules are first-class product surfaces, not settings: continuous compliance scoring, ISO 27001 (93 controls), GDPR Art. 30 records, an STIX 2.1 tamper-evident audit chain, secrets governance, vendor/DPA registers, and an Evidence Vault.
- **Content is never logged.** Only metadata — type, length, timing. This is a hard GDPR requirement and constrains every analytics, debugging, and dashboard design: a UI that displays the offending prompt is a product violation, not a feature request.
- **English only, on every surface.** All UI strings, page copy, labels, and comments across site, dashboard, and portal.
- Optional third-party dependencies (Anthropic key, liboqs for post-quantum crypto, Redis, ClickHouse) all fail open or degrade — the product must remain honest in air-gapped mode, so no design may imply an internet connection is required to protect a request.
- Tiering is a real product constraint: features are gated by tier and by purchased add-ons, and the UI distinguishes "your plan is too low" (403) from "eligible but not purchased" (402).

## Brand Commitments

- **Name:** Shadow Warden AI. **Logo:** `site/public/logo.png` (castle mark) — used across all site pages, `og:image`, and favicon. Both are fixed. `[inferred — treat as locked until told otherwise]`
- **Personality:** Vigilant · Precise · Uncompromising. The tone is that of a serious tool built by people who understand the threat model. It does not try to be friendly. It is not anxious or aggressive. It is confident in its specificity: it names exact algorithms, exact latency numbers, exact compliance controls. Every word earns its place. The brand is what the product is — a system that watches, judges, and acts without hesitation.
- **License:** proprietary. Never present the product as open source.

### Anti-references

- **Notion-white / friendly SaaS:** warm backgrounds, rounded everything, pastel accents, reassuring copy, soft gradients. Shadow Warden is infrastructure, not a productivity app.
- **Consumer startup warmth:** playful illustration, casual voice, "Hey there!" onboarding. This product is deployed in enterprise environments under audit.
- **Cyberpunk / red-alert hacker aesthetic:** neon green terminals, aggressive red palettes, matrix-rain backgrounds, gothic type. Security does not mean theatrical danger.
- **Generic enterprise blue:** the IBM/Salesforce navy-and-white SaaS template. Interchangeable with any other vendor, zero identity.

## Evidence on Hand

**Real and citable:**

- Compliance artifacts in `docs/`: `dpia.md` (GDPR Art. 35 DPIA), `soc2-evidence.md` (control mapping + auditor collection procedures), `security-model.md` (9-layer model, OWASP LLM Top 10 coverage, threat model), `sla.md` (Pro 99.9% / Enterprise 99.95%, P99 < 50ms, credits), and a 93-control ISO 27001:2022 mapping shipped as live product surface.
- Measured operational figures: sub-2ms topological gate, P99 < 50ms filter budget, a verified restore drill at ~17s RTO (21 Postgres tables + 7 SQLite DBs), ~4300 tests, 75% coverage gate.
- Published pricing, exact: Starter $0 (1k req), Individual $5/mo (5k), Community Business $19/mo (10k), Pro $69/mo (50k, MasterAgent included), Enterprise $249/mo (unlimited, PQC + Sovereign). Add-ons: `shadow_ai_discovery` +$15/mo (Pro+), `xai_audit` +$9/mo (Individual+), `smb_governance_suite` $29/mo. Quote these exactly or not at all.
- A live production deployment behind Cloudflare at `api.shadow-warden-ai.com`.

**Absent — must never be fabricated:** `[inferred: no customer logos, quotes, case studies, press, funding, team-size, or user-count claims appear anywhere in the repo]`

- No named customers, logos, testimonials, quotes, case studies, or press mentions exist. Do not invent them, do not use placeholder logo rows that read as real customers, and do not write "trusted by teams at…" copy.
- No third-party audit certification has been issued. The product ships SOC 2 and ISO 27001 *evidence and control mappings* — it is not certified. Design must never imply a completed audit.
- No independent benchmark against competitors exists. Comparison tables may state Shadow Warden's own measured numbers only.

## Product Principles

1. **Practice what you preach.** The product claims to be precise and uncompromising; the interface is the first proof. No decoration without purpose, no claim without evidence, no feature without a measurable outcome.
2. **Signal over spectacle.** Information density beats visual drama for this audience. A well-composed table of detection stats persuades a CISO more than any animation.
3. **Expert confidence.** Address users as peers who already understand TLS fingerprinting and Betti numbers. Never explain what a CISO knows. Earn trust through specificity, never through reassurance.
4. **The audit trail is the product.** Every verdict must be explainable, attributable, and exportable. A design that shows a decision without its cause has removed the reason someone bought this.
5. **Honest degradation.** Optional dependencies fail open by design, so the UI must always tell the truth about which protections are actually running — a degraded system that looks healthy is the worst outcome this product can produce.

## Accessibility & Inclusion

WCAG AA as the floor. Body text must achieve ≥4.5:1 against its background at all sizes. All interactive elements require visible focus indicators. Animations must respect `prefers-reduced-motion`. The dark theme must never trade contrast for elegance — muted gray on near-black fails both users and auditors.

---

## Design Principles (legacy — pending migration to DESIGN.md)

Visual commitments recorded before this project had a DESIGN.md. They are design decisions, not product truth; `/impeccable document` should move them into DESIGN.md and this section should then be deleted.

- **Dark is the environment.** The dark theme is not an aesthetic choice — it matches the operational context: SOC screens, terminal sessions, late-night incident response. Every color decision must hold at ambient dark conditions.
- **Earned color.** The indigo-violet-cyan palette is reserved for signal: active states, critical values, primary actions. Overusing it dilutes its meaning. When everything glows, nothing alerts.
