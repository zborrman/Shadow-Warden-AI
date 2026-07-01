# Project Progress — Shadow Warden AI

**Current version:** 7.0 | **Last updated:** 2026-06-28

## Autonomous Loop Log
<!-- Entries appended by .github/workflows/autonomous-security-loop.yml -->
2026-06-28T16:35:00Z — Loop blueprint installed. Nightly cron active (02:00 UTC). 32/32 Playwright tests green.
CHECKER_REJECTED: Ignoring 13 permissions.allow entries from .claude/settings.json: this workspace has not been trusted. Not logged in · Please run /login. Root cause: runner missing /home/runner/.claude.json trust config. Fix: workflow now pre-creates trusted claude.json before maker/checker steps.

## Shipped (complete)

### Core security pipeline
- 9-stage filter pipeline (topology → obfuscation → secrets → semantic → brain → causal → phish → ers → decision)
- TDA Gatekeeper: Betti numbers β₀/β₁ (<2ms)
- ObfuscationDecoder: base64/hex/ROT13/Caesar/homoglyphs depth-3
- SecretRedactor: 15 regex patterns + Shannon entropy
- HyperbolicBrain: MiniLM + Poincaré ball (70/30 cosine/hyperbolic blend)
- CausalArbiter: Bayesian DAG, Pearl do-calculus
- ERS: Redis sliding window, shadow ban (gaslight/delay/standard)

### Agentic infrastructure
- SOVA: Claude Opus 4.6 loop, 31 tools, 7 ARQ cron jobs
- MasterAgent: 4 sub-agents, HMAC task tokens, human-in-the-loop approval
- WardenHealer: OLS trend prediction, Haiku incident classification, SQLite recipe cache
- EvolutionEngine: ArXiv → synthesize_from_intel() → hot-reload corpus

### Business community (v4.x series)
- SEP: UECIID codec, peering, Causal Transfer Guard, Data Pods, STIX 2.1 audit chain
- Secrets Governance: 4 vault connectors, SQLite inventory, lifecycle, policy
- Obsidian Plugin: v4.19, TypeScript, 5 commands, sidebar, Dataview dashboard
- Shadow AI Discovery: 18 providers, subnet probe, DNS classifier, policy engine
- XAI: 9-stage causal chain, HTML/PDF reports, dashboard

### Marketplace (v5.x + v6.6)
- 4-stage M2M lifecycle: DID → pgvector search → Brand Agent → ClearingEngine
- 71+ tests: lifecycle, fairness guard, Confused Deputy, vector search, Layer 2 memory
- MAESTRO: GoalMisalignment + Collusion + ModelPoisoning detectors
- **Monetization (v6.6):** x402 nanopayments, 1.5% take rate, sponsored listings, ADP

### Compliance + analytics
- ISO 27001:2022: 93 controls, 4 themes
- Real-time compliance dashboard: 19 controls, Redis push, WebSocket
- Business Intelligence: 8 functions, 15-min TTL cache, OLS predictions
- Semantic Layer: 9 built-in models, deterministic SQL, Redis cache
- Document Intelligence: MarkItDown, SHA-256 cache, 50MB gate

### Infrastructure
- OTel distributed tracing: all 9 filter stages
- Post-Quantum Crypto: Ed25519+ML-DSA-65, X25519+ML-KEM-768 (liboqs fail-open)
- Sovereign routing: 8 jurisdictions, MASQUE tunnels, attestation
- Caddy v2 reverse proxy with QUIC/HTTP3
- GitHub Actions CI: matrix 3.11/3.12, lint, Docker smoke, mutation testing

## Current focus (v6.6+)

- Loop Engineering: `workflows/`, `memory/`, `rules/`, `hooks/` populated ← **this session**
- Project structure: `.claude/` cleaned up; `agents/`, `commands/`, `skills/` at root ← **this session**

## Next priorities (unstarted)

- Circle Gateway integration for x402 v2 (on-chain USDC settlement)
- `PLATFORM_WALLET_ADDRESS` settlement from `ClearingResult.platform_fee_usd`
- Marketplace billing UI: sponsored listing checkout in portal
- `rules/` on-demand loading wired into CLAUDE.md (keep root CLAUDE.md < 200 lines)
