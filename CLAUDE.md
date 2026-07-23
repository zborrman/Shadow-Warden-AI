# CLAUDE.md — Shadow Warden AI

## Response Style
- **Keep responses under 100 words.** Code and tool calls don't count — only prose.
- No summaries after completing tasks. No filler phrases.

## Language Rule
- **All project content is English-only.** Every page, UI string, comment, label, and copy on the site (`site/`), dashboard (`dashboard/`), and portal (`portal/`) must be written in English. Never write Russian, Hebrew, or any other language in project files.

## Deploy Rule
- **After each modernization-plan Phase passes its tests, merge to `main` and push.** CI autodeploy (`DEPLOY_SSH_KEY/HOST/USER/PATH`) pulls `main` and runs `docker compose up` on the Hetzner VPS — do not skip the merge/push step or the server stays stale. Do not batch multiple phases into one merge.

## Modernization Governance (canonical: `docs/unified-modernization-roadmap.md`)
Two modernization tracks run in parallel; that registry is the single source of truth for status, ownership, and shared-file conflicts. Rules:
- **Two tracks, prefixed IDs — never a bare "Phase N" in commits/PRs:**
  - **Track A — Security Remediation (`SR-*`)**, source `MODERNIZATION_PLAN.md`. Owns: authn/authz, SSRF, IDOR/GDPR, request-path invariants, CI/supply-chain hardening.
  - **Track B — Deep-Eng / Math (`DE-*`)**, source `docs/modernization-plan-v8.md`. Owns: ML/detection math (TDA, MAESTRO, Causal, embeddings), GSAM, **storage/data-layer**, runtime-isolation math.
- **Shared files (coordinate before editing; run the other track's tests):** `causal_arbiter.py`, the data layer, `staff_dispatch`/`BoundaryRegistry`, `net_guard`/Inner-Warden SSRF, key-hygiene (`resolve_key`/JIT lease). See the roadmap's conflict table for the per-file rule.
- **C2 data-layer is one workstream, led by Track B** (SR-5 folds into DE-6). Track A does not open a separate DB-consolidation effort; it contributes the "one context-manager, DDL-once" requirement to Track B's PRs.

## Autonomous Security Loop (Loop Engineering)

The project runs a nightly autonomous audit cycle at 02:00 UTC via `.github/workflows/autonomous-security-loop.yml`.

**Blueprint:** `workflows/autonomous-security-loop.md`  
**Memory log:** `memory/progress.md`

Sequence: Heartbeat (Playwright 32 tests + ruff + mypy) → if unhealthy: git worktree isolation → Maker sub-agent drafts fix → Checker sub-agent audits → verification (ruff + mypy + Playwright + pytest) → PR auto-opened.

**Manual trigger:**
```bash
claude --print "$(cat workflows/autonomous-security-loop.md)"
```

**Protected invariants the loop never touches:** `<link rel="agent-protocol">`, clearing.py Decimal math, x402 fail-open, all 32 Playwright assertions, GDPR content-never-logged rule.

## Digital Staff Invariants (STAFF-01…STAFF-05)

These rules apply to all `warden/staff/` code. The autonomous loop and Claude Code must never violate them:

- **Boundary check first:** `staff_dispatch()` must call `BoundaryRegistry.check_and_dispatch()` before every tool execution — no exceptions, no bypasses.
- **Velocity guard always runs:** `VelocityGuard.record_and_check()` is called in `staff_dispatch()` after every boundary check. Never remove this call.
- **Refund intent pattern (Rec-3):** `issue_refund()` must call `sign_refund_intent()` and store the HMAC-signed intent. Payment credentials must never be passed to an agent.
- **Injection pre-screen (Rec-1):** `generate_seo_content()`, `score_kyc_profile()`, `screen_sanctions_list()`, and `generate_sar()` must pre-screen freetext via `POST /filter` (fail-open on timeout).
- **Draft-only pattern:** BDR emails, growth proposals, SAR documents, and refund intents are created with `status=PENDING_REVIEW` or `PENDING_HUMAN_APPROVAL`. Agents never approve their own outputs.
- **No LLM in support KB:** `resolve_ticket_kb()` uses the static `_KB` dict — never calls an LLM directly. Agentic reasoning lives in `StaffAgentRunner`, not in individual tool handlers.
- **AgentRole StrEnum:** `warden/staff/boundaries.py` uses `AgentRole(StrEnum)` — never revert to `str, Enum`.
- **BoundaryViolationError naming:** Exception class is `BoundaryViolationError` (N818 compliant) — never `BoundaryViolation`.
- **Staff agent model routing:** L1=Haiku, L2=Sonnet, L3=Opus (≤8 iterations). Never hardcode model strings outside `_MODEL_BY_LEVEL`.

## AI-Driven CI/CD Stack

The project uses Claude Code as autonomous engineer across this stack:

| Layer | Tool | Role |
|-------|------|------|
| Local dev | Docker Desktop Pro | Isolated env: Postgres, Redis, warden:8001 |
| AI engineer | Claude Code CLI | Code → test → commit → PR cycle |
| Version control | GitHub Actions | CI: ruff + mypy + pytest + Playwright |
| Security gate | `.github/workflows/claude-security-review.yml` | Claude Opus reviews PRs touching security-critical files |
| Warden scan | `.github/workflows/warden-scan.yml` | Shadow Warden 9-layer filter on every commit diff |
| Frontend deploy | Vercel | Preview URLs per PR; production on main merge |
| Shield | Cloudflare WAF | Rate-limits `/staff/agents/*`, `/filter`, `/agent/*` |
| MCP | `.mcp.json` | Claude Code ↔ SQLite/Postgres/OTel/EVM direct access |

**Security review trigger:** PRs touching `topology_guard.py`, `causal_arbiter.py`, `shadow_ban.py`, `masking/engine.py`, `staff/boundaries.py`, or any `warden/crypto/` file automatically receive a Claude Opus 4.8 audit comment via `.github/workflows/claude-security-review.yml`.

**Non-interactive usage pattern:**
```bash
# Audit a specific file from CLI
claude --print "Review warden/staff/boundaries.py for HMAC usage and fail-open compliance" \
  --model claude-opus-4-8

# Run autonomous loop manually
claude --print "$(cat workflows/autonomous-security-loop.md)"
```

---

## Project Overview

Shadow Warden AI is a self-contained, GDPR-compliant AI security gateway. It sits in front of every AI request, blocking jailbreak attempts, stripping secrets/PII, and self-improving via Claude Opus — all without sending sensitive data to third parties.

**Version:** 7.7 · **License:** Proprietary · **Language:** Python 3.11+ · **Updated:** 2026-07-22

## Architecture

```
POST /filter → TopologicalGatekeeper (n-gram point cloud → β₀/β₁ Betti numbers, < 2ms)
                → ObfuscationDecoder (base64/hex/ROT13/Caesar/word-split/UUencode/homoglyphs, depth-3 recursive)
                → SecretRedactor (15 regex patterns + Shannon entropy scan for unknown secrets)
                → SemanticGuard (rules, compound risk escalation)
                → HyperbolicBrain (MiniLM → Poincaré ball, 70% cosine + 30% hyperbolic blend)
                → CausalArbiter (gray-zone: Bayesian DAG P(HIGH_RISK|evidence) via do-calculus)
                → ERS (Redis sliding window, shadow ban at score ≥ 0.75)
                → Decision
                    ↓
    EvolutionEngine (background, Claude Opus) ← HIGH/BLOCK
                ↓ add_examples() hot-reload
    _brain_guard corpus
                ↓
    event_logger → data/logs.json → Streamlit dashboard (:8501)
                ↓ background S3 ship (fail-open)
    MinIO on-prem object store (S3_ENABLED=true)
        warden-evidence/bundles/<session_id>.json   ← Evidence Vault
        warden-logs/logs/<date>/<request_id>.json   ← analytics

Agent pipeline:
    AgentMonitor.record_tool_event() → _check_injection_chain() (+ 6 other patterns)
    MaskingEngine.mask/unmask()      → Fernet-encrypted vault (HMAC-SHA256 reverse map)
    openai_proxy._stream_gen()       → 400-char fast-scan → live-emit (progressive streaming)

SOVA Agent (autonomous operator):
    POST /agent/sova            → run_query() → Claude Opus 4.6 agentic loop (≤10 iter)
    DELETE /agent/sova/{sid}    → clear_history()
    POST /agent/sova/task/{job} → trigger scheduled job manually (incl. visual-patrol)
    ARQ cron:
        sova_morning_brief  08:00 UTC daily
        sova_threat_sync    every 6h (00:05, 06:05, 12:05, 18:05)
        sova_rotation_check 02:00 UTC daily
        sova_sla_report     Monday 09:00 UTC
        sova_upgrade_scan   Sunday 10:00 UTC
        sova_corpus_watchdog every 30 min (delegates to WardenHealer — no LLM)
        sova_visual_patrol  03:00 UTC daily (ScreencastRecorder + Claude Vision → MinIO, smart priority weights)
    Memory: Redis sova:conv:{session_id} JSON (6h TTL, 20-turn cap)
    Tools: 30 tool handlers → http://localhost:8001 X-API-Key calls
        #28: visual_assert_page — BrowserSandbox + Claude Vision (in-process)
        #29: scan_shadow_ai     — Shadow AI Discovery (ShadowAIDetector, 18 providers, subnet probe + DNS)
        #30: explain_decision   — Causal chain retrieval from logs + XAI rationale
        #31: visual_diff        — Claude Vision baseline vs candidate screenshot comparison
    Healer: WardenHealer — autonomous anomaly detection (CB, bypass spike, corpus DEGRADED, canary probe, OLS trend prediction, Haiku incident classification, SQLite recipe cache)

MasterAgent (multi-agent SOC coordinator — v4.0):
    POST /agent/master               → run_master() → decompose → parallel sub-agents → synthesis
    POST /agent/approve/{token}      → approve or reject pending high-impact action
    GET  /agent/approve/{token}      → check approval status
    Sub-agents (each has specialized tool subset + system prompt):
        SOVAOperator   — health, stats, billing, config, key rotation
        ThreatHunter   — CVE triage, ArXiv intel, adversarial analysis
        ForensicsAgent — agent activity, GDPR Art.30, Evidence Vault, visual patrol
        ComplianceAgent— SLA monitors, SOC 2 controls, ROI proposals
    Task tokens: HMAC-SHA256 binding (sub_agent, task_hash, issued_at) — cross-agent injection prevention
    Human-in-the-Loop: REQUIRES_APPROVAL actions → Slack webhook → Redis pending (1h TTL) → /agent/approve/{token}
```

11 Docker services: `proxy` (80/443), `warden` (8001), `app` (8000), `analytics` (8002), `dashboard` (8501), `postgres`, `redis`, `prometheus`, `grafana` (3000), `minio` (9000/9001), `minio-init`.

## Two Distinct Guard Classes (critical distinction)

| Class | Module | Method | Purpose |
|-------|--------|--------|---------|
| `SemanticGuard` | `warden.semantic_guard` | `analyse()` | Regex rule engine + compound risk escalation |
| `SemanticGuard` (alias `BrainSemanticGuard`) | `warden.brain.semantic` | `check()` / `check_async()` | MiniLM ML cosine similarity |

Both run in the `/filter` pipeline (Stage 2 + Stage 2b). The Evolution Engine must receive `_brain_guard` (not `_guard`) because only the ML guard has `add_examples()`.

## Key Files

| File | Role |
|------|------|
| `warden/main.py` | FastAPI gateway — auth, rate-limit, cache, multi-tenant, Prometheus, GDPR, alerting, batch |
| `warden/topology_guard.py` | TDA Gatekeeper — n-gram point cloud, Betti numbers (β₀/β₁), ripser optional |
| `warden/brain/hyperbolic.py` | Poincaré ball projection + vectorized hyperbolic distance (pure numpy) |
| `warden/causal_arbiter.py` | Bayesian DAG causal inference — 5 nodes, Pearl do-calculus, backdoor correction |
| `warden/brain/semantic.py` | ML jailbreak detector — MiniLM + hyperbolic blend, adversarial suffix stripping |
| `warden/brain/evolve.py` | Claude Opus auto-rule generation + `synthesize_from_intel()` (ArXiv paper → attack examples) |
| `warden/obfuscation.py` | Obfuscation decoder pre-filter (base64, hex, ROT13, unicode homoglyphs) |
| `warden/secret_redactor.py` | 15 PII/secret regex patterns + Shannon entropy scan for unknown secrets |
| `warden/semantic_guard.py` | Rule-based semantic analyser, compound risk escalation (3+ MEDIUM → HIGH) |
| `warden/schemas.py` | Pydantic models (`FilterRequest` with `tenant_id`, `FilterResponse` with `processing_ms`) |
| `warden/cache.py` | Redis SHA-256 content hash cache (5-min TTL, fail-open) |
| `warden/auth_guard.py` | Per-tenant API keys (JSON multi-key + SHA-256 hash lookup), constant-time compare |
| `warden/openai_proxy.py` | OpenAI-compatible `/v1/chat/completions` proxy — progressive streaming (400-char fast-scan buffer → live-emit) |
| `warden/agent_monitor.py` | Session-level threat patterns incl. INJECTION_CHAIN — cryptographic attestation chain |
| `warden/masking/engine.py` | PII masking engine — Fernet-encrypted vault, HMAC-SHA256 reverse map, no plaintext in memory |
| `warden/alerting.py` | Slack + PagerDuty real-time alerts on HIGH/BLOCK |
| `warden/analytics/logger.py` | NDJSON logger + GDPR helpers (`purge_before`, `read_by_request_id`) |
| `warden/analytics/dashboard.py` | Streamlit security dashboard (reads logs.json directly) |
| `warden/analytics/pages/2_Settings.py` | Streamlit Settings page — Threat Radar tab + Intel Bridge tab + Causal Arbiter interactive visualizer |
| `warden/intel_ops.py` | Threat Radar — OSV API dependency CVE scanner + ArXiv LLM-attack paper hunter; saves `data/intel_report.json` |
| `warden/intel_bridge.py` | Auto-Evolution Bridge — ArXiv papers → `synthesize_from_intel()` → `SemanticGuard.add_examples()` hot-reload |
| `warden/analytics/siem.py` | Splunk HEC + Elastic ECS SIEM integration |
| `warden/integrations/langchain_callback.py` | LangChain duck-typed callback (`WardenCallback`) |
| `warden/tools/browser.py` | Playwright headless Chromium sandbox (`Context7Manager`) |
| `warden/Dockerfile` | Playwright MCR base + CPU-only torch (non-root user UID/GID 10001) |
| `warden/storage/s3.py` | S3-compatible object storage backend — MinIO / AWS S3 (lazy boto3, background threads, fail-open) |
| `warden/storage/__init__.py` | Package init for storage backends |
| `docker-compose.yml` | Full orchestration with healthchecks + resource limits (includes minio + minio-init) |
| `warden/shadow_ban.py` | Shadow Ban Engine — differentiated strategies: gaslight (prompt injection), delay (bot/stuffing), standard |
| `warden/metrics.py` | Prometheus metric singletons — incl. `SHADOW_BAN_TOTAL`, `SHADOW_BAN_COST_SAVED_USD` (v2.2) |
| `grafana/provisioning/alerting/warden_alerts.yml` | SLO alerts: P99 latency + 5xx rate + availability + shadow ban rate + corpus drift |
| `docs/security-model.md` | 9-layer defense model, OWASP LLM Top 10 coverage, threat model, crypto controls |
| `docs/dpia.md` | GDPR Art. 35 Data Protection Impact Assessment |
| `docs/soc2-evidence.md` | SOC 2 Type II evidence guide — control mapping + auditor collection procedures |
| `warden/financial/impact_calculator.py` | Dollar Impact Calculator — IBM 2024 benchmarks, industry multipliers, ROI tiers, ASCII report |
| `warden/financial/metrics_reader.py` | Live data adapter — reads logs.json, Redis ERS, Prometheus for real impact numbers |
| `warden/api/financial.py` | FastAPI router `/financial/*` — impact, cost-saved, roi, generate-proposal endpoints |
| `scripts/impact_analysis.py` | CLI entry point — `--live`, `--industry`, `--requests`, `--export`, `--interactive` |
| `.github/workflows/ci.yml` | Test matrix (3.11/3.12) + lint + Docker smoke + mutation testing |
| `warden/secrets_gov/vault_connector.py` | Abstract vault connectors — AWS SM / Azure KV / HashiCorp / GCP SM / env (metadata-only, no plaintext) |
| `warden/secrets_gov/inventory.py` | SQLite-backed secrets inventory — risk scoring, auto-retire, expiry tracking |
| `warden/secrets_gov/policy.py` | Secrets Policy Engine — per-tenant governance rules, compliance audit scoring |
| `warden/secrets_gov/lifecycle.py` | Lifecycle Manager — expiry alerts, auto-retire, rotation scheduling |
| `warden/api/secrets.py` | FastAPI router `/secrets/*` — 14 endpoints: vaults, inventory, lifecycle, policy, audit, report |
| `warden/analytics/pages/6_Secrets_Governance.py` | Streamlit dashboard — 6-tab secrets governance UI |
| `warden/integrations/obsidian/note_scanner.py` | Obsidian note scanner — YAML frontmatter parse, data classification, SecretRedactor integration |
| `warden/api/obsidian.py` | FastAPI router `/obsidian/*` — 5 endpoints: scan, share (SEP UECIID), feed, ai-filter, stats |
| `obsidian-plugin/main.ts` | TypeScript Obsidian plugin — ribbon, status bar, 5 commands, auto-scan on modify, settings tab |
| `warden/api/monitor.py` | Uptime Monitor REST API — `/monitors/*` CRUD + `/status` + `/uptime` + `/history` |
| `warden/workers/probe_worker.py` | Async probe scheduler — HTTP/SSL/DNS/TCP checks, TimescaleDB write, Redis Pub/Sub publish |
| `warden/db/migrations/versions/0010_uptime_monitors.py` | TimescaleDB migration — hypertable, continuous aggregate, retention + compression policies |
| `warden/phishing_guard.py` | PhishGuard + SE-Arbiter — URL phishing + social engineering detection (SEC-GAP-002 fixed) |
| `warden/agent/master.py` | MasterAgent — supervisor loop, 4 sub-agents, HMAC task tokens, human-in-the-loop approval gate |
| `warden/crypto/pqc.py` | Post-Quantum Cryptography — HybridSigner (Ed25519+ML-DSA-65), HybridKEM (X25519+ML-KEM-768), CryptoBackend, liboqs fail-open |
| `warden/crypto/__init__.py` | Package init for crypto backends |
| `warden/communities/keypair.py` | Community keypair — classical + hybrid PQC (`generate_community_keypair(pqc=True)`, `upgrade_to_hybrid()`) |
| `warden/shadow_ai/signatures.py` | AI provider fingerprint DB — 18 providers, domains, URL patterns, local ports, risk levels |
| `warden/shadow_ai/discovery.py` | `ShadowAIDetector` — async subnet probe + DNS telemetry classifier; Redis findings store |
| `warden/shadow_ai/policy.py` | `ShadowAIPolicy` — per-tenant MONITOR/BLOCK_DENYLIST/ALLOWLIST_ONLY governance; Redis-backed |
| `warden/api/shadow_ai.py` | FastAPI router `/shadow-ai/*` — scan, dns-event, findings, report, policy, providers |
| `warden/xai/chain.py` | `CausalChain` + `build_chain()` — 9-stage pipeline graph, primary cause, counterfactuals |
| `warden/xai/renderer.py` | HTML + PDF (reportlab optional) report renderer — self-contained, print-ready |
| `warden/api/xai.py` | FastAPI router `/xai/*` — explain, batch, HTML report, PDF download, dashboard |
| `warden/sovereign/jurisdictions.py` | 8-jurisdiction registry (EU/US/UK/CA/SG/AU/JP/CH) + transfer rules matrix |
| `warden/sovereign/tunnel.py` | `MASQUETunnel` registry — MASQUE_H3/H2/CONNECT_TCP, TOFU pinning, health probing |
| `warden/sovereign/policy.py` | Per-tenant routing policy — BLOCK/DIRECT fallback, data-class overrides, Redis |
| `warden/sovereign/router.py` | Routing engine — picks best tunnel, compliance check, adequacy decisions |
| `warden/sovereign/attestation.py` | `SovereigntyAttestation` — HMAC-SHA256 signed, Redis 7yr TTL, verify endpoint |
| `warden/api/sovereign.py` | FastAPI router `/sovereign/*` — jurisdictions, tunnels, policy, route, attest, report |
| `warden/billing/addons.py` | Add-on SKU registry — `ADDON_CATALOG`, grant/revoke/check (Redis), `require_addon_or_feature()` FastAPI dep (HTTP 403 tier too low / 402 not purchased) |
| `warden/billing/router.py` | Billing API — tier catalog (Pro $69/Enterprise $249), addon catalog+checkout+grant+revoke endpoints |
| `warden/communities/sep.py` | SEP core — UECIID codec (Snowflake→base-62 `SEP-{11}`) + UECIID index + Causal Transfer Proof (HMAC + optional ML-DSA-65 pqc_signature) + Sovereign Pod Tags |
| `warden/communities/peering.py` | Inter-community peering — MIRROR_ONLY/REWRAP_ALLOWED/FULL_SYNC; HMAC handshake token; `transfer_entity()` → TransferGuard → CTP → STIX audit chain |
| `warden/communities/knock.py` | Knock-and-Verify invitations — Redis-backed tokens (72h TTL); `issue_knock()`, `verify_and_accept_knock()` |
| `warden/communities/transfer_guard.py` | Causal Transfer Guard — maps SEP context → CausalArbiter evidence; blocks exfiltration (P≥0.70) in <20ms; `TRANSFER_RISK_THRESHOLD` env var |
| `warden/communities/data_pod.py` | Sovereign Data Pods — per-jurisdiction MinIO routing; `register_pod()`, `get_pod_for_entity()`, `probe_pod()`; Fernet-encrypted secret keys |
| `warden/communities/stix_audit.py` | STIX 2.1 Tamper-Evident Audit Chain — SHA-256 prev_hash chain; `append_transfer()`, `verify_chain()`, `export_chain_jsonl()`; SQLite `sep_stix_chain` |
| `warden/api/sep.py` | SEP REST API `/sep/*` — 24 endpoints: UECIID, pod tags, peerings, knock, pods CRUD+probe, audit-chain list/verify/export |
| `warden/agent/sova.py` | SOVA core — Claude Opus 4.6 agentic loop, prompt caching, tool dispatch, Redis memory |
| `warden/agent/tools.py` | 30 tool handlers + Anthropic schema defs + TOOL_HANDLERS dispatch table |
| `warden/tools/browser.py` | BrowserSandbox (Playwright headless Chromium) + `ScreencastRecorder` (video → MinIO SOC 2 evidence) |
| `warden/agent/memory.py` | Redis-backed conversation memory (sova:conv:{sid}, 6h TTL, 20-turn cap) |
| `warden/agent/scheduler.py` | 7 ARQ job functions for SOVA scheduled tasks |
| `warden/agent/healer.py` | WardenHealer — autonomous anomaly detection (CB, bypass spike, corpus DEGRADED, canary probe, OLS trend prediction, Haiku classification, SQLite recipe cache) |
| `warden/api/agent.py` | FastAPI router `/agent/sova` — query, clear session, trigger task |
| `warden/testing/context.py` | SWFE FakeContext — unified fake activation via mock.patch, X-Simulation-ID isolation |
| `warden/testing/fakes/` | SWFE fake layer — FakeAnthropicClient, FakeNvidiaClient, FakeS3Storage, FakeEvolutionEngine |
| `warden/telemetry.py` | OTel TracerProvider, gRPC exporter, `trace_stage()` context manager (all 9 pipeline stages) |
| `dashboard/` | Next.js 14.2 SOC Dashboard — App Router, TanStack Query, Recharts, Tailwind dark theme |
| `dashboard/src/lib/api.ts` | API client — stats, events, event detail, threats, roi, compliance, health, filter |
| `dashboard/src/app/(soc)/` | Route group — overview, events, events/[id], threats, sandbox, platform/metrics, platform/traces |
| `dashboard/Dockerfile` | Multi-stage Node 20 Alpine build (deps → builder → runner), port 3002 |
| `packages/ui/` | Shared DS-01 design system — 10 components (Card, Button, Badge, Input, Select, Modal, Table, Tabs, Chart, ThemeToggle) + ThemeProvider; standalone npm package, not a workspace member |
| `docker/Caddyfile` | Caddy v2 vhosts — api/app/analytics/landing/dash.shadow-warden-ai.com |
| `warden/testing/scenarios/` | SWFE Scenario DSL — ScenarioRunner, ScenarioStep, build_core_scenarios(), YAML loader |
| `docs/sla.md` | Formal SLA — Pro 99.9% / Enterprise 99.95% uptime, P99 < 50ms, incident response, credits |
| `site/src/pages/community/*.astro` | 7-page Community & Tunnel Astro SPA — `view`, `members`, `tunnel`, `integrations`, `activity`, `settings`, `new`; all data in `localStorage` key `sw_communities`; member roles (Owner/Admin/Member), join request flow, E2EE key simulation, audit log, disappearing messages, GDPR export |
| `site/src/layouts/BaseLayout.astro` | Astro base layout — navbar + footer + mobile menu + `og:image` + favicon; uses `/logo.png` (castle PNG); wraps all 40 site pages |
| `site/public/logo.png` | Shadow-Warden-AI castle logo PNG — primary brand asset on all 40 Astro pages, og:image, favicon |
| `warden/vendor_gov/registry.py` | AI Vendor Governance Register — `VendorRecord`, `DPARecord`, expiry alerts, vendor stats (BL-22) |
| `warden/financial/cost_allocation.py` | AI Cost Allocation — per-dept/vendor SQLite spend tracking, monthly summaries (BL-23) |
| `warden/financial/budget.py` | AI Budget Dashboard — budget caps, threshold alerts, approval workflow (BL-24) |
| `warden/communities/incident_register.py` | AI Incident Register — STIX-linked severity journal, auto-log from filter events (CM-35) |
| `warden/communities/supplier_risk.py` | Supplier AI Risk Assessment — 5-criteria composite scoring, peering-based (CM-36) |
| `warden/communities/prompt_library.py` | Shared Prompt Library — UECIID provenance, injection screening, community sharing (CM-37) |
| `warden/communities/training_records.py` | Employee AI Training Records — HMAC-SHA256 attestation, behavioral hooks (CM-38) |
| `warden/integrations/smb_suite.py` | SMB AI Governance Suite — single-wizard provisioning of all 7 SMB modules (IN-25) |
| `warden/api/vendor_gov.py` | FastAPI router `/vendor-gov/*` — 7 endpoints (BL-22) |
| `warden/api/cost_allocation.py` | FastAPI router `/financial/allocation/*` — 5 endpoints (BL-23) |
| `warden/api/budget.py` | FastAPI router `/financial/budget/*` — 5 endpoints (BL-24) |
| `warden/api/incident_register.py` | FastAPI router `/incidents/*` — 5 endpoints (CM-35) |
| `warden/api/supplier_risk.py` | FastAPI router `/supplier-risk/*` — 3 endpoints (CM-36) |
| `warden/api/prompt_library.py` | FastAPI router `/prompt-library/*` — 6 endpoints (CM-37) |
| `warden/api/training_records.py` | FastAPI router `/training/*` — 5 endpoints (CM-38) |
| `warden/api/smb_suite.py` | FastAPI router `/smb-suite/*` — 3 endpoints (IN-25) |
| `warden/analytics/pages/10_SMB_Governance.py` | Streamlit SMB Governance — 6 tabs: Incidents, Vendors, Training, Prompt Library, Supplier Risk, Budget |
| `warden/business_intelligence/service.py` | BI analytics — 8 functions: usage, threats, vendors, costs, compliance, benchmarks, predictions, reports (CM-39) |
| `warden/business_intelligence/repository.py` | BI SQLite cache — 15-min TTL, `cache_get/set/invalidate/purge_expired/stats` |
| `warden/business_intelligence/predictive.py` | Pure-Python OLS extrapolation — `moving_average`, `linear_trend`, `predict_next`, `r_squared`, `trend_direction` |
| `warden/business_intelligence/benchmarking.py` | Community benchmarking — `percentile`, `percentile_rank`, `benchmark_metric`, `build_benchmarks` |
| `warden/business_intelligence/router.py` | FastAPI router `/business-intelligence/*` — 11 endpoints (CM-39) |
| `warden/analytics/pages/12_Business_Intelligence.py` | Streamlit BI dashboard — 8 tabs: Usage, Threats, Vendors, Costs, Compliance, Benchmarks, Predictions, Report Builder |
| `warden/semantic_layer/__init__.py` | Semantic Layer (Headless BI) package — FE-42 |
| `warden/semantic_layer/models.py` | Pydantic models — `SemanticModel`, `Metric`, `Dimension`, `QueryObject`, `QueryResult`; dual field-name aliases for repo/engine compat |
| `warden/semantic_layer/engine.py` | `SemanticEngine` — deterministic SQL generator, 3 built-in models, access-rule enforcement, parameterised output |
| `warden/semantic_layer/api.py` | FastAPI router `/semantic-layer/*` — 5 endpoints: list/get/register models, query, AI query (Pro+ gate) |
| `warden/analytics/pages/15_Semantic_Layer.py` | Streamlit Semantic Layer — 4 tabs: Models, Query Builder, AI Query, Docs |
| `dashboard/src/app/(soc)/semantic-layer/page.tsx` | SOC Dashboard semantic-layer page — model cards, AI query widget, architecture panel |
| `warden/settings/__init__.py` | Settings Hub package — FE-43 |
| `warden/settings/models.py` | Settings Pydantic models — `AgentSettings`, `CommerceSettings`, `SemanticSettings`, `NotificationChannel` + API-router aliases |
| `warden/settings/service.py` | `SettingsService` — Redis + in-process fallback; 10 module-level shims for `/api/settings.py` compatibility |
| `warden/settings/api.py` | FastAPI router `/settings/*` — agents, notifications, commerce, semantic config |
| `warden/api/settings.py` | Original settings router — API keys, secrets, agent config, notification channels; imports shims from `warden/settings/service` |
| `warden/analytics/pages/16_Settings.py` | Streamlit Settings Hub — 6 tabs: API Keys, Secrets, Agents, Notifications, Commerce, Semantic |
| `dashboard/src/app/(soc)/settings/page.tsx` | SOC Dashboard settings status page — config snapshot, quick links |
| `warden/semantic_layer/catalog.py` | Self-Service tenant model registry — register/update/delete/list with SQLite persistence + hot-reload into SemanticEngine singleton; `bootstrap_tenant_models()` on startup |
| `warden/business_community/agentic_commerce/semantic_budget.py` | Commerce Budget Guardian — `check_budget()` reads limits from Settings Hub, queries `ai_spend` Semantic Layer model for MTD spend, returns allow/require_approval/block; `get_spend_summary()` for dashboards |
| `site/src/pages/analytics.astro` | AI Analytics Hub landing page — /analytics; 9-model grid, architecture flow, Budget Guardian + Self-Service + SOVA tool docs, SQL example, CTA |
| `site/src/components/WhatsNew.astro` | Changelog section — v5.3/v5.2/v5.1 entries, wired into index.astro |
| `site/src/pages/roadmap.astro` | /roadmap page — 25 shipped + 3 planned features, JS filter by status + tier |
| `ROADMAP.md` | Machine-readable feature registry — FE-01…FE-49, CP-22/25, IN-15, status, tier, version |
| `scripts/warden_github_scan.py` | GitHub Actions & pre-commit scan driver — `ci` mode (commit message + per-file diff, skip binaries) + `pre-commit` mode (staged diff + COMMIT_EDITMSG); `build_step_summary()` + `build_pr_comment()` renderers |
| `.github/workflows/warden-scan.yml` | GitHub Actions CI gate — triggers on push/PR to main/develop/master; per-file diff scanning, step summary table, PR comment, 90-day audit artifact, `workflow_dispatch` with `fail-on` choice |
| `.github/actions/warden-scan/action.yml` | Reusable composite action — `verdict`, `files-scanned`, `high-risk-count` outputs; wraps `warden_github_scan.py` |
| `warden/analytics/pages/17_Compliance_Scoring.py` | Streamlit compliance scoring — 4 tabs: Posture (SVG ring + Altair bar), Timeline (area chart + sparklines), Standards (drilldown cards), Evidence (download links); 30s auto-refresh |
| `warden/analytics/pages/18_ISO27001.py` | Streamlit ISO 27001:2022 — 4 tabs: Overview (KPI + theme coverage), Controls (searchable 93-item matrix), Themes (per-theme drilldown), Report (HTML + JSON links) |
| `dashboard/src/app/(soc)/compliance/page.tsx` | SOC Dashboard compliance page — real-time 5-standard posture, SVG score ring, bar chart, timeline, evidence download section |
| `dashboard/src/app/(soc)/compliance/iso27001/page.tsx` | SOC Dashboard ISO 27001 drilldown — KPI tiles, theme bars, Recharts bar chart, full 93-control searchable matrix with theme/status filters |
| `dashboard/src/app/(soc)/community/page.tsx` | SOC Dashboard Community Hub list — 4 StatCards (total/active/public/suspended), community cards sorted desc by `created_at`, click → detail; `NEXT_PUBLIC_TENANT_ID` fallback |
| `dashboard/src/app/(soc)/community/[id]/page.tsx` | SOC Dashboard Community Hub detail — 6 tabs: Overview/Members/Data/Compliance/Evolution/Analytics; WebSocket live-metrics banner (`useCommunityWebSocket`); members sorted desc by `joined_at`; dates in `dd/mm/yy` |
| `dashboard/src/hooks/useCommunityWebSocket.ts` | Community WebSocket hook — connects `wss://.../ws/community/{id}`, `WsStatus` type, 30s auto-reconnect on unclean close, unmount cleanup |
| `warden/analytics/pages/22_Community_Hub.py` | Streamlit Community Hub — 7 tabs: My Communities / Explore / Members / Data / Compliance / Evolution / Settings; `fmt_date()` dd/mm/yy helper; `st_toast()` fallback wrapper; descending date sort on all lists |
| `warden/app_factory.py` | Application Factory (v7.2) — `RouterSpec` + `register_router_safe()` (catches all `Exception`, not just `ImportError`); `register_staff_routers()` isolates the Digital Staff subsystem; `OPTIONAL_ROUTERS` registry of 30+ routers for gradual migration |
| `warden/staff/economics.py` | Unit Economics Token Tracker (v7.2) — `TokenCostTracker` SQLite per-action LLM cost (Haiku/Sonnet/Opus pricing); `get_report()`, `get_margin_alerts()`, `get_total_cost()` |
| `warden/staff/a2a.py` | Agent-to-Agent Protocol (v7.2) — `A2ARouter` HMAC-SHA256 call tokens, `ALLOWED_ROUTES` whitelist, SQLite audit trail; SupportAgent → ComplianceAgent KYC pre-check |
| `warden/staff/structured_log.py` | Structured JSON Logging (v7.2) — `emit()` fixed-schema JSON lines to `warden.staff` logger; `AgentSpan` context object for correlated agent/tool lifecycle events |
| `warden/tests/test_contract_security.py` | Security Contract Tests (v7.2) — 52 invariant tests across SecretRedactor / SemanticGuard / TopologicalGatekeeper / ObfuscationDecoder / MaskingEngine |
| `warden/tests/test_staff_economics.py` | Unit tests for `TokenCostTracker` — cost computation, reporting, margin alerts |
| `warden/tests/test_staff_a2a.py` | Unit tests for `A2ARouter` — HMAC tokens, route whitelist, audit log |
| `docs/cloudflare-waf.md` | Cloudflare WAF documentation — rate limit rules, custom WAF rules, DNS/SSL config, Workers preflight stub |
| `warden/sac/guard.py` | SAC Inner Warden execution guard — screens agent tool calls (SSRF/exfil URL block fail-CLOSED via `net_guard`, secret-path denylist); first GSAM producer, metadata-only, fail-OPEN telemetry (FE-52) |
| `warden/gsam/jit_lease.py` | GSAM Hermes JIT credential lease — single-use HMAC leases on `gsam_leases`, fail-CLOSED (503 without key), secret never in response; mirrors `protocols/acp/token_vault.py` (FE-52) |
| `warden/gsam/api.py` | GSAM REST API — `/gsam/lease*` (issue/redeem/revoke/get); read surface (`/gsam/heatmap` etc.) added in a later slice (FE-52) |
| `docs/sac-architecture.md` | SAC architecture — pillar 1 (execution guard) + pillar 2 (JIT lease), config, non-goals (eBPF/Kata/COW/ZK/AMM), follow-on slices |
| `warden/gsam/drift.py` | GSAM drift math (pure) — L1/total-variation distance, EWMA drift, poisoning-gated baseline update, anti-inflation clamp |
| `warden/gsam/rollup.py` | GSAM rollup sink — folds observation batches → `gsam_agent_stats` (hourly upsert) + drift baselines; `read_agent_stats`/`read_heatmap`/`compliance_score` read helpers |
| `warden/gsam/quarantine.py` | GSAM drift quarantine — `quarantine_agent`/`is_quarantined`/`release_agent`; Redis flag + in-proc TTL fallback |
| `docs/modernization-plan-v8.md` | Deep-eng/math modernization plan — 1–100 assessment, 7-phase roadmap, cybersecurity deep-dive; Phase 1 (GSAM downstream) done |

## Build & Test Commands

```bash
# Start all services (including dashboard on port 3002)
docker-compose up --build

# Build dashboard separately (if not using compose)
docker build -t shadow-warden-dashboard ./dashboard

# Run tests locally (CPU-only torch required)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"

# Full coverage gate
pytest warden/tests/ --tb=short -m "not adversarial" --cov=warden --cov-fail-under=75

# Lint (ruff + mypy — must pass before merge)
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional

# Mutation testing (Linux/WSL/CI only — not supported on native Windows)
mutmut run --no-progress

# CI: force --no-cache pre-build for admin + arq-worker (prevents corrupted layer cache)
docker compose build --no-cache admin arq-worker 2>&1 | tail -5 || true
```

## Environment Variables (test context)

Tests require these env vars (set in `warden/tests/conftest.py`):

```
ANTHROPIC_API_KEY=""           # disables Evolution Engine
WARDEN_API_KEY=""              # disables auth
ALLOW_UNAUTHENTICATED="true"   # required when WARDEN_API_KEY is blank (fail-closed by default)
SEMANTIC_THRESHOLD="0.72"
LOGS_PATH="/tmp/warden_test_logs.json"
DYNAMIC_RULES_PATH="/tmp/warden_test_dynamic_rules.json"
STRICT_MODE="false"
REDIS_URL="memory://"          # in-memory limiter; no Redis needed
MODEL_CACHE_DIR="/tmp/warden_test_models"  # default /warden/models is Docker-only
```

OTel + dashboard env vars (production, in `/opt/shadow-warden/.env`):

```
OTEL_ENABLED=true                                          # activate distributed tracing
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317    # gRPC exporter endpoint
OTEL_SERVICE_NAME=shadow-warden                            # Jaeger service label

# Dashboard (dashboard/ service, port 3002)
NEXT_PUBLIC_API_URL=https://api.shadow-warden-ai.com
NEXT_PUBLIC_ANALYTICS_URL=https://api.shadow-warden-ai.com
NEXT_PUBLIC_GRAFANA_URL=http://91.98.234.160:3000
# Jaeger is bound to 127.0.0.1 (no authentication — it must not be on a public
# IP). Reach it via `ssh -L 16686:127.0.0.1:16686 root@<host>`, or put it behind
# a vhost + Cloudflare Access and point this at that hostname. Do NOT set it
# back to http://<public-ip>:16686.
NEXT_PUBLIC_JAEGER_URL=http://127.0.0.1:16686
```

## Design Constraints

- **One gate for every agentic tool call (Phase 7)**: `warden/agent/gate.py::agentic_gate()` applies boundary (fail-CLOSED) → velocity → GSAM quarantine (additive) to SOVA and MasterAgent, the same three checks Digital Staff get. `traced_dispatch(tool_name, tool_input, agent_id, *, already_gated=False)` runs it for every non-staff caller. **Never dispatch a tool by reaching into `TOOL_HANDLERS` directly** — that is exactly the hole MasterAgent had (no SAC/SSRF screen, no boundary, no velocity, no quarantine, no span), and `_AGENT_TOOLS` alone only limits what is *offered* to the model, not what executes. Agentic boundaries are seeded by `ensure_agentic_boundaries()` from the authoritative tables (SOVA = all `TOOL_HANDLERS`; sub-agent = its `_AGENT_TOOLS` list) under namespaced ids (`master:<sub_agent>`). `staff_dispatch` passes `already_gated=True` — it ran the checks itself; re-running double-counts velocity. STAFF-01/02 stay as-is on the staff path.
- **One chokepoint for money movement (FT-6, in progress)**: `warden/payments/authorize.py::authorize_payment()` mirrors `agentic_gate()`'s role but for payments — composes the autonomy check (`marketplace/autonomy.py::check_action()`) + Budget Guardian (`business_community/agentic_commerce/semantic_budget.py::check_budget()`) unconditionally, plus AP2 mandate verification when a `mandate_id` is given. Verdict precedence DENY > REQUIRE_APPROVAL > ALLOW; each check fails soft to REQUIRE_APPROVAL on its own error (never silent ALLOW, never hard DENY on an infra error). Opt-in via `AUTHORIZE_PAYMENT_ENFORCED` (default false). **Not yet a ratchet-enforced chokepoint** — `marketplace/listing.py::purchase_listing()` and `marketplace/clearing.py::clear()` both call it now; `credits.py::purchase_credits()` is deliberately excluded (it fulfills an already-settled external Lemon Squeezy payment, not an agent spend decision — see `warden/marketplace/CLAUDE.md`). Order-model and x402-implementation consolidation (the other two FT-6 sub-parts) remain unstarted. Do not assume every money endpoint passes through this yet.
- **Signing keys are fail-CLOSED (Phase 7)**: any key you *sign* with must come from `warden.secret_keys.resolve_key(env_name, purpose=...)` — explicit env override wins, else a domain-separated subkey derived from the boot-validated `VAULT_MASTER_KEY`, else it **raises**. Never `os.getenv("X_SECRET", "")` plus "skip the check when empty" — that is a fail-open signature bypass (exactly the hole closed in `agentic/mandate.py`, where an unset `MANDATE_SECRET` accepted **unsigned** payment mandates). Resolve keys **per call**, never at import (a module-level snapshot captures `""` before the env is set). Verification must be unconditional; an unresolvable key **denies**. Guarded by the `test_no_new_raw_signing_key.py` ratchet.
- **DDL registry (Phase 6)**: `warden/db/ddl_registry.py` is the central schema registry for the per-module SQLite DBs. Modules call `register(db_key, module, ddl)` at import and `ensure_schema(conn, db_key, db_path)` inside their connection helper — never `conn.executescript(DDL)` on every connection. `ensure_schema` is **lazy** (first connection in the process, so workers/tests without the FastAPI lifespan still get tables — do NOT convert it to a startup-only `apply_all()`), **memoized** (DDL-once), **persistent** (`_warden_ddl_applied` module+checksum), **drift-detecting** (changed checksum re-applies), and **fail-safe** (tracking failure ⇒ run DDL directly). `db_key` must be **per physical DB file**, not per Turso db name — two modules sharing a Turso db but separate local files need separate keys or their tables cross-leak. The Alembic tree (`warden/db/migrations`) is Postgres-only and is deliberately NOT the home for these DBs. DE-6 P1 (batches 9–19) migrated nearly every module onto this seam via `open_db()`/`open_persistent_db()`/`open_db_readonly()`; the raw-`sqlite3.connect()` ratchet (`warden/tests/test_no_raw_sqlite_connect.py`) is down to 2 sites, both the legitimate `sqlite3.Connection.backup()` src/dst pair in `warden/backup/service.py` (byte-level online backup, not an app query — intentionally outside the seam).
- **GSAM ingest is fail-OPEN toward ClickHouse** — it spools to NDJSON and replays, so a dead OLAP store fails *silently*. `GET /gsam/health` (`warden/gsam/api.py`) is the operator signal: `clickhouse_enabled/reachable`, `spool_bytes`, queue depth/dropped, plus a `degraded` flag (enabled-but-unreachable OR spool backlog OR drops). ClickHouse is already on in `docker-compose.yml` (service + `docker/clickhouse/init.sql`, `GSAM_CLICKHOUSE_ENABLED=true`), and is intentionally **not** in warden's `depends_on` so the gateway boots without it. Alert on `degraded`, not on container liveness.
- **Encrypted DB backup (Phase 6 + R1)**: `warden/backup/service.py` is the single source of truth — discovers every `warden_*.db` under `data_dir()`, SQLite online-backup → Fernet (`VAULT_MASTER_KEY`, **fail-CLOSED** — no key, no backup) → `SNAPSHOT_DIR/<ts>/*.db.enc`, keeps last `SNAPSHOT_KEEP` (7). **R1**: when `DATABASE_URL` is set, `pg_dump --format=custom` is also encrypted into the same snapshot dir as `postgres.pgdump.enc` (`pg_restore --clean --if-exists` on restore via `restore(snap, db_name="postgres")`); a pg_dump failure never costs the SQLite snapshots in the same run. Ship is **fail-OPEN** to *two* independent S3 targets — same-host `S3_*` (MinIO) and **offsite** `OFFSITE_S3_*` (different hardware — the same-host copy does not survive VPS loss); each degrades independently via `record_failopen`. Requires `postgresql-client-16` in `warden/Dockerfile` (PGDG apt repo — bookworm's default client 15 cannot dump a pg16 server). Runs as `sova_nightly_backup` ARQ cron on `arq-worker` (03:30 UTC) — `arq-worker` needs `VAULT_MASTER_KEY` + `S3_*`/`OFFSITE_S3_*` in `docker-compose.yml`, not just `warden`. `scripts/db_snapshot.py` is a thin CLI wrapper over it (used by the autonomous-loop Step 1b). Never re-implement backup logic elsewhere; extend the service.
- **`WARDEN_DATA_DIR` (Phase 6 data-layer consolidation)**: single base dir for all module SQLite DBs + spool files. `warden/config.py` exports `data_dir()` and `data_path(filename, override_env=None)`; new/edited module DB paths must resolve their default via `data_path("warden_x.db", "X_DB_PATH")` — never hardcode `/tmp/…`. Defaults to `/tmp` (backward-compatible); set to a persisted volume in prod. Explicit per-module `X_DB_PATH` env overrides always win. Live: all 17 `config.py` path defaults + the `warden/staff/*` cluster. The primitive lives in `config.py` (not `warden/db/`) to avoid the `db/__init__ → connection → config` circular import.
- **`WARDEN_ENV` + secret-DBs-off-/tmp guardrails (S1)**: `data_path()` creates a non-`/tmp` base dir with **mode `0o700`** (+ best-effort `chmod` to tighten a pre-existing loose dir) — module DBs hold PII/secret material and must never be world-readable; `/tmp` itself is never chmod-ed (OS-owned sticky dir). `Settings.warden_env` (env `WARDEN_ENV`, default `"dev"`) drives `settings.is_prod` (`prod`/`production`). In prod, `Settings.validate()` **flags** a `data_dir()` still resolving under `/tmp` (POSIX-normalised string check — not `os.path.abspath`, which rewrites `/tmp`→`C:\tmp` on a Windows host); with `CONFIG_FAILCLOSED=true` the boot crash-loops instead of serving credentials from ephemeral `/tmp`. Dev/unset env is unchanged. Set `WARDEN_ENV=production` + `WARDEN_DATA_DIR=/var/lib/warden` (or similar persisted mode-0700 volume) on the VPS.
- **`BI_DB_PATH` env var**: SQLite cache for Business Intelligence module (`/tmp/warden_bi.db` default). Shared by `business_intelligence/repository.py`. 15-minute TTL on all cached reports. Cache is invalidatable per-tenant via `DELETE /business-intelligence/cache`.
- **BI data sources are read-only**: `business_intelligence/service.py` only reads from `SEP_DB_PATH` (incidents, training, supplier risk), `VENDOR_GOV_DB_PATH` (vendors, DPA), `COST_ALLOC_DB_PATH` (spend), and `LOGS_PATH`. Never writes to peer module DBs.
- **SMB suite modules**: 8 new feature keys in `TIER_LIMITS` (`vendor_governance_enabled`, `cost_allocation_enabled`, `budget_dashboard_enabled`, `incident_register_enabled`, `supplier_risk_enabled`, `prompt_library_enabled`, `training_records_enabled`, `smb_suite_enabled`). All Community Business+ and above. Add-on `smb_governance_suite` $29/mo unlocks all 8 from Individual tier.
- **Incident Register STIX linkage**: `log_incident()` in `incident_register.py` calls `stix_audit.append_transfer()` after creation and stores `stix_chain_id` on the incident record. Every AI incident is automatically in the STIX audit trail.
- **Training attestation**: `record_completion()` in `training_records.py` HMAC-SHA256 signs the completion record with `VAULT_MASTER_KEY`. Unsigned completions are invalid. Calls `behavioral.record_event()` with `"ai_training_completed"` for anomaly tracking.
- **Prompt library injection screening**: `add_prompt()` in `prompt_library.py` runs `POST /filter` on the prompt text before saving. If the filter returns `blocked=True`, the prompt is rejected with HTTP 422.
- **Supplier risk is peering-based**: `assess_supplier()` pulls velocity and rejection rate from `sep_transfers` and DPA status from `vendor_dpa_records` to compute composite score. No external API calls.
- **CPU-only torch**: Two-step Dockerfile pip install (`--index-url` prevents CUDA pull). Target hardware is standard dev machines, not GPU servers.
- **Playwright base image**: `mcr.microsoft.com/playwright/python:v1.49.0-noble` — do NOT switch to `python:3.x-slim` (Playwright requires OS-level browser deps from MCR). Non-root user uses GID/UID 10001 (1001 is taken by the noble base image).
- **GDPR**: Content is NEVER logged — only metadata (type, length, timing). This is a hard requirement.
- **Atomic writes**: `tempfile` + `os.replace()` for `logs.json` and `dynamic_rules.json` to prevent corruption.
- **Async logging**: `event_logger.append()` is dispatched via `background_tasks.add_task()` when `background_tasks is not None` (i.e., inside a FastAPI request handler). Falls back to synchronous call only when no BackgroundTasks scope exists. Keeps file I/O + threading lock off the hot response path.
- **Redis socket timeouts**: `cache.py` uses `socket_connect_timeout=5, socket_timeout=3`. Do not tighten below these values — values below 2s/1s cause false cache-miss cascades under transient Redis load.
- **Docker stop_grace_period: 30s**: warden service in `docker-compose.yml` is set to `stop_grace_period: 30s` so in-flight requests complete before the container exits on deploy or restart.
- **No root package.json**: the repo root has no `package.json`. `portal/` and `dashboard/` are standalone npm projects with their own lock files. `packages/ui/` has its own `package.json` but is not a workspace member. Do not add a root `package.json` with `workspaces` — it breaks `npm ci` in subdirectories on Linux npm v10.
- **Client IP behind Cloudflare**: request code must resolve the caller with `warden.client_ip.get_client_ip(request)` — **never** `request.client.host`, `get_remote_address()`, or a raw `X-Forwarded-For` read. warden's peer is always the Caddy container, so the socket address is one constant for the whole internet: keying ERS / shadow ban / slowapi / marketplace quota on it puts every anonymous caller in a single bucket (one attacker shadow-bans everyone, and the per-minute quota is shared globally). `get_client_ip()` honours `CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For` **only** when the peer is inside `TRUSTED_PROXY_CIDRS` (default loopback + RFC1918), so a direct-to-origin request cannot spoof an identity. `docker/Caddyfile` is the other half: `trusted_proxies` (Cloudflare ranges + `private_ranges` for `cloudflared`) + `client_ip_headers`, and the `(client_ip_headers)` snippet *overwrites* all three headers with `{client_ip}` on every `reverse_proxy`. The only exception is `mtls.py`, which logs the true TLS peer by design. See `docs/cloudflare-waf.md`; guarded by `warden/tests/test_client_ip.py`.
- **Cloudflare rules are edge-only**: every WAF / rate-limit / Bot-Fight rule is bypassed by a request sent straight to the origin IP. Keep Authenticated Origin Pulls (mTLS) + a Cloudflare-only host firewall on `80/443`, and never publish `16686` (Jaeger — zero auth), `9000`/`9091` (MinIO) on the public interface; they are bound to `127.0.0.1` in `docker-compose.yml`. Never allowlist `104.18.0.0/16` / `104.21.0.0/16` in Bot Fight — those are Cloudflare's own proxy ranges, not an identity.
- **Fail-closed auth (#11)**: startup raises `RuntimeError` if `WARDEN_API_KEY` and `WARDEN_API_KEYS_PATH` are both unset, unless `ALLOW_UNAUTHENTICATED=true`. Tests set `ALLOW_UNAUTHENTICATED=true` in `conftest.py`.
- **VAULT_MASTER_KEY validation (#1)**: startup validates Fernet key format and halts with a clear error if invalid. Used by communities/sovereign/data_pod for at-rest encryption of private key material.
- **Shadow ban randomness (#3)**: `_pick_response()` uses `secrets.choice()` — not deterministic hash — to prevent fingerprinting. `_GASLIGHT_POOL` has 30+ entries.
- **CPT drift gate (#6)**: `calibrate_from_logs()` rejects CPT updates that shift any parameter >25% from prior — prevents slow-burn data poisoning via coordinated borderline attacks.
- **Evolution regex gate (#2)**: `EvolutionEngine._validate_regex_safety()` rejects AI-generated `regex_pattern` rules that fail compile, time out on 8 000-char degenerate string (0.3s), or contain nested quantifiers.
- **Evolution Loop optional**: Runs without `ANTHROPIC_API_KEY` (air-gapped mode). All detection still works.
- **Model loading**: `@lru_cache(maxsize=1)` singleton in `brain/semantic.py`. Pre-warmed in FastAPI `lifespan()`. Uses `asyncio.get_running_loop()` (not deprecated `get_event_loop()`).
- **Entrypoint pass-through**: `entrypoint.sh` checks `$# > 0` — if args are passed (e.g. `docker run ... python3 script.py`), exec them as wardenuser instead of starting uvicorn. Required for `[1b/4]` ONNX export step in CI deploy.
- **DataPoisoningGuard model access**: uses `_load_model()` from `warden.brain.semantic` (module-level `@lru_cache` singleton) — NOT `self._guard._model` (SemanticGuard has no such attribute).
- **Corpus snapshot atomicity**: `tempfile.mkstemp()` per call in `_save_snapshot_sync()` — prevents ENOENT race when two uvicorn workers call `save_snapshot_async()` concurrently.
- **Intel Bridge optional**: `INTEL_OPS_ENABLED=true` activates background ArXiv → Evolution sync. `INTEL_BRIDGE_INTERVAL_HRS` (default 6). Requires `ANTHROPIC_API_KEY` for synthesis; fail-open otherwise.
- **SOVA agent optional**: requires `ANTHROPIC_API_KEY`. Router mounted at startup with try/except — missing anthropic package skips silently. Session memory fails open (no Redis = no history).
- **Named Docker volume `warden-models`**: replaces bind-mount `./warden/models`. Persists ONNX model across rebuilds and git operations. ONNX export uses `--name warden-onnx-export` + skip-if-running guard to prevent OOM from duplicate containers.
- **`warden-models` migration**: copy from host path via `docker run --rm -v warden-models:/warden/models alpine sh -c "cp -r /src/. /warden/models/"` before switching compose mount.
- **ScreencastRecorder video timing**: `page.video.path()` must be called AFTER `page.close()` and BEFORE `context.close()`. `BrowserSandbox.__aexit__` closes the page explicitly when `record_video=True` to finalise the WebM before the context is torn down.
- **visual_assert_page is in-process**: unlike the other 27 SOVA tools (all HTTP), `visual_assert_page` imports `BrowserSandbox` directly and calls the Anthropic SDK in-process. No HTTP round-trip. Requires Playwright + `ANTHROPIC_API_KEY`.
- **visual_diff tool (#31)**: `BrowserSandbox.capture_screenshot_b64()` static helper captures both URLs, sends both images to Claude Vision for comparison. Verdicts: IDENTICAL | MINOR_DIFF | REGRESSION | CRITICAL_REGRESSION | ERROR. Falls back to byte-size delta when no `ANTHROPIC_API_KEY`.
- **WardenHealer is LLM-free on happy path**: all 4 checks are direct httpx calls to localhost:8001. On anomaly, `_llm_classify_incident()` calls Claude Haiku (`claude-haiku-4-5-20251001`) once per unique incident fingerprint and caches the remedy in SQLite `incident_recipes`. `sova_corpus_watchdog` delegates to `WardenHealer` — do not call `_run(task, ...)` from the watchdog.
- **WardenHealer trend prediction**: `_check_trend_prediction()` uses OLS (`_linear_trend()`) over the last 12 bypass-rate samples (stored in SQLite `bypass_metrics`). Fires WARN action if predicted rate > `HEALER_BYPASS_THRESHOLD` (default 15%) while current ≤ threshold. Pure Python — no numpy dependency.
- **PATROL_URLS env var**: comma-separated list of extra URLs for `sova_visual_patrol`.
- **OTel is opt-in**: `OTEL_ENABLED=false` by default. When disabled, `trace_stage()` is a no-op context manager — zero overhead, no import errors. Never import OTel directly in pipeline code; always go through `warden.telemetry`.
- **OTel span attributes must be GDPR-safe**: raw content, decoded text, PII, and secret values are prohibited on spans. Refer to Rule.md §21 for the full allowlist.
- **Next.js 14.2 `next.config.mjs`** (not `.ts`): Next.js 14 does not support TypeScript config files. Use `.mjs` with JSDoc `/** @type */` annotation. `output: "standalone"` enables minimal Docker image (no Next.js CDN runtime dependency).
- **Dashboard `public/` must exist at build time**: Dockerfile runner stage does `COPY --from=builder /app/public ./public` — if `public/` is empty or missing from git, Docker COPY fails. Keep `dashboard/public/.gitkeep` committed.
- **Dashboard uses mock data until Block L-02**: `dashboard/src/app/(soc)/overview/page.tsx` and threats page use `placeholderData` from `@tanstack/react-query`. Wire real API endpoints after analytics REST adapter is built.
- **_PatrolWeights**: Redis-backed per-URL failure weights for `sova_visual_patrol`. Decay × 0.85 on success, boost × 1.5 (cap 10) on failure. Key `sova:patrol_weights` (7-day TTL). Falls back to in-process dict when Redis unavailable. Patrol targets sorted descending by weight so frequently-failing routes always run first.
- **ScenarioStep.smart_retry**: int field (default 0). When > 0, `ScenarioRunner._run_step()` retries the step up to that many extra times on failure. Final `failure_msg` is enriched with XAI causal-chain hint via `GET /xai/explain/{request_id}` (primary stage, verdict, score).
- **MasterAgent task tokens**: every delegated sub-task carries HMAC-SHA256 token `(sub_agent:task_hash:ts:sig)`. `_verify_token()` is called before each sub-agent run — prevents cross-agent injection if a sub-agent is compromised.
- **MasterAgent approval**: `REQUIRES_APPROVAL` is a text flag the sub-agent includes in its response. Master scans for it, extracts context, issues approval token, stores in Redis `master:approval:{token}` (1h TTL), posts to Slack. `/agent/approve/{token}?action=approve|reject` resolves via `resolve_approval()` which sets `master:approval:callback:{cb_key}`. `auto_approve=True` skips the gate entirely (for scheduled jobs).
- **MasterAgent sub-agent tools**: each sub-agent only gets its `_AGENT_TOOLS[SubAgent]` subset — principle of least privilege across agents. Parsed with split/strip — empty strings filtered out. `DASHBOARD_URL` is a separate single-URL convenience var.
- **Shadow AI scan safety limits**: max subnet prefix /24 (256 hosts); max 50 concurrent probes (`SHADOW_AI_CONCURRENCY`); 3s per-host timeout (`SHADOW_AI_PROBE_TIMEOUT`); HTTP fingerprinting only (no raw TCP port scan). Rejects subnets larger than /24.
- **Shadow AI findings cap**: 1 000 most-recent entries per tenant in Redis `shadow_ai:findings:{tenant_id}` (LPUSH + LTRIM).
- **Shadow AI policy modes**: MONITOR (report only) | BLOCK_DENYLIST (enforce denylist) | ALLOWLIST_ONLY (flag unlisted). Stored in Redis `shadow_ai:policy:{tenant_id}` (no TTL). Falls back to in-process dict when Redis unavailable.
- **`scan_shadow_ai` tool (SOVA #29)**: no longer a stub — calls `ShadowAIDetector().scan()` directly. Falls back to `{"status":"unavailable"}` only if `warden.shadow_ai.discovery` ImportError (package missing).
- **XAI chain stages**: 9 nodes in fixed order — topology, obfuscation, secrets, semantic_rules, brain, causal, phish, ers, decision. Each node has `verdict` (PASS/FLAG/BLOCK/SKIP), `score`, `score_label`, `color`, `weight`. Primary cause = first BLOCK node, then highest-weight FLAG.
- **XAI counterfactuals**: one `Counterfactual` per non-PASS stage with a plain-English remediation action. Severity = HIGH (BLOCK) or MEDIUM (FLAG).
- **XAI PDF**: `render_pdf()` uses reportlab if installed → `application/pdf`; falls back to `render_html()` → `text/html`. `X-Report-Format: pdf|html` response header signals which was returned.
- **XAI dashboard**: reads full `load_entries()` then calls `build_chain()` per record — CPU-only, no Redis. Filter by `hours` (1–168). Returns stage hit rates, top causes, flag distribution.
- **MASQUE tunnel lifecycle**: PENDING → ACTIVE (first probe success) → DEGRADED (≥2 failures) → OFFLINE (≥TUNNEL_OFFLINE_AFTER_FAILS=5). TOFU pinning via `tls_fingerprint` (SHA-256 of server leaf cert or endpoint-derived placeholder).
- **Sovereign routing algorithm**: load policy → allowed jurisdictions per data_class → ACTIVE tunnels in those jurisdictions → prefer `preferred_tunnel_id` → else min(home_jurisdiction_first, lowest_latency).
- **Sovereignty attestation**: HMAC-SHA256 over `attest_id|request_id|tenant_id|jurisdiction|tunnel_id|data_class|compliant|issued_at`. Key: `SOVEREIGN_ATTEST_KEY` → fallback `VAULT_MASTER_KEY`. Redis TTL 7 years (220,752,000 s). Cap 10,000 per tenant.
- **Transfer rules matrix**: CLASSIFIED → never; PHI → US/EU/UK/CA/CH only; PII/FINANCIAL/GENERAL → all jurisdictions (with adequacy check for cross_border_restricted sources).
- **Add-on gate HTTP status codes**: 403 = tier below `min_tier` (plan upgrade CTA); 402 = eligible tier but add-on not purchased (checkout CTA). `require_addon_or_feature()` in `warden/billing/addons.py`.
- **UECIID format**: `SEP-{11 base-62 chars}` encodes 64-bit Snowflake; alphabet `0-9A-Za-z` (case-sensitive); lexicographic order = chronological order.
- **SEP SQLite DB**: `SEP_DB_PATH` env var (default `/tmp/warden_sep.db`); shared by sep.py + peering.py. Tables: `sep_ueciid_index`, `sep_pod_tags`, `sep_peerings`, `sep_transfers`.
- **Peering handshake token**: only HMAC-SHA256 hash stored in DB; `_verify_handshake_token()` uses `hmac.compare_digest()`. One duplicate ACTIVE peering between same two communities is blocked.
- **Knock token**: Redis `sep:knock:{hmac_hash}` (72h TTL). `verify_and_accept_knock()` asserts `invitee_tenant_id == claiming_tenant_id` before `invite_member()`. One-time use: status → ACCEPTED.
- **Causal Transfer Proof**: HMAC-SHA256 canonical string stored as JSON in `sep_transfers`. `POST /sep/transfers/{id}/verify-proof` re-derives signature to detect post-issuance tampering. Optional `pqc_signature` field: base64-encoded ML-DSA-65 hybrid sig; populated only when source community keypair `is_hybrid=True`. Both HMAC and PQC must pass `verify_transfer_proof()`.
- **Causal Transfer Guard**: `evaluate_transfer_risk()` runs before every `transfer_entity()`. Maps (data_class, transfer velocity, peering age/policy, burst pattern) → `arbitrate()` evidence nodes. Block threshold: `TRANSFER_RISK_THRESHOLD` (default 0.70). Redis sliding window keys: `sep:transfer_velocity:{community_id}` (sorted set, 1h window) + `sep:transfer_burst:{community_id}` (5min). Falls back to weighted sum if `causal_arbiter` unavailable. Status set to REJECTED (not raised as exception) so the transfer record is still written.
- **Sovereign Data Pods**: SQLite `sep_data_pods` in `SEP_DB_PATH`. Secret keys are Fernet-encrypted with SHA-256 of `COMMUNITY_VAULT_KEY`. `get_pod_for_entity()` resolution order: jurisdiction match → data_class match → primary pod → first ACTIVE pod. `probe_pod()` calls `/minio/health/live` endpoint (5s timeout).
- **STIX 2.1 Audit Chain**: `append_transfer()` is always called after `transfer_entity()` (including REJECTED transfers — full audit trail). Genesis block `prev_hash = "0" * 64`. `verify_chain()` re-hashes bundles from canonical JSON (sorted keys, no whitespace). STIX bundle extension `x-chain.prev_hash` links entries. `export_chain_jsonl()` produces OASIS STIX 2.1 compatible JSONL for SIEM import. `sep_stix_chain.seq` is per-community monotonic sequence.
- **Sovereign Pod Tags**: per-entity data residency. No tag → allowed. PHI EU→US blocked by `is_transfer_allowed()` from sovereign/jurisdictions.py. Tags survive entity deletion.
- **Tier prices**: Starter $0 (1k req), Individual $5/mo (5k req), Community Business $19/mo (10k req, File Scanner + Shadow AI Monitor + 3 communities×10 members + 180-day retention), Pro $69/mo (50k req, MasterAgent included), Enterprise $249/mo (unlimited, PQC + Sovereign). Add-ons: `shadow_ai_discovery` +$15/mo (Pro+), `xai_audit` +$9/mo (Individual+). MasterAgent is included in Pro — **not sold as an add-on**.
- **Billing admin endpoints**: `POST /billing/addons/grant` and `DELETE /billing/addons/revoke` require `X-Admin-Key` header (`ADMIN_KEY` env var). Called by Lemon Squeezy webhook handler.
- **Adequacy decisions**: EU↔UK, EU↔CA, EU↔JP, EU↔CH — used by `is_transfer_allowed()` and `check_compliance()`.
- **PQC optional (liboqs-python)**: `warden/crypto/pqc.py` wraps liboqs with `_OQS_AVAILABLE` guard. All PQC code path raises `PQCUnavailableError(RuntimeError)` if not installed. Classical Ed25519/X25519 still work. `is_pqc_available()` / `pqc_status()` are health check helpers.
- **Hybrid kid convention**: classical kids are "v1", "v2", …; hybrid PQC kids append "-hybrid" (e.g. "v1-hybrid"). `CommunityKeypair.is_hybrid` checks `kid.endswith("-hybrid") and mldsa_pub_b64 is not None`.
- **PQC Enterprise-only**: `pqc_enabled: True` only in the `enterprise` TIER_LIMITS entry. `POST /communities/{id}/upgrade-pqc` requires `_require_tier(mcp)` + `gate.require("pqc_enabled")`. Raises HTTP 503 if liboqs not installed.
- **Hybrid signature layout**: 3373 bytes = Ed25519 sig (64 B) + ML-DSA-65 sig (3309 B). `HybridSignature.pack()` / `unpack()` handle serialization. `hybrid_verify()` falls back to Ed25519-only if liboqs unavailable.
- **Hybrid KEM shared secret**: `HKDF-SHA256(X25519_ss XOR mlkem_ss[:32])` — XOR-then-HKDF pattern; if one algorithm is broken the other provides full security. Ciphertext = ephem_pub (32 B) + ML-KEM-768 ct (1088 B).
- **Semantic Layer (FE-42, v5.1)**: `warden/semantic_layer/` — Headless BI module. `SemanticEngine` generates deterministic SQL from `QueryObject`. 3 built-in models (filter_events, ers_scores, billing_usage). `Metric.effective_expression()` / `Dimension.effective_column()` handle dual field-name schemas. FastAPI router at `/semantic-layer/*` (Pro+). Streamlit page `15_Semantic_Layer.py`. SOC page at `dashboard/(soc)/semantic-layer/`.
- **Settings Hub (FE-43, v5.1)**: `warden/settings/` — unified config for Agents (SOVA/MasterAgent), Notifications, Agentic Commerce, Semantic Layer. `service.py` uses Redis + in-memory fallback. `warden/api/settings.py` router at `/settings/*`. 10 module-level shims bridge class methods to flat API. Streamlit page `16_Settings.py`. SOC page at `dashboard/(soc)/settings/`. Portal page extended with AgentsSection, CommerceSection, SemanticLayerSection.
- **Settings models schema**: `warden/settings/models.py` exports both new models (`AgentSettings`, `CommerceSettings`, `SemanticSettings`) and API-router aliases (`AgentConfig`, `ApiKeyCreate/Out/Created`, `SecretCreate/Out/Update`, `ChannelCreate`, `SettingsSummary`, `TestResult`). Never import API-alias names from outside `warden/api/settings.py`.
- **Agentic Commerce (CM-40, v5.0)**: `warden/business_community/agentic_commerce/` — UCP/AP2/MCP procurement protocols, multi-agent auction (`MultiAgentOrchestrator`), FIDO2 passkeys (`warden/auth/fido.py`), Sepolia Web3 mandate contract (`warden/blockchain/`). Commerce settings stored in Redis via Settings Hub.
- **AI Analytics Hub (FE-47, v5.2)**: `warden/semantic_layer/` expanded to 9 built-in models. Redis cache in `SemanticEngine.generate()` — key = `sl:query:{sha256[:24]}`, TTL = `SEMANTIC_CACHE_TTL` (default 600s), fail-open. Self-Service Catalog at `/semantic-layer/models/catalog` (Pro+). SOVA tools: `semantic_query`, `list_semantic_models`, `check_commerce_budget`, `get_spend_summary`.
- **Commerce Budget Guardian (FE-48, v5.2)**: `warden/business_community/agentic_commerce/semantic_budget.py` — `check_budget()` is called in every AP2 payment; reads `CommerceSettings` from Settings Hub, queries `ai_spend` Semantic Layer model for actual MTD spend. Fail-open: exceptions return `allowed=True`. Slack alert on budget exceeded. `_check_budget()` in `service.py` no longer calls non-existent `get_budget_status`.
- **Self-Service Catalog (FE-49, v5.2)**: `catalog.py` — `bootstrap_tenant_models()` restores persisted models on FastAPI startup. `register_tenant_model()` persists to SQLite + hot-loads into engine. Model IDs must not collide with built-in IDs (`filter_events`, `ers_scores`, `billing_usage`, `incidents`, `vendor_contracts`, `agentic_orders`, `tunnel_sessions`, `compliance_attestations`, `ai_spend`).
- **Self-Service Catalog (FE-49, v5.2)**: `catalog.py` — `bootstrap_tenant_models()` restores persisted models on FastAPI startup. `register_tenant_model()` persists to SQLite + hot-loads into engine. Model IDs must not collide with built-in IDs (`filter_events`, `ers_scores`, `billing_usage`, `incidents`, `vendor_contracts`, `agentic_orders`, `tunnel_sessions`, `compliance_attestations`, `ai_spend`).
- **GitHub Actions CI gate (IN-15, v5.3)**: `scripts/warden_github_scan.py` — two modes: `ci` (commit message + per-file diff, max 30 files, skip binaries/lockfiles) + `pre-commit` (staged diff + COMMIT_EDITMSG). `build_step_summary()` writes to `$GITHUB_STEP_SUMMARY`; `build_pr_comment()` writes `warden_pr_comment.md`. `fail_on` threshold: `BLOCK` (default) or `HIGH`. `github_actions_scan_enabled` feature key: `True` for Pro+/Enterprise, `False` below.
- **Continuous compliance scoring (CP-25, v5.3)**: `GET /compliance/posture` + `GET /compliance/history` gated by `compliance_scoring_enabled` (Pro+). 168-entry `_posture_history` deque stores hourly snapshots. Tier gate uses `_POSTURE_GATE = [require_feature("compliance_scoring_enabled")]` with try/except fail-open import. Tests must pass `X-Tenant-Tier: pro` header to `TestClient`.
- **ISO 27001:2022 full mapping (CP-22, v5.3)**: `_ISO27001_CONTROLS_V2` — 93 5-tuples `(control_id, theme, domain, status, evidence)`. Themes: Organizational (37), People (8), Physical (14), Technological (34). Statuses: Implemented | Partial | Delegated. `_ISO27001_CONTROLS` legacy 4-tuple alias preserved. `iso27001_enabled`: `True` Enterprise only. `_ISO_GATE` fail-open same pattern as posture gate. Tests must pass `X-Tenant-Tier: enterprise`.
- **`_BLOCK_TYPES` alias**: `warden/integrations/misp_bridge.py` exposes `_BLOCK_TYPES = _ALL_TYPES` as a public alias. Import the alias — not `_ALL_TYPES` directly — in external callers and tests.
- **`_span_meta` integer guard**: `format(value, "032x")` must be guarded by `isinstance(value, int)` check before calling. MagicMock-backed spans will set `trace_id`/`span_id` to non-int; guard returns `None` instead of raising `TypeError`.
- **`_scan(meta=None)` default**: `WardenSpanProcessor._scan()` and `_async_scan()` accept `meta: dict | None = None`; callers that omit `meta` get `{}` silently. Do not call with positional-only syntax assuming `meta` is required.
- **Site version: `v7.7` Latest (GSAM Observation Stream / Drift Detection & Agent Quarantine / Hermes JIT Credential Lease / GSAM Read APIs & Dashboards / CI Posture Gate) / `v7.6` (Marketplace API Restored / Community API Restored / Route-Inventory Guard Hardening / CI Import Audit / MCP Config Fix) / `v7.5` (Layered Architecture Refactor / Self-Defending Layer Guard / Route-Inventory Guard / Security Hardening) / `v7.4` (Pipeline Health Endpoint / x402 Replay Protection / payment_bypassed Audit Log / CI Loop Trust Fix) / `v7.3` (Paid MCP Gateway / ACP Protocol / Zero-Trust Billing Audit Chain / Turso Distributed SQLite) / `v7.2` / v7.1 / v7.0 / v5.3 / v5.2 / v5.1.
- **Document Intelligence (FE-50, v5.4)**: `warden/document_intel/converter.py` — `MarkItDownConverter` with SHA-256 Redis cache, file-type TTLs (PDF/DOCX 24h, audio 7d, images 1h), 50 MB gate (`DOC_INTEL_MAX_BYTES`), 30s thread timeout (`DOC_INTEL_TIMEOUT_S`). `warden/document_intel/api.py` — 6 endpoints at `/document-intel/*`. `FilterRequest` now has `file_base64: str | None` + `file_filename: str = "upload.bin"` — filter hook converts file to Markdown before pipeline (fail-open). `warden/communities/doc_converter.py` + `warden/api/doc_converter.py` — community API at `/doc-converter`. `POST /obsidian/scan-attachment`, `POST /prompt-library/from-file`. SOVA tool #50 `scan_document`. Prometheus counters: `warden_doc_intel_convert_total{ext,data_class}`, `warden_doc_intel_convert_errors_total{ext,error}`, `warden_doc_intel_cache_hits_total`. Portal `/doc-scanner/` page + server proxy (`portal/src/app/api/doc-scanner/route.ts`). Static Astro page `site/src/pages/cyber-security/document-intelligence.astro`. markitdown import wrapped in `except Exception` (not just `ImportError`) to handle Windows dotenv Unicode issue.
- **Real-time Compliance Dashboard (CP-30, v5.5)**: `warden/compliance/models.py` — `Gap`, `FrameworkScore`, `ComplianceReport` dataclasses. `warden/compliance/posture_service.py` — `CompliancePostureService` with 19 controls across GDPR(6)/SOC2(5)/ISO27001(4)/HIPAA(4); all checks fail-safe (try/except → LOW gap if unavailable). Redis cache key `compliance:posture:{tenant_id}` (TTL `COMPLIANCE_CACHE_TTL`, default 300s); publishes to `compliance:events` on recompute. New endpoints in `warden/api/compliance_report.py`: `GET /compliance/posture/gaps`, `GET /compliance/posture/{framework}`, `POST /compliance/posture/recalculate`, `WebSocket /compliance/ws` (30s push loop). SOVA tool #51 `get_compliance_report` + tool #52 `remediate_gap`. Portal `/compliance/` self-service page + server proxy (`portal/src/app/api/compliance/route.ts`). Streamlit `21_Compliance_Dashboard.py` — 5-tab gap manager. 28 compliance tests (16 CP-25 + 12 CP-30), all green.
- **Application Factory (v7.2)**: `warden/app_factory.py` — `RouterSpec` dataclass + `register_router_safe()` catches `Exception` (not just `ImportError`) so a broken sub-router init can never crash the security pipeline. `register_staff_routers()` wraps `warden/api/staff.py`, `warden/api/staff_agents.py`, `warden/api/voice.py`. `OPTIONAL_ROUTERS` holds 30+ entries for gradual migration. `warden/main.py` calls `register_staff_routers(app)` instead of inline try/except.
- **Shadow Agentic Container / SAC (FE-52, v7.8)**: `warden/sac/guard.py` — the "Inner Warden" execution guard. `screen_and_emit(agent_id, tenant_id, tool_name, tool_input, url_sensitive)` is called at the tool-dispatch chokepoint. **Enforcement split (critical): security decisions fail-CLOSED, telemetry fail-OPEN.** URL screening blocks any `http(s)` URL in the tool input that `net_guard.is_public_url` rejects (SSRF/exfil) → returns `{"error":"blocked_by_sac_guard",...}` instead of dispatching; secret-path denylist (`.ssh`/`.env`/`.git/config`/`../`) only WARNS. It emits the first-ever GSAM `Observation` (metadata-only — never tool-input text). Wired into `warden/agent/tools.py::traced_dispatch` (SOVA, `_URL_SENSITIVE_TOOLS`) and `warden/staff/dispatcher.py::staff_dispatch` (staff-native tools). **Do NOT add a private-IP block inside `BrowserSandbox.navigate`** — it also serves trusted internal visual-patrol of `localhost:8001`/`PATROL_URLS`; screen untrusted agent URLs at the dispatch boundary instead. `warden/gsam/jit_lease.py` — Hermes JIT credential lease on the existing `gsam_leases` DDL, mirrors `protocols/acp/token_vault.py`: HMAC over `lease_id|agent_id|tenant_id|scope|expires_at`, **fail-CLOSED** via `resolve_key("GSAM_LEASE_SECRET", purpose="gsam_lease")` (API maps `InsecureKeyError`→503), **single-use** via atomic `UPDATE … WHERE used_at=''`, **issue response never contains a secret** — only redeem returns a scope-bound HMAC-derived capability (`gsam_cap_…`), once. Router `warden/gsam/api.py` mounted at `/gsam` in `main.py` (next to shadow_ai). Non-goals (not built, see `docs/sac-architecture.md`): kernel eBPF, Kata/QEMU, COW speculative execution, ZK-audit, AMM resource market.
- **GSAM downstream (Phase 1, v7.8)**: `warden/gsam/rollup.py` is registered as a `collector.register_sink()` at `main.py` startup — it folds every flushed observation batch into `gsam_agent_stats` (hourly upsert) and updates `gsam_drift_baselines`. **Drift = EWMA of total-variation distance** between the agent's `payload_kind` frequency vector and its baseline (`warden/gsam/drift.py`); the baseline update is **poisoning-gated** (frozen while `drift ≥ gsam_drift_quarantine_threshold`, mirroring the CPT 25% gate). On threshold breach the agent is quarantined (`warden/gsam/quarantine.py` — Redis flag `gsam:quarantine:{agent_id}` + in-proc TTL fallback); `staff_dispatch` enforces it as an **additive** gate AFTER the boundary check (never weakens STAFF-01/02). Read APIs `GET /gsam/heatmap|agents/{id}/stats|compliance/score` and the `gsam_agent_stats` semantic model read the **rollup, never ClickHouse**. `anti_inflation_clamp` requires ≥2 distinct counterpart contracts before a trust gain applies.
- **Unit Economics Tracker (v7.2)**: `warden/staff/economics.py` — `TokenCostTracker` (SQLite `staff_action_costs`) records per-action LLM cost (Haiku $0.80/$4.00, Sonnet $3.00/$15.00, Opus $15.00/$75.00 per MTok). `StaffAgentRunner.run()` calls `_record_cost()` (fail-open) on every return path. `GET /staff/agents/economics/report` + `GET /staff/agents/economics/alerts`.
- **Agent-to-Agent Protocol (v7.2)**: `warden/staff/a2a.py` — `A2ARouter` issues HMAC-SHA256 call tokens (`caller:target:tool:ts`), enforces an `ALLOWED_ROUTES` frozenset whitelist, and writes a SQLite audit trail of every cross-agent call. `GET /staff/agents/a2a/audit`.
- **Structured JSON Logging (v7.2)**: `warden/staff/structured_log.py` — `emit()` writes fixed-schema JSON lines to the `warden.staff` logger (`agent_id, tenant_id, tool_name, model, input_tokens, output_tokens, cost_usd, latency_ms, status, detail`). `AgentSpan` is a stateful context object wired into `StaffAgentRunner.run()` covering `agent_start`/`tool_call`/`tool_result`/`agent_end`/`agent_error`.
- **Security Contract Tests (v7.2)**: `warden/tests/test_contract_security.py` — 52 tests expressing business invariants (not coverage proxies) across SecretRedactor, SemanticGuard, TopologicalGatekeeper, ObfuscationDecoder, MaskingEngine. Use real module APIs: `SecretRedactor().redact().text`, `SemanticGuard().analyse().risk_level`, `scan().is_noise`, `decode().decoded_extra`, `engine.unmask(masked.masked, masked.session_id)`.

## Code Style

- Python 3.11+ features allowed (match/case, `X | Y` union types, etc.)
- Ruff: `line-length=100`, select `E,F,W,I,N,UP,B,C4,SIM`, ignore `E501,B008`
- No docstrings or type annotations required on code you didn't change
- Pytest markers: `adversarial`, `slow`, `integration`
- Coverage omits: dashboard, auth UI, SIEM, LangChain callback, browser sandbox, OpenAI proxy (require live external services)

## CI Pipeline

Three jobs: `test` (matrix 3.11/3.12), `lint`, `docker-build`.

- **Coverage gate**: ≥75% (`--cov-fail-under=75`), currently ~74% (post-security-fix additions)
- **Adversarial tests**: informational (`|| true`), don't block merges
- **Mutation testing**: mutmut on `secret_redactor.py` + `semantic_guard.py`, threshold 20 surviving mutants
- **Docker smoke**: Phase 1 (import test, no model) + Phase 2 (runtime /health check with model cache)
- **ML model cache**: `actions/cache` with key `warden-model-all-minilm-l6-v2-v1` at `/tmp/warden-model-cache`
