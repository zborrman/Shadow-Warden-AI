# PLAN.md — Shadow Warden AI Product Roadmap

**Version 4.19 · Last updated 2026-05-07**

Product roadmap, tier feature matrix, and sprint delivery status.

---

## Delivery Blocks

### Block A — Core Gateway (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| A-01 | TopologicalGatekeeper (Betti numbers, < 2ms) | ✅ |
| A-02 | ObfuscationDecoder (base64/hex/ROT13/homoglyphs, depth-3) | ✅ |
| A-03 | SecretRedactor (15 patterns + Shannon entropy) | ✅ |
| A-04 | SemanticGuard (rule engine + compound risk) | ✅ |
| A-05 | HyperbolicBrain (MiniLM + Poincaré ball) | ✅ |
| A-06 | CausalArbiter (Bayesian DAG, do-calculus) | ✅ |
| A-07 | ERS (Redis sliding window, shadow ban ≥ 0.75) | ✅ |
| A-08 | EvolutionEngine (Claude Opus auto-rule gen, hot-reload) | ✅ |
| A-09 | Analytics + Streamlit dashboard | ✅ |
| A-10 | MinIO Evidence Vault (S3-compatible, fail-open) | ✅ |

---

### Block B — Observability & Operations (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| B-01 | PhishGuard + SE-Arbiter (URL phishing + social engineering) | ✅ |
| B-02 | Prometheus + Grafana SLO alerts (P99, 5xx, shadow ban rate) | ✅ |
| B-03 | SIEM integration (Splunk HEC + Elastic ECS) | ✅ |
| B-04 | LangChain callback (WardenCallback duck-typed) | ✅ |
| B-05 | SOVA Agent (Claude Opus 4.6, ≤10 iter, 30 tools) | ✅ |
| B-06 | ARQ cron scheduler (7 jobs) | ✅ |
| B-07 | WardenHealer (autonomous anomaly detection, LLM-free) | ✅ |
| B-08 | Uptime Monitor REST API + TimescaleDB hypertable | ✅ |
| B-09 | Financial Impact Calculator (IBM 2024 benchmarks, ROI) | ✅ |

---

### Block C — SMB Foundations (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| C-01 | SMB compose isolation (docker-compose.smb.yml) | ✅ |
| C-02 | DOCX / XLSX scanner (warden/smb/file_scan.py) | ✅ |
| C-03 | Offline Mode (9 filter layers, no external deps) | ✅ |
| C-04 | Community keypair (classical + hybrid PQC) | ✅ |
| C-05 | Email Guard (SMTP header injection + phish link + brand impersonation) | ✅ |

---

### Block D — SMB Tier Extensions (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| Q1.1 | API Key Rotation (warden/api/rotation.py) | ✅ |
| Q1.2 | Extension Risk Scoring (warden/api/extension_risk.py) | ✅ |
| Q1.3 | SMB Compliance Report PDF/JSON (warden/api/compliance_report.py) | ✅ |
| Q2.4 | Secrets Rotation Scheduler (ARQ cron, Redis warden:key_age:) | ✅ |
| Q2.5 | Agent Action Whitelist logic (warden/agentic/action_whitelist.py) | ✅ |
| Q2.6 | Agent Action Whitelist REST API (warden/api/action_whitelist.py) | ✅ |
| Q3.7 | SMB Billing Tier + Add-on gates | ✅ |
| Q3.8 | Shadow AI Dashboard for SMB | ✅ |
| Q4.10 | Knock-and-Verify invitation flow | ✅ |
| Q4.11 | STIX 2.1 Tamper-Evident Audit Chain | ✅ |
| Q4.12 | SOC Next.js Dashboard SPA | ✅ |

---

### Block E — Enterprise Pillars (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| E-01 | Post-Quantum Cryptography (HybridSigner Ed25519+ML-DSA-65, HybridKEM X25519+ML-KEM-768) | ✅ |
| E-02 | Shadow AI Governance (ShadowAIDetector, 18 providers, /24 subnet probe) | ✅ |
| E-03 | Explainable AI 2.0 (CausalChain, 9-stage DAG, HTML+PDF renderer) | ✅ |
| E-04 | Sovereign AI Cloud (8 jurisdictions, MASQUE tunnels, attestation) | ✅ |
| E-05 | MasterAgent SOC (4 sub-agents, HMAC tokens, human-in-the-loop) | ✅ |

---

### Block F — SEP Strategic Features (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| F-01 | Syndicate Exchange Protocol — UECIID codec + index | ✅ |
| F-02 | Inter-community peering (MIRROR_ONLY/REWRAP_ALLOWED/FULL_SYNC) | ✅ |
| F-03 | Knock-and-Verify invitations (Redis 72h TTL, one-time token) | ✅ |
| F-04 | Causal Transfer Guard (exfiltration P≥0.70 block, <20ms) | ✅ |
| F-05 | Sovereign Data Pods (per-jurisdiction MinIO routing, Fernet keys) | ✅ |
| F-06 | STIX 2.1 Audit Chain (SHA-256 prev_hash, OASIS-compatible JSONL) | ✅ |

---

### Block G — Secrets Governance (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| G-01 | Vault connectors: AWS SM / Azure KV / HashiCorp / GCP SM / env (metadata-only) | ✅ |
| G-02 | SQLite-backed secrets inventory — risk scoring, auto-retire, expiry tracking | ✅ |
| G-03 | Policy Engine — per-tenant governance rules, 7 violation types, compliance score | ✅ |
| G-04 | Lifecycle Manager — expiry alerts, auto-retire, rotation scheduling | ✅ |
| G-05 | FastAPI router `/secrets/*` — 14 endpoints | ✅ |
| G-06 | Feature gate — `secrets_governance` (Community Business+) + `secrets_vault` add-on $12/mo | ✅ |
| G-07 | Streamlit dashboard — 6-tab secrets governance UI | ✅ |
| G-08 | 48 tests in test_secrets_governance.py | ✅ |

---

### Block H — Obsidian Business Community Integration (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| H-01 | `warden/integrations/obsidian/note_scanner.py` — scan_note(), data classification | ✅ |
| H-02 | `warden/api/obsidian.py` — 6 endpoints: /scan, /share, /feed, /ai-filter, /reputation, /stats | ✅ |
| H-03 | `obsidian-plugin/main.ts` v4.10 — TypeScript plugin: ribbon, 5 commands, auto-scan | ✅ |
| H-04 | 25 tests in test_obsidian_integration.py (6 classes) | ✅ |

---

### Block I — OTel Distributed Tracing (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| I-01 | `warden/telemetry.py` — TracerProvider, gRPC exporter, `trace_stage()` context manager | ✅ |
| I-02 | Per-layer spans in all 9 pipeline stages (topology → ers) | ✅ |
| I-03 | Per-module inner spans in topology_guard, obfuscation, secret_redactor, semantic_guard, brain/semantic, phishing_guard | ✅ |
| I-04 | OTel Collector service (otel/opentelemetry-collector-contrib:0.103.1) | ✅ |
| I-05 | Jaeger 1.58 (OTLP gRPC → collector → Jaeger) | ✅ |
| I-06 | Helm chart values: `otel.*` + `otelCollector.*` blocks | ✅ |
| I-07 | py-spy profiling script + k6 load harness (`scripts/profile_under_load.sh`) | ✅ |
| I-08 | Redoc static docs page (docs/redoc.html) at docs.shadow-warden-ai.com | ✅ |

---

### Block J — SOC Next.js Dashboard (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| J-01 | `dashboard/` — Next.js 14.2 App Router, TanStack Query, Recharts, Tailwind dark theme | ✅ |
| J-02 | SOC Overview page — KPI cards, 24h area chart, verdict pie, threat breakdown, ROI + compliance | ✅ |
| J-03 | Events table — filter by verdict/search, pagination, click-through to detail | ✅ |
| J-04 | Event detail page — 9-stage pipeline timeline with scores | ✅ |
| J-05 | Threats page — bar chart, radar chart, 14-day stacked trend | ✅ |
| J-06 | Filter Sandbox — live `/filter` test harness with example prompts | ✅ |
| J-07 | Platform Metrics — Grafana iframe panel grid | ✅ |
| J-08 | Platform Traces — Jaeger iframe embed | ✅ |
| J-09 | `docker-compose.yml` — `dashboard` service (port 3002) | ✅ |
| J-10 | Caddyfile — `dash.shadow-warden-ai.com` vhost | ✅ |

---

### Block K — CI / Lint / Type Hardening (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| K-01 | ruff: 7 errors fixed (F401, I001×3, F541, UP037, I001) | ✅ |
| K-02 | mypy: `_sp: object → Any` in `secret_redactor._redact_inner` | ✅ |
| K-03 | CI: `--no-cache` pre-build for admin + arq-worker (corrupted layer guard) | ✅ |
| K-04 | admin/Dockerfile: `python3 -m pip` (PATH-resilient) | ✅ |
| K-05 | probe_worker: `User-Agent` header added (Cloudflare Bot Fight bypass) | ✅ |

---

### Block L — Public Community Intelligence (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| L-01 | SOVA community tools #38–40 (`search_community_feed`, `publish_to_community`, `get_community_recommendations`) | ✅ |
| L-02 | `sova_threat_sync` cross-reference community feed (4 keywords + Slack alert) | ✅ |
| L-03 | `POST /agent/sova/community/lookup` endpoint + models | ✅ |
| L-04 | `GET /public/community` unauthenticated GDPR-safe stats endpoint | ✅ |
| L-05 | `shadow-warden-ai.com/community` Storytelling Dashboard (Astro, SVG chart, live feed) | ✅ |
| L-06 | Community Defense Widget in SOC dashboard Overview page | ✅ |
| L-07 | Community Recommendations block in Event Detail page (blocked events) | ✅ |

---

### Block M — Collective Immunity & ISAC (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| M-01 | `warden/communities/reputation.py` — SQLite points ledger + badge ladder | ✅ |
| M-02 | `GET /public/leaderboard` — anonymised top-10 (no tenant_id) | ✅ |
| M-03 | Reputation points awarded automatically on `publish_to_community` tool | ✅ |
| M-04 | `warden/integrations/misp.py` — MISP REST → EvolutionEngine synthesis | ✅ |
| M-05 | SOVA tool #41 `sync_misp_feed` + `POST /agent/misp/sync` | ✅ |
| M-06 | `POST /agent/sova/community/apply/{ueciid}` — auto-apply with human-in-the-loop | ✅ |
| M-07 | `GET /public/incident/{ueciid}` — anonymised public incident card + XAI chain | ✅ |
| M-08 | `shadow-warden-ai.com/incident?id=SEP-xxx` — public incident Astro page | ✅ |
| M-09 | SOVA tool #42 `get_reputation` | ✅ |
| M-10 | Leaderboard section on community.astro (120s auto-refresh) | ✅ |

---

### Block N — SOVA + Obsidian + Slack Unification (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| N-01 | `warden/api/slack_commands.py` — Slack slash command handler (HMAC-SHA256, Block Kit, /warden scan/status/approve) | ✅ |
| N-02 | `warden/alerting.py` — `alert_obsidian_event()` Slack webhook (HIGH/BLOCK + share with UECIID) | ✅ |
| N-03 | `warden/api/obsidian.py` — `GET /obsidian/reputation` endpoint | ✅ |
| N-04 | `warden/agent/tools.py` — SOVA tools #43–45: scan_obsidian_note, get_obsidian_feed, share_obsidian_note | ✅ |
| N-05 | `warden/agent/scheduler.py` — `sova_obsidian_watchdog()` ARQ job (every 4h) | ✅ |
| N-06 | `warden/workers/settings.py` — registered sova_obsidian_watchdog cron | ✅ |
| N-07 | Lint: 6 ruff + 2 mypy errors fixed (agent.py, reputation.py, misp.py) | ✅ |

---

### Block O — Obsidian Plugin v4.18 — Sidebar + Pre-validation (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| O-01 | `WardenSidebarView` — ItemView right panel: scan result, reputation, feed, queue badge | ✅ |
| O-02 | `tagFrontmatter()` — async `processFrontMatter()` writes warden_* YAML tags | ✅ |
| O-03 | `prevalidate()` — 8 client-side regex patterns, instant PII warning before API call | ✅ |
| O-04 | `GET /obsidian/reputation` polling in sidebar (5min interval) | ✅ |
| O-05 | `styles.css` — `.warden-sidebar-*`, `.warden-pipeline-dot`, `.warden-queue-row` | ✅ |

---

### Block P — Obsidian Plugin v4.19 — Dashboard + Queue + XAI + Scheduler (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| P-01 | `buildDashboardNote()` — 5 Dataview query blocks (high-risk, scanned, distribution, flagged, clean) | ✅ |
| P-02 | `createSecurityDashboard()` — creates/opens `Warden Security Dashboard.md` | ✅ |
| P-03 | `PublishQueueItem` offline queue — `enqueueShare()`, `flushPublishQueue()`, `loadData()`/`saveData()` | ✅ |
| P-04 | Sidebar queue badge + Flush button; Settings tab queue section + Flush button | ✅ |
| P-05 | `PipelineStage` + `buildPipelineStages()` — 4-stage XAI viz derived from ScanResult | ✅ |
| P-06 | `verdictColor()` — hex mapping; modal table + sidebar mini colored dots | ✅ |
| P-07 | `scheduledScanEnabled` + `scheduledScanIntervalHours` — `startScheduledScan()` via setInterval | ✅ |
| P-08 | `manifest.json` version `1.0.0 → 4.19.0` | ✅ |
| P-09 | TypeScript compiles clean (`tsc --noEmit`) | ✅ |

---

### Block R — Billing v4.20 Enhancements (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| R-01 | `warden/billing/addons.py` — `on_prem_pack` add-on (+$29/mo, Pro+, unlocks `on_prem_deployment`) | ✅ |
| R-02 | `warden/billing/addons.py` — `community_seats` add-on (+$9/mo, stackable, +5 members/unit) | ✅ |
| R-03 | `warden/billing/addons.py` — `BUNDLE_CATALOG` + `power_user_bundle` ($29 → saves $7 vs $36) | ✅ |
| R-04 | `warden/billing/addons.py` — `grant_bundle()`, `get_seat_expansion()`, `increment_seat_units()` helpers | ✅ |
| R-05 | `warden/billing/trial.py` — NEW: 14-day Pro trial (10k req cap, no MasterAgent, Redis TTL, idempotent) | ✅ |
| R-06 | `warden/billing/feature_gate.py` — `ANNUAL_PRICING` dict (15% off: $51/$194/$703/$2541/yr) | ✅ |
| R-07 | `warden/billing/feature_gate.py` — `trial_eligible` flag per tier; `annual_pricing` in `as_dict()` | ✅ |
| R-08 | `warden/billing/router.py` — `POST /billing/trial/start`, `GET /billing/trial/status` | ✅ |
| R-09 | `warden/billing/router.py` — `GET /billing/addons/bundles`, `GET /billing/addons/bundle/{key}/checkout` | ✅ |
| R-10 | `warden/billing/router.py` — `POST /billing/community-seats/add`, `GET /billing/community-seats` | ✅ |
| R-11 | `warden/billing/router.py` — annual pricing in `/billing/tiers` response | ✅ |
| R-12 | `dashboard/src/components/ui/pricing-calculator.tsx` — interactive tier+addon+bundle calculator with annual toggle | ✅ |
| R-13 | `dashboard/src/components/ui/usage-progress.tsx` — quota progress bar, 80% upgrade CTA, 60s auto-refresh | ✅ |

---

## Next Sprint — Block Q (Planned)

| ID | Feature | Priority |
|----|---------|----------|
| Q-01 | DNS A record `dash.shadow-warden-ai.com → 91.98.234.160` (Cloudflare) | P0 |
| Q-02 | Analytics API live endpoints wired into dashboard (replace mock data) | P1 |
| Q-03 | `TRUSTED_ENTRY +3` reputation cron — 30-day no-report entries auto-awarded | P2 |
| Q-04 | `SEARCH_HIT +1` reputation — award on `search_community_feed` result match | P2 |
| Q-05 | MISP syslog bridge — route MISP ZMQ feed into Shadow Warden syslog sink | P3 |

---

## Production Infrastructure

| Component | URL / Location | Status |
|-----------|---------------|--------|
| API Gateway | `https://api.shadow-warden-ai.com` | ✅ Live |
| Tenant Portal | `https://app.shadow-warden-ai.com` | ✅ Live |
| Landing Page | `https://shadow-warden-ai.com` | ✅ Live |
| Redoc Docs | `https://docs.shadow-warden-ai.com` | ✅ Live |
| Community Dashboard | `https://shadow-warden-ai.com/community` | ✅ Live (Vercel) |
| Public Incident Page | `https://shadow-warden-ai.com/incident` | ✅ Live (Vercel) |
| SOC Dashboard | `https://dash.shadow-warden-ai.com` | ⚠️ Needs DNS A record |
| Grafana | `http://91.98.234.160:3000` | ✅ Live |
| Jaeger UI | `http://91.98.234.160:16686` | ✅ Live |
| Server | Hetzner Ubuntu VPS — `91.98.234.160` | ✅ Live |
