# CLAUDE.md — Shadow Warden AI

## Response Style
- **Keep responses under 100 words.** Code and tool calls don't count — only prose.
- No summaries after completing tasks. No filler phrases.

## Project Overview

Shadow Warden AI is a self-contained, GDPR-compliant AI security gateway. It sits in front of every AI request, blocking jailbreak attempts, stripping secrets/PII, and self-improving via Claude Opus — all without sending sensitive data to third parties.

**Version:** 4.19 · **License:** Proprietary · **Language:** Python 3.11+

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
| `docker/Caddyfile` | Caddy v2 vhosts — api/app/analytics/landing/dash.shadow-warden-ai.com |
| `warden/testing/scenarios/` | SWFE Scenario DSL — ScenarioRunner, ScenarioStep, build_core_scenarios(), YAML loader |
| `docs/sla.md` | Formal SLA — Pro 99.9% / Enterprise 99.95% uptime, P99 < 50ms, incident response, credits |

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
NEXT_PUBLIC_JAEGER_URL=http://91.98.234.160:16686
```

## Design Constraints

- **CPU-only torch**: Two-step Dockerfile pip install (`--index-url` prevents CUDA pull). Target hardware is standard dev machines, not GPU servers.
- **Playwright base image**: `mcr.microsoft.com/playwright/python:v1.49.0-noble` — do NOT switch to `python:3.x-slim` (Playwright requires OS-level browser deps from MCR). Non-root user uses GID/UID 10001 (1001 is taken by the noble base image).
- **GDPR**: Content is NEVER logged — only metadata (type, length, timing). This is a hard requirement.
- **Atomic writes**: `tempfile` + `os.replace()` for `logs.json` and `dynamic_rules.json` to prevent corruption.
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
