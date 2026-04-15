# CLAUDE.md — Shadow Warden AI

## Response Style
- **Keep responses under 100 words.** Code and tool calls don't count — only prose.
- No summaries after completing tasks. No filler phrases.

## Project Overview

Shadow Warden AI is a self-contained, GDPR-compliant AI security gateway. It sits in front of every AI request, blocking jailbreak attempts, stripping secrets/PII, and self-improving via Claude Opus — all without sending sensitive data to third parties.

**Version:** 3.2 · **License:** Proprietary · **Language:** Python 3.11+

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
    POST /agent/sova/task/{job} → trigger scheduled job manually
    ARQ cron:
        sova_morning_brief  08:00 UTC daily
        sova_threat_sync    every 6h (00:05, 06:05, 12:05, 18:05)
        sova_rotation_check 02:00 UTC daily
        sova_sla_report     Monday 09:00 UTC
        sova_upgrade_scan   Sunday 10:00 UTC
        sova_corpus_watchdog every 30 min (no LLM — direct health check)
    Memory: Redis sova:conv:{session_id} JSON (6h TTL, 20-turn cap)
    Tools: 27 tool handlers → http://localhost:8001 X-API-Key calls
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
| `warden/api/monitor.py` | Uptime Monitor REST API — `/monitors/*` CRUD + `/status` + `/uptime` + `/history` |
| `warden/workers/probe_worker.py` | Async probe scheduler — HTTP/SSL/DNS/TCP checks, TimescaleDB write, Redis Pub/Sub publish |
| `warden/db/migrations/versions/0010_uptime_monitors.py` | TimescaleDB migration — hypertable, continuous aggregate, retention + compression policies |
| `warden/phishing_guard.py` | PhishGuard + SE-Arbiter — URL phishing + social engineering detection (SEC-GAP-002 fixed) |
| `warden/agent/sova.py` | SOVA core — Claude Opus 4.6 agentic loop, prompt caching, tool dispatch, Redis memory |
| `warden/agent/tools.py` | 27 tool handlers + Anthropic schema defs + TOOL_HANDLERS dispatch table |
| `warden/agent/memory.py` | Redis-backed conversation memory (sova:conv:{sid}, 6h TTL, 20-turn cap) |
| `warden/agent/scheduler.py` | 6 ARQ job functions for SOVA scheduled tasks |
| `warden/api/agent.py` | FastAPI router `/agent/sova` — query, clear session, trigger task |
| `warden/testing/context.py` | SWFE FakeContext — unified fake activation via mock.patch, X-Simulation-ID isolation |
| `warden/testing/fakes/` | SWFE fake layer — FakeAnthropicClient, FakeNvidiaClient, FakeS3Storage, FakeEvolutionEngine |
| `warden/testing/scenarios/` | SWFE Scenario DSL — ScenarioRunner, ScenarioStep, build_core_scenarios(), YAML loader |
| `docs/sla.md` | Formal SLA — Pro 99.9% / Enterprise 99.95% uptime, P99 < 50ms, incident response, credits |

## Build & Test Commands

```bash
# Start all services
docker-compose up --build

# Run tests locally (CPU-only torch required)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"

# Full coverage gate
pytest warden/tests/ --tb=short -m "not adversarial" --cov=warden --cov-fail-under=75

# Lint
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional

# Mutation testing (Linux/WSL/CI only — not supported on native Windows)
mutmut run --no-progress
```

## Environment Variables (test context)

Tests require these env vars (set in `warden/tests/conftest.py`):

```
ANTHROPIC_API_KEY=""           # disables Evolution Engine
WARDEN_API_KEY=""              # disables auth
SEMANTIC_THRESHOLD="0.72"
LOGS_PATH="/tmp/warden_test_logs.json"
DYNAMIC_RULES_PATH="/tmp/warden_test_dynamic_rules.json"
STRICT_MODE="false"
REDIS_URL="memory://"          # in-memory limiter; no Redis needed
MODEL_CACHE_DIR="/tmp/warden_test_models"  # default /warden/models is Docker-only
```

## Design Constraints

- **CPU-only torch**: Two-step Dockerfile pip install (`--index-url` prevents CUDA pull). Target hardware is standard dev machines, not GPU servers.
- **Playwright base image**: `mcr.microsoft.com/playwright/python:v1.49.0-noble` — do NOT switch to `python:3.x-slim` (Playwright requires OS-level browser deps from MCR). Non-root user uses GID/UID 10001 (1001 is taken by the noble base image).
- **GDPR**: Content is NEVER logged — only metadata (type, length, timing). This is a hard requirement.
- **Atomic writes**: `tempfile` + `os.replace()` for `logs.json` and `dynamic_rules.json` to prevent corruption.
- **Evolution Loop optional**: Runs without `ANTHROPIC_API_KEY` (air-gapped mode). All detection still works.
- **Model loading**: `@lru_cache(maxsize=1)` singleton in `brain/semantic.py`. Pre-warmed in FastAPI `lifespan()`. Uses `asyncio.get_running_loop()` (not deprecated `get_event_loop()`).
- **Entrypoint pass-through**: `entrypoint.sh` checks `$# > 0` — if args are passed (e.g. `docker run ... python3 script.py`), exec them as wardenuser instead of starting uvicorn. Required for `[1b/4]` ONNX export step in CI deploy.
- **DataPoisoningGuard model access**: uses `_load_model()` from `warden.brain.semantic` (module-level `@lru_cache` singleton) — NOT `self._guard._model` (SemanticGuard has no such attribute).
- **Corpus snapshot atomicity**: `tempfile.mkstemp()` per call in `_save_snapshot_sync()` — prevents ENOENT race when two uvicorn workers call `save_snapshot_async()` concurrently.
- **Intel Bridge optional**: `INTEL_OPS_ENABLED=true` activates background ArXiv → Evolution sync. `INTEL_BRIDGE_INTERVAL_HRS` (default 6). Requires `ANTHROPIC_API_KEY` for synthesis; fail-open otherwise.
- **SOVA agent optional**: requires `ANTHROPIC_API_KEY`. Router mounted at startup with try/except — missing anthropic package skips silently. Session memory fails open (no Redis = no history).
- **Named Docker volume `warden-models`**: replaces bind-mount `./warden/models`. Persists ONNX model across rebuilds and git operations. ONNX export uses `--name warden-onnx-export` + skip-if-running guard to prevent OOM from duplicate containers.
- **`warden-models` migration**: copy from host path via `docker run --rm -v warden-models:/warden/models alpine sh -c "cp -r /src/. /warden/models/"` before switching compose mount.

## Code Style

- Python 3.11+ features allowed (match/case, `X | Y` union types, etc.)
- Ruff: `line-length=100`, select `E,F,W,I,N,UP,B,C4,SIM`, ignore `E501,B008`
- No docstrings or type annotations required on code you didn't change
- Pytest markers: `adversarial`, `slow`, `integration`
- Coverage omits: dashboard, auth UI, SIEM, LangChain callback, browser sandbox, OpenAI proxy (require live external services)

## CI Pipeline

Three jobs: `test` (matrix 3.11/3.12), `lint`, `docker-build`.

- **Coverage gate**: ≥75% (`--cov-fail-under=75`), currently ~75.2%
- **Adversarial tests**: informational (`|| true`), don't block merges
- **Mutation testing**: mutmut on `secret_redactor.py` + `semantic_guard.py`, threshold 20 surviving mutants
- **Docker smoke**: Phase 1 (import test, no model) + Phase 2 (runtime /health check with model cache)
- **ML model cache**: `actions/cache` with key `warden-model-all-minilm-l6-v2-v1` at `/tmp/warden-model-cache`
