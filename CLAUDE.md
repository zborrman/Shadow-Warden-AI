# CLAUDE.md — Shadow Warden AI

## Project Overview

Shadow Warden AI is a self-contained, GDPR-compliant AI security gateway. It sits in front of every AI request, blocking jailbreak attempts, stripping secrets/PII, and self-improving via Claude Opus — all without sending sensitive data to third parties.

**Version:** 0.4.0 · **License:** Proprietary · **Language:** Python 3.11+

## Architecture

```
POST /filter → ObfuscationDecoder (base64/hex/ROT13/homoglyphs)
                → SecretRedactor (regex)
                → SemanticGuard (rules)
                → SemanticBrain (MiniLM ML)
                → Decision
                    ↓
    EvolutionEngine (background, Claude Opus) ← HIGH/BLOCK
                ↓ add_examples() hot-reload
    _brain_guard corpus
                ↓
    event_logger → data/logs.json → Streamlit dashboard (:8501)
```

9 Docker services: `proxy` (80/443), `warden` (8001), `app` (8000), `analytics` (8002), `dashboard` (8501), `postgres`, `redis`, `prometheus`, `grafana` (3000).

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
| `warden/brain/semantic.py` | ML jailbreak detector (all-MiniLM-L6-v2, `@lru_cache` singleton, ThreadPoolExecutor) |
| `warden/brain/evolve.py` | Claude Opus auto-rule generation (streaming + adaptive thinking + corpus poisoning protection) |
| `warden/obfuscation.py` | Obfuscation decoder pre-filter (base64, hex, ROT13, unicode homoglyphs) |
| `warden/secret_redactor.py` | 15 PII/secret regex patterns (incl. anthropic, huggingface keys) |
| `warden/semantic_guard.py` | Rule-based semantic analyser, compound risk escalation (3+ MEDIUM → HIGH) |
| `warden/schemas.py` | Pydantic models (`FilterRequest` with `tenant_id`, `FilterResponse` with `processing_ms`) |
| `warden/cache.py` | Redis SHA-256 content hash cache (5-min TTL, fail-open) |
| `warden/auth_guard.py` | Per-tenant API keys (JSON multi-key + SHA-256 hash lookup), constant-time compare |
| `warden/openai_proxy.py` | OpenAI-compatible `/v1/chat/completions` proxy with filter-before-forward |
| `warden/alerting.py` | Slack + PagerDuty real-time alerts on HIGH/BLOCK |
| `warden/analytics/logger.py` | NDJSON logger + GDPR helpers (`purge_before`, `read_by_request_id`) |
| `warden/analytics/dashboard.py` | Streamlit security dashboard (reads logs.json directly) |
| `warden/analytics/siem.py` | Splunk HEC + Elastic ECS SIEM integration |
| `warden/integrations/langchain_callback.py` | LangChain duck-typed callback (`WardenCallback`) |
| `warden/tools/browser.py` | Playwright headless Chromium sandbox (`Context7Manager`) |
| `warden/Dockerfile` | Playwright MCR base + CPU-only torch (non-root user UID/GID 10001) |
| `docker-compose.yml` | Full orchestration with healthchecks + resource limits |
| `grafana/provisioning/alerting/warden_alerts.yml` | P99 latency + 5xx error rate Grafana alerts |
| `.github/workflows/ci.yml` | Test matrix (3.11/3.12) + lint + Docker smoke + mutation testing |

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

## Code Style

- Python 3.11+ features allowed (match/case, `X | Y` union types, etc.)
- Ruff: `line-length=100`, select `E,F,W,I,N,UP,B,C4,SIM`, ignore `E501,B008`
- No docstrings or type annotations required on code you didn't change
- Pytest markers: `adversarial`, `slow`, `integration`
- Coverage omits: dashboard, auth UI, SIEM, LangChain callback, browser sandbox, OpenAI proxy (require live external services)

## CI Pipeline

Three jobs: `test` (matrix 3.11/3.12), `lint`, `docker-build`.

- **Coverage gate**: ≥75% (`--cov-fail-under=75`), currently ~86%
- **Adversarial tests**: informational (`|| true`), don't block merges
- **Mutation testing**: mutmut on `secret_redactor.py` + `semantic_guard.py`, threshold 20 surviving mutants
- **Docker smoke**: Phase 1 (import test, no model) + Phase 2 (runtime /health check with model cache)
- **ML model cache**: `actions/cache` with key `warden-model-all-minilm-l6-v2-v1` at `/tmp/warden-model-cache`
