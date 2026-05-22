# Shadow Warden AI — Project Structure

**Version 4.30 · Updated 2026-05-22**

## Top-Level Layout

```
shadow-warden-ai/
├── warden/              # Core Python gateway package (pip install .)
├── analytics/           # Streamlit analytics dashboard service
├── admin/               # Streamlit MSP admin UI service
├── dashboard/           # Next.js 14.2 SOC dashboard (port 3002)
├── portal/              # Next.js tenant portal service
├── landing/             # Astro marketing site
├── site/                # MkDocs documentation site
├── app/                 # Reference customer integration (docs-as-code)
├── worker/              # Cloudflare Workers (TypeScript, deployed separately)
├── obsidian-plugin/     # TypeScript Obsidian plugin
├── browser-extension/   # Browser security extension
├── vscode-extension/    # VS Code extension
├── sdk/                 # Multi-language SDKs (Go, Python, TypeScript)
├── docker/              # Caddyfile reverse proxy config
├── helm/                # Kubernetes Helm charts
├── k8s/                 # Kubernetes raw manifests
├── terraform/           # IaC (AWS, Azure)
├── grafana/             # Grafana dashboards + provisioning
├── k6/                  # k6 load test specs
├── scripts/             # Utility scripts (gen_certs, load tests, chaos)
├── data/                # Runtime data (signatures, configs — gitignored)
├── docs/                # Architecture and API documentation
├── legal/               # License and terms
└── docker-compose.yml   # Full 21-service orchestration
```

---

## `warden/` Package Architecture

The gateway package is organized into **four facade packages** (new canonical paths)
and **existing domain packages**. All legacy flat-module imports remain valid.

### Facade Packages (new in v4.30)

These packages provide a stable public API surface and group related flat modules:

```
warden/
├── guards/              # All detection and blocking modules
│   __init__.py          → SemanticGuard, HoneyEngine, ToolCallGuard,
│                          SessionGuard, topology_scan, arbitrate, ...
│
├── redaction/           # PII/secret/content redaction modules
│   __init__.py          → SecretRedactor, decode_obfuscation, get_output_sanitizer
│
├── intel/               # Threat intelligence modules
│   __init__.py          → ThreatFeedClient, ThreatStore, ThreatVault,
│                          WardenIntelBridge, WardenIntelOps, ...
│
└── core/                # Infrastructure (schemas, cache, metrics, telemetry)
    __init__.py          → FilterRequest, FilterResponse, RiskLevel,
                           Settings, AuditTrail, trace_stage, ...
```

**Import examples:**
```python
# New canonical paths (recommended for new code)
from warden.guards import SemanticGuard, topology_scan
from warden.redaction import SecretRedactor
from warden.intel import ThreatFeedClient
from warden.core import FilterRequest, RiskLevel

# Legacy paths (still valid — backward compatible)
from warden.semantic_guard import SemanticGuard
from warden.secret_redactor import SecretRedactor
```

### Domain Packages (existing)

```
warden/
├── agent/               # SOVA autonomous agent (tools, scheduler, healer, memory)
├── agentic/             # Agent action whitelist, mandate, registry
├── analytics/           # Streamlit pages + logger, SIEM, report engine
├── api/                 # 30+ FastAPI routers (one per feature)
├── auth/                # SAML + password auth
├── billing/             # Feature gates, add-ons, trial, quota middleware
├── brain/               # ML layer (semantic, hyperbolic, evolution engine, FAISS)
├── business_intelligence/ # BI analytics, predictive, benchmarking, cache (CM-39)
├── communities/         # SEP, peering, incidents, training, prompts (CM-35–38)
├── compliance/          # Compliance report engine
├── crypto/              # Post-Quantum Cryptography (PQC) — Ed25519 + ML-DSA-65
├── db/                  # SQLAlchemy models + Alembic migrations (TimescaleDB)
├── feed_server/         # Threat feed publishing server
├── financial/           # Cost allocation, budget dashboard (BL-23/24)
├── hooks/               # Event hook dispatcher
├── integrations/        # LangChain, MISP, TAXII, NeMo, Obsidian
├── masking/             # Fernet-encrypted PII masking vault
├── providers/           # LLM provider adapters (Azure, Bedrock, Vertex, NIM)
├── secrets_gov/         # Secrets governance (vault connectors, lifecycle, policy)
├── shadow_ai/           # Shadow AI discovery (18 providers, subnet probe)
├── sovereign/           # Sovereign cloud routing (8 jurisdictions, MASQUE tunnels)
├── storage/             # S3-compatible object storage (MinIO / AWS)
├── syndicates/          # Syndicate Exchange Protocol (SEP) core
├── testing/             # SWFE fake layer (FakeAnthropicClient, FakeS3, scenarios)
├── tests/               # 102-file test suite (pytest, markers: adversarial/slow/integration)
├── threat_intel/        # Threat intelligence aggregation layer
├── tools/               # Playwright browser sandbox
├── vendor_gov/          # AI Vendor Governance Register (BL-22)
├── workers/             # ARQ background workers (probe, reaper, CVE scanner)
└── xai/                 # Explainable AI (CausalChain, HTML/PDF renderer)
```

### Core Flat Modules (66 files)

Key modules that live at `warden/*.py` (not yet promoted to a subpackage):

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI gateway — lifespan, middleware, all router mounts |
| `schemas.py` | Pydantic models — FilterRequest, FilterResponse, RiskLevel |
| `semantic_guard.py` | Rule-based semantic analyser (compound risk escalation) |
| `secret_redactor.py` | 15 PII/secret regex + Shannon entropy scan |
| `topology_guard.py` | TDA Gatekeeper (n-gram → Betti numbers, < 2ms) |
| `causal_arbiter.py` | Bayesian DAG causal inference (Pearl do-calculus) |
| `obfuscation.py` | Obfuscation decoder (base64/hex/ROT13/homoglyphs, depth-3) |
| `shadow_ban.py` | Shadow Ban Engine (gaslight/delay/standard strategies) |
| `auth_guard.py` | Per-tenant API key auth (multi-key JSON, SHA-256 hash) |
| `cache.py` | Redis SHA-256 content hash cache (5-min TTL) |
| `metrics.py` | Prometheus metric singletons |
| `telemetry.py` | OTel TracerProvider + `trace_stage()` context manager |
| `alerting.py` | Slack + PagerDuty real-time alerts |
| `audit_trail.py` | Tamper-evident audit trail (SHA-256 chain) |
| `entity_risk.py` | Entity Risk Scoring (ERS) — Redis sliding window |
| `honey.py` | Honeypot engine (fake credentials, trap prompts) |
| `taint_tracker.py` | Data taint propagation tracker |
| `phishing_guard.py` | URL phishing + typosquatting detection |
| `tool_guard.py` | Agent tool call inspection |
| `worm_guard.py` | Prompt worm / replication attack detection |
| `session_guard.py` | Cross-session threat pattern detection |
| `prompt_shield.py` | Injection shield with injection-type classification |
| `output_guard.py` | Output content compliance scanner |
| `threat_vault.py` | Curated threat pattern vault |
| `threat_store.py` | Per-tenant threat event storage |
| `intel_bridge.py` | ArXiv → EvolutionEngine auto-synthesis bridge |

---

## Docker Services (21 services)

| Service | Image / Build | Port | Purpose |
|---------|--------------|------|---------|
| proxy | caddy:2-alpine | 80/443 | Reverse proxy (QUIC/H3) |
| warden | warden/Dockerfile | 8001 | Security gateway |
| arq-worker | warden/Dockerfile | — | ARQ background jobs |
| analytics | analytics/Dockerfile | 8501 | Streamlit analytics |
| admin | admin/Dockerfile | 8502 | MSP admin UI |
| portal | portal/Dockerfile | 3001 | Tenant portal |
| dashboard | dashboard/Dockerfile | 3002 | SOC Next.js dashboard |
| postgres | timescale/timescaledb | 5432 | TimescaleDB (probes + auth) |
| redis | redis:7-alpine | 6379 | Cache + pub/sub + rate limit |
| minio | minio/minio | 9000/9001 | S3-compatible evidence vault |
| prometheus | prom/prometheus | 9090 | Metrics scrape |
| grafana | grafana/grafana | 3000 | Dashboards + SLO alerts |
| jaeger | jaegertracing | 16686 | Distributed traces |
| otel-collector | otel/opentelemetry-collector | 4317 | OTel gRPC collector |
| loki | grafana/loki | 3100 | Log aggregation |
| promtail | grafana/promtail | — | Log shipping |
| redis-exporter | oliver006/redis_exporter | 9121 | Redis → Prometheus |
| postgres-exporter | prometheuscommunity/postgres_exporter | 9187 | PG → Prometheus |
| node-exporter | prom/node-exporter | 9100 | Host metrics (profile: monitoring) |
| cadvisor | gcr.io/cadvisor | 8080 | Container metrics (profile: monitoring) |
| minio-init | minio/mc | — | Bucket bootstrapper (init container) |

---

## Test Organisation

```
warden/tests/           # 102 test files — primary suite
  conftest.py           # Shared fixtures + env vars
  adversarial/          # Adversarial corpus (pytest.mark.adversarial)
  test_*.py             # Unit + integration tests
  pre_release_final_test.py  # 42KB end-to-end smoke suite

warden/business_intelligence/tests/  # BI module isolated tests (CM-39)

sdk/python/tests/       # Python SDK tests
scripts/                # Load + chaos + stress test scripts
k6/                     # k6 load test specs
```

**Test markers:**
- `adversarial` — corpus adversarial tests (informational in CI)
- `slow` — ML model load tests
- `integration` — end-to-end FastAPI tests

**Coverage gate:** ≥80% (`--cov-fail-under=80` in pyproject.toml)

---

## Install Options

```bash
# Core gateway
pip install shadow-warden-ai

# With post-quantum cryptography (liboqs)
pip install "shadow-warden-ai[pqc]"

# With OpenTelemetry tracing
pip install "shadow-warden-ai[otel]"

# With LangChain integration
pip install "shadow-warden-ai[langchain]"

# Full stack (all optional features)
pip install "shadow-warden-ai[full]"

# Development
pip install "shadow-warden-ai[dev]"
```
