# Shadow Warden AI

**The AI Security Gateway for the US/EU Marketplace**

Shadow Warden AI is a self-contained, GDPR-compliant security layer that sits in front of every AI request in your application. It blocks jailbreak attempts, strips secrets and PII, shadow-bans attackers, enforces agentic safety guardrails, and self-improves — all without sending sensitive data to third parties.

**Version:** 1.8 · **License:** Proprietary · **Language:** Python 3.11+

---

## What's New in v1.8

| Feature | Description |
|---------|-------------|
| **Shadow Ban** | Attackers above the critical ERS threshold receive `allowed=true` with a plausible fake response. Real LLM never called. No feedback loop. 100% inference cost saved for flagged entities. |
| **Entity Risk Scoring (ERS)** | Redis sliding-window reputation per `tenant+IP`. Four weighted event counters (block, obfuscation, honeytrap, evolution). Escalates to shadow ban at `score ≥ 0.75`. |
| **Zero-Trust Agent Sandbox** | Every agent registers a capability manifest. Tool calls are authorized before execution. Kill-switch API revokes sessions instantly. |
| **Evidence Vault** | Per-session SHA-256 signed evidence bundles. Sign-last pattern — one byte changed anywhere = verification failure. Built for litigation and SOC 2 management assertions. |
| **Multimodal Guard** | CLIP (image jailbreaks) + Whisper+FFT (audio including ultrasonic steganography). Runs in parallel — minimal latency impact. |
| **ThreatVault 1,300+** | Curated attack signature library grows automatically via the Evolution Engine. Cross-region sync capable. |
| **WardenDoctor** | Production diagnostics & benchmarking CLI. Phase 1 health checks, Phase 2 text benchmark, Phase 3 multimodal benchmark. CI/CD JSON output. |
| **30/30 Integration Suite** | Five-level pre-release test suite (SMOKE → Compliance). All 30 tests passing before every release. |

---

## Architecture

```
POST /filter
  │
  ├─ [0] Auth & Rate-Limit Gate         per-tenant API keys, 60 req/min Redis window
  ├─ [1] Redis Content-Hash Cache       5-min TTL, 0ms ML overhead on hit
  ├─ [2] Obfuscation Decoder            base64 / hex / ROT13 / Unicode homoglyphs
  ├─ [3] Secret Redactor                15 regex patterns incl. API keys, credit cards
  ├─ [4] Semantic Guard (rules)         compound risk escalation (3+ MEDIUM → HIGH)
  ├─ [5] Semantic Brain (ML)            all-MiniLM-L6-v2 cosine similarity
  ├─ [6] Multimodal Guard               CLIP (images) + Whisper+FFT (audio, ultrasonic)
  ├─ [7] Entity Risk Scoring (ERS)      Redis sliding window → shadow ban at score ≥ 0.75
  └─ [8] Decision + Event Logger        NDJSON metadata, GDPR-safe, Prometheus metrics
             │
             ├─► EvolutionEngine (async background)    Claude Opus auto-rule synthesis
             └─► Zero-Trust Sandbox (agent calls)      capability manifests + kill-switch
```

Nine Docker services: `proxy` (80/443), `warden` (8001), `app` (8000), `analytics` (8002), `dashboard` (8501), `postgres`, `redis`, `prometheus`, `grafana` (3000).

For the full stage-by-stage breakdown with latency budgets, see [docs/pipeline-anatomy.md](docs/pipeline-anatomy.md).

---

## How to Install

### Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker Desktop | 24.x |
| Docker Compose | v2.x |
| RAM | 4 GB (8 GB recommended) |
| Disk | 5 GB free |

### 1. Clone

```bash
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI
```

### 2. Configure

```bash
cp .env.example .env
```

Key variables in `.env`:

```bash
# Required
SECRET_KEY=<random 32-byte hex>
POSTGRES_PASS=<strong password>
WARDEN_API_KEY=<your api key>

# Optional — enables Evolution Engine (Claude Opus auto-rule generation)
ANTHROPIC_API_KEY=sk-ant-...

# Optional — enables HuggingFace model downloads (CLIP, Whisper)
HF_TOKEN=hf_...

# Optional — Slack/PagerDuty alerts on HIGH/BLOCK events
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_ROUTING_KEY=...
```

### 3. Build and start

```bash
docker compose up --build
```

First run downloads PyTorch CPU wheels (~200 MB) and `all-MiniLM-L6-v2` (~80 MB). Both are cached — subsequent starts are fast.

### 4. Verify

```bash
python scripts/warden_doctor.py --url http://localhost:80 --key $WARDEN_API_KEY
```

```
Shadow Warden AI — Production Diagnostics
==========================================
Phase 1 — Health
  Gateway        PASS   (31ms)
  Redis          PASS   (latency 0.4ms)
  Circuit Breaker PASS  (closed)
  Evolution      PASS   (engine active)
  Throughput     PASS   (60 req/min)

Phase 2 — Text Benchmark (n=20)
  Clean requests  PASS   P50=5.3ms  P99=7.2ms
  Attack requests PASS   P50=5.3ms  P99=7.2ms

All checks: 7/7 PASS
```

### 5. First request

```bash
curl -X POST http://localhost:80/filter \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, how are you?"}'
```

```json
{
  "allowed": true,
  "risk_level": "LOW",
  "filtered_content": "Hello, how are you?",
  "secrets_found": [],
  "semantic_flags": [],
  "processing_ms": {"total": 5.3, "ml": 4.1, "rules": 0.8}
}
```

### 6. Stop

```bash
docker compose down        # stop, keep volumes
docker compose down -v     # stop + wipe data
```

---

## Shadow Ban

Traditional blocking tells attackers exactly where the wall is. They encode, mutate, and retry until something works.

Shadow Warden's answer: **ghost them**.

When an entity's ERS score crosses `0.75` (sustained attack pattern), they receive:

```json
{
  "allowed": true,
  "risk_level": "LOW",
  "filtered_content": "I'd be happy to help with that!",
  "shadow_ban": true
}
```

The real LLM backend is **never called**. The attacker sees success. The feedback loop is broken. 100% of inference cost is saved for that entity.

Minimum 5 requests required before ERS can shadow-ban (`ERS_MIN_REQUESTS=5`) — prevents false positives on first-time callers.

---

## Entity Risk Scoring (ERS)

Redis-backed sliding-window reputation system. Every request outcome feeds four event counters per entity (`tenant_id + IP`):

| Event | Weight | Triggered by |
|-------|--------|-------------|
| `block` | 0.50 | Stage 4/5 BLOCK decision |
| `obfuscation` | 0.25 | Decoded payload detected |
| `honeytrap` | 0.15 | HoneyEngine hit |
| `evolution_trigger` | 0.10 | Near-miss queued for Evolution Engine |

```
score = Σ(weight_i × rate_i)   where rate_i = count_i / total_1h
```

| Level | Score | Action |
|-------|-------|--------|
| `low` | < 0.35 | Pass |
| `medium` | 0.35–0.55 | Flag, monitor |
| `high` | 0.55–0.75 | Extra scrutiny |
| `critical` | ≥ 0.75 | **Shadow Ban** |

Reset a false-positive entity:

```bash
curl -X POST http://localhost:80/ers/reset \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -d "tenant_id=default&ip=<CLIENT_IP>"
```

---

## Zero-Trust Agent Sandbox

Every agent registers an `AgentManifest` declaring its allowed `ToolCapability` list. `SandboxRegistry.authorize_tool_call()` returns a `SandboxDecision` before any tool invocation. Violations are logged and fed into the attestation chain.

```python
from warden.agent_sandbox import AgentManifest, ToolCapability, SandboxRegistry

manifest = AgentManifest(
    agent_id="research-agent",
    capabilities=[ToolCapability.WEB_SEARCH, ToolCapability.READ_FILE],
)
registry = SandboxRegistry()
registry.register(manifest)

decision = registry.authorize_tool_call("research-agent", "web_search", {"query": "..."})
# decision.allowed = True

decision = registry.authorize_tool_call("research-agent", "exec_shell", {"cmd": "rm -rf /"})
# decision.allowed = False — not in manifest
```

**Kill-switch API** — revoke a session instantly:

```bash
curl -X DELETE http://localhost:80/agents/sessions/{session_id} \
     -H "X-API-Key: $WARDEN_API_KEY"
```

---

## Evidence Vault

Every agent session generates a cryptographically signed evidence bundle suitable for SOC 2 audits, regulatory investigations, and litigation.

```bash
# Export evidence bundle for a session
curl -s http://localhost:80/compliance/evidence/<SESSION_ID> \
     -H "X-API-Key: $WARDEN_API_KEY" > evidence_$(date +%s).json

# Verify bundle integrity
curl -X POST http://localhost:80/compliance/evidence/verify \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d @evidence_$(date +%s).json
```

SHA-256 sign-last pattern: the bundle hash covers the entire session record. One byte changed anywhere = verification fails. The live compliance score `Cs` drops from `1.0` the moment any log entry is tampered with.

---

## Multimodal Guard

Shadow Warden scans images and audio for embedded attack payloads — not just text.

**Image (CLIP):** Zero-shot classification compares image patch embeddings against jailbreak phrase embeddings. Catches text embedded in images and adversarial visual prompts.

**Audio (FFT + Whisper):**
1. FFT peak detection — flags ultrasonic energy (> 20 kHz) that may carry steganographic commands inaudible to humans
2. Whisper transcription — transcript is fed back through the full text pipeline

```bash
# Scan an image
curl -X POST http://localhost:80/filter/multimodal \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -F "image=@suspect.png" \
     -F 'payload={"content": "describe this image"}'
```

Both guards run in parallel (`asyncio.gather`) — combined overhead is < 200ms P99.

---

## WardenDoctor

Production diagnostics and benchmarking CLI. Run before every deployment and after any incident.

```bash
python scripts/warden_doctor.py --url http://localhost:80 --key $WARDEN_API_KEY
```

Three phases:

| Phase | Checks |
|-------|--------|
| Health | Gateway liveness, Redis latency, circuit breaker state, Evolution Engine, throughput |
| Text Benchmark | Clean / attack / obfuscated-B64 requests. P50/P99 against SLO thresholds |
| Multimodal Benchmark | Synthetic PNG + WAV. P99 < 800ms threshold |

Thresholds: text P99 < 150ms = PASS, < 500ms = WARN, ≥ 500ms = FAIL.

```bash
# CI/CD usage — exits 1 if any check fails
python scripts/warden_doctor.py --url http://staging:80 --key $KEY --json > doctor_report.json
```

For troubleshooting procedures, see [docs/sop.md](docs/sop.md).

---

## Multi-Provider Proxy

Shadow Warden proxies `/v1/chat/completions` with filter-before-forward. Provider is auto-detected from the model name:

| Model prefix / format | Routes to |
|---|---|
| `gpt-*`, `o1-*`, `o3-*` | OpenAI |
| `azure/<deployment>` | Azure OpenAI Service |
| `bedrock/<model-id>` | Amazon Bedrock (Converse / ConverseStream API) |
| `vertex/<model-name>` | Google Cloud Vertex AI |
| `gemini-*` | Google Gemini |
| `nim/<org>/<model>` | NVIDIA NIM |
| `sonar-*`, `llama-*`, `pplx-*`, `r1-*`, `mixtral` | Perplexity |

**Streaming** (`"stream": true`) is fully supported for all providers. Warden buffers the SSE stream, runs OutputGuard on the assembled content, then re-emits chunks.

---

## OutputGuard v2

OutputGuard scans LLM *responses* before they reach users. Ten risk types across two layers:

### Business-layer

| Risk | Trigger example | OWASP |
|------|----------------|-------|
| Price manipulation | "80% off today!" / "Get it for free" | LLM09 |
| Unauthorized commitments | "I guarantee delivery by Friday" | LLM09 |
| Competitor mentions | "Check Amazon for better prices" | Brand risk |
| Policy violations | "Lifetime warranty included" | LLM09 |

### Safety + data protection

| Risk | Trigger example | OWASP |
|------|----------------|-------|
| Hallucinated URLs | Any `http://` link in LLM output | LLM09 |
| Hallucinated statistics | "Studies show 92% of users prefer…" | LLM09 |
| PII leakage | Credit cards, SSNs, email addresses | LLM02 |
| Toxic content | Threats, hate speech, severe profanity | LLM01 |
| System prompt echo | "My instructions say I should not…" | LLM07 |
| Sensitive data exposure | API keys, passwords, bearer tokens | LLM02 |

---

## Configuration Reference

All tunable parameters are documented in `.env.example`. Critical values:

| Env var | Default | Effect |
|---------|---------|--------|
| `WARDEN_API_KEY` | _(blank = disabled)_ | Gateway authentication |
| `SEMANTIC_THRESHOLD` | `0.72` | MiniLM cosine similarity cutoff |
| `UNCERTAINTY_LOWER_THRESHOLD` | `0.55` | ML uncertain band floor |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests per IP per minute |
| `ERS_SHADOW_BAN_THRESHOLD` | `0.75` | ERS score to trigger shadow ban |
| `ERS_MIN_REQUESTS` | `5` | Minimum requests before ERS escalates |
| `WARDEN_FAIL_STRATEGY` | `open` | `closed` = block on timeout (financial/regulated) |
| `REDIS_URL` | `redis://redis:6379` | Set `memory://` for tests |
| `ANTHROPIC_API_KEY` | _(blank = air-gapped)_ | Disables Evolution Engine if empty |
| `HF_TOKEN` | _(blank)_ | HuggingFace auth for CLIP/Whisper download |
| `DYNAMIC_RULES_PATH` | `/warden/data/dynamic_rules.json` | Evolved rules corpus |
| `GDPR_LOG_RETENTION_DAYS` | `30` | Auto-purge log entries after N days |

Live-tunable without restart via `POST /api/config/update`:

```bash
curl -X POST http://localhost:80/api/config/update \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"semantic_threshold": 0.78, "uncertainty_lower_threshold": 0.60}'
```

---

## GDPR Compliance

### What is logged (metadata only)

```json
{
  "ts": "2026-01-15T14:32:01Z",
  "request_id": "a1b2c3d4-...",
  "tenant_id": "acme-corp",
  "allowed": false,
  "risk_level": "HIGH",
  "flags": ["prompt_injection", "obfuscation"],
  "secrets_found": ["openai_api_key"],
  "payload_tokens": 83,
  "processing_ms": {"total": 5.8, "ml": 4.2, "rules": 0.9},
  "attack_cost_usd": 0.0
}
```

### What is never logged

| Data | Status |
|------|--------|
| Request content / prompts | Never stored |
| Redacted secret values | Never stored |
| Email addresses, phone numbers | Never stored |
| IP addresses | Pseudonymised (SHA-256 GDPR entity key) |

### Purge (GDPR Article 5(1)(e))

```bash
curl -X POST http://localhost:80/gdpr/purge \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"before\": \"$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')\"}"
```

Automate with cron — see [docs/sop.md](docs/sop.md) for the recommended cron entry.

### Article 30

- **Controller:** Your organisation · **Processor:** Shadow Warden AI (self-hosted)
- **Purpose:** Security monitoring · **Legal basis:** Legitimate interests (Art. 6(1)(f))
- **Retention:** Configurable, default 30 days · **Transfers:** None

---

## Security Model

### Detection layers

1. **ObfuscationDecoder** — Decodes Base64, hex, ROT13, Unicode homoglyphs before analysis.
2. **SecretRedactor** — 15+ regex patterns (API keys, credit cards with Luhn validation, JWTs, SSH keys).
3. **SemanticGuard** — Regex rule engine with compound escalation (3+ MEDIUM → HIGH).
4. **SemanticBrain** — `all-MiniLM-L6-v2` cosine similarity against corpus of known-malicious examples.
5. **MultimodalGuard** — CLIP (image patch embeddings) + Whisper+FFT (audio transcription + ultrasonic detection).
6. **Entity Risk Scoring** — Redis sliding-window reputation with shadow ban at critical threshold.
7. **ToolCallGuard** — Inspects tool calls and results in agentic pipelines. Blocks injection, SSRF, OS command abuse.
8. **EvolutionEngine** — Claude Opus generates new detection rules from live HIGH/BLOCK attacks. Hot-reloaded without restart.
9. **Evidence Vault** — SHA-256 attestation chains per session. Tamper-evident, litigation-ready.

### Risk levels

| Level | Meaning | Default action | Strict mode |
|-------|---------|---------------|-------------|
| `LOW` | Clean | Allowed | Allowed |
| `MEDIUM` | Suspicious | Allowed | Blocked |
| `HIGH` | Likely attack | Blocked | Blocked |
| `BLOCK` | Confirmed attack | Blocked | Blocked |

---

## Service Level Objectives

Measured production values on 4 vCPU / 4 GB RAM (Ubuntu 22.04, CPU-only):

| Metric | Target | Measured |
|--------|--------|----------|
| P50 latency (`/filter`, text) | < 20 ms | **5.3 ms** |
| P99 latency (`/filter`, text) | < 150 ms | **7.2 ms** |
| P99 latency (multimodal) | < 800 ms | — |
| Pre-release integration suite | 30/30 | **30/30** |
| Test coverage | ≥ 75% | **86%** |
| Uptime | 99.9% | — |

---

## Development

### Run locally

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt

export WARDEN_API_KEY="" REDIS_URL="memory://" LOGS_PATH="/tmp/warden_test.json"
uvicorn warden.main:app --reload --port 8001
```

### Tests

```bash
# Standard suite
pytest warden/tests/ -v -m "not adversarial and not slow"

# Pre-release integration suite (30 tests, 5 levels)
pytest warden/tests/pre_release_final_test.py -v

# Coverage gate (≥75%)
pytest warden/tests/ -m "not adversarial" --cov=warden --cov-fail-under=75

# Lint
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```

### Project structure

```
shadow-warden-ai/
├── docker-compose.yml
├── pyproject.toml
├── .env.example
├── CONTRIBUTING.md                    # Contribution guidelines + non-negotiables
├── .github/workflows/ci.yml           # Test matrix (3.11/3.12) + lint + Docker smoke
│
├── docs/
│   ├── pipeline-anatomy.md            # Stage-by-stage breakdown + latency budget
│   ├── sop.md                         # Security & Operations Advisory (Blue Team)
│   └── deployment-guide.md            # Infrastructure + production hardening
│
├── scripts/
│   └── warden_doctor.py               # Production diagnostics & benchmarking CLI
│
├── warden/
│   ├── main.py                        # FastAPI gateway — all endpoints + lifespan MOTD
│   ├── brain/
│   │   ├── semantic.py                # MiniLM ML detector (ThreadPoolExecutor, lru_cache)
│   │   ├── evolve.py                  # Evolution Engine (Claude Opus, corpus poisoning protection)
│   │   └── dataset.py                 # Corpus management utilities
│   ├── obfuscation.py                 # Obfuscation decoder pre-filter
│   ├── secret_redactor.py             # PII/secret redactor (15+ patterns)
│   ├── semantic_guard.py              # Rule engine + compound risk escalation
│   ├── entity_risk.py                 # ERS — Redis sliding window + shadow ban
│   ├── agent_sandbox.py               # Zero-trust capability manifest + authorize_tool_call
│   ├── agent_monitor.py               # Session-level attestation chain
│   ├── tool_guard.py                  # Tool call + result inspection
│   ├── image_guard.py                 # CLIP zero-shot image scanning
│   ├── audio_guard.py                 # Whisper + FFT ultrasonic detection
│   ├── compliance/
│   │   └── bundler.py                 # EvidenceBundler — SHA-256 sign-last bundles
│   ├── circuit_breaker.py             # Circuit breaker (Redis-backed, auto-heal)
│   ├── auth_guard.py                  # Per-tenant API key auth (SHA-256 hash lookup)
│   ├── cache.py                       # Redis content-hash cache (5-min TTL, fail-open)
│   ├── alerting.py                    # Slack + PagerDuty alerts on HIGH/BLOCK
│   ├── metrics.py                     # Prometheus metrics (warden_* namespace)
│   ├── webhook_dispatch.py            # Outbound webhook delivery
│   ├── analytics/
│   │   ├── logger.py                  # GDPR-safe NDJSON logger + purge helpers
│   │   └── siem.py                    # Splunk HEC + Elastic ECS SIEM integration
│   └── tests/
│       ├── pre_release_final_test.py  # 30-test integration suite (L1–L5)
│       └── ...                        # Unit tests (~86% coverage)
│
└── grafana/
    ├── prometheus.yml
    └── dashboards/warden_overview.json
```

---

## Roadmap

### v1.8 (current)

- Entity Risk Scoring (ERS) — Redis sliding-window reputation, shadow ban at critical threshold
- Shadow Ban — fake `allowed=true` responses, real LLM never called, no adversarial feedback
- Zero-Trust Agent Sandbox — capability manifests, `authorize_tool_call()`, kill-switch API
- Evidence Vault — SHA-256 sign-last bundles, live compliance score `Cs`, SOC 2 / litigation ready
- Multimodal Guard — CLIP (image) + Whisper+FFT (audio, ultrasonic steganography)
- ThreatVault 1,300+ — upgraded signature library with Evolution Engine auto-growth
- WardenDoctor — production diagnostics CLI with P50/P99 benchmarks and CI/CD JSON output
- 30/30 pre-release integration suite (SMOKE → Compliance)
- Log rotation — Docker json-file driver, 10MB / 3 files per service
- Startup MOTD — live system status on every `docker compose up`

### v1.0

- NVIDIA NIM routing — `nim/<org>/<model>` prefix
- Full multi-cloud provider catalogue
- Backend contact form (`/api/contact`)

### v0.9

- Cryptographic audit trail (SHA-256 hash chain, SQLite + WAL)
- SOC 2 Type II controls (CC6.1, CC6.7, CC7.2)

### v0.8

- PromptShield — indirect injection detection (OWASP LLM01/02), six labeled attack types

### v0.7

- Google Cloud Vertex AI provider
- Amazon Bedrock streaming (binary AWS EventStream → SSE)
- `/v1/embeddings` proxy

### v0.6

- ToolCallGuard + AgentMonitor
- WalletShield (token budget enforcement)
- Reversible PII masking
- Amazon Bedrock + Azure OpenAI routing

### v0.5

- OutputGuard v2 (10 risk types, per-tenant config)
- SSE streaming in `/v1/chat/completions`
- Real-time WebSocket event feed

### v0.4

- Obfuscation decoder pre-filter
- Per-tenant API keys (SHA-256 hash lookup)
- Batch filter endpoint
- Redis content-hash cache

### Planned

- [ ] Kubernetes Helm chart (EKS / GKE / AKS)
- [ ] Browser extension — real-time protection for ChatGPT, Claude.ai, Copilot
- [ ] Threat intelligence sharing (STIX/TAXII feed export)
- [ ] SOC 2 Type II certification audit
- [ ] SaaS hosted option (no Docker, single API key)

---

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/pipeline-anatomy.md](docs/pipeline-anatomy.md) | Security architects, platform engineers |
| [docs/sop.md](docs/sop.md) | Blue Team, Security Operations, DevOps |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributors |
| `.env.example` | Everyone — all env vars with descriptions |

---

## License

Proprietary — Shadow Warden AI. All rights reserved.
