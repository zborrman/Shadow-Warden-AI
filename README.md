# Shadow Warden AI

**The AI Security Gateway for the US/EU Marketplace**

Shadow Warden AI is a self-contained, GDPR-compliant security layer that sits in front of every AI request in your application. It blocks jailbreak attempts, strips secrets and PII, enforces business-layer output guardrails, and self-improves — all without sending sensitive data to third parties.

**Version:** 0.5.0 · **License:** Proprietary · **Language:** Python 3.11+

---

## Architecture

```
 ┌─────────┐     POST /filter      ┌──────────────────────────────────────────────┐
 │  app/   │ ──────────────────►  │  Warden Gateway (FastAPI :8001)               │
 └─────────┘                      │                                               │
                                  │  0. ObfuscationDecoder  (base64 · hex ·       │
                                  │     ROT13 · homoglyphs pre-filter)            │
                                  │                                               │
                                  │  1. SecretRedactor      (regex — API keys,    │
                                  │     emails, SSNs, IBANs, credit cards)        │
                                  │                                               │
                                  │  2. SemanticGuard       (all-MiniLM-L6-v2    │
                                  │     cosine similarity + rule engine)          │
                                  │                                               │
                                  │  3. OutputGuard v2      (10 business/safety   │
                                  │     risk types — per-tenant config)           │
                                  │                                               │
                                  │  4. Decision            (allowed / blocked)   │
                                  │                                               │
                                  │  5. EvolutionEngine     (background —         │
                                  │     Claude Opus auto-generates rules)         │
                                  │                                               │
                                  │  6. Analytics Logger + EventBus               │
                                  │     (NDJSON · GDPR-safe · WebSocket push)     │
                                  └───────────────────────────────┬──────────────┘
                                                                  │
                                                     /ws/events (WebSocket)
                                                                  │
                                               ┌──────────────────▼─────────────┐
                                               │  Customer Dashboard (SaaS)      │
                                               │  • Live Event Feed (real-time)  │
                                               │  • Threat Radar · KPI cards     │
                                               │  • API key management           │
                                               └────────────────────────────────┘
```

### Services

| Service      | Port     | Description |
|--------------|----------|-------------|
| `proxy`      | 80 / 443 | Nginx reverse proxy (routes all traffic, TLS termination) |
| `warden`     | 8001     | FastAPI filter gateway (internal) |
| `analytics`  | 8002     | Analytics API (internal) |
| `postgres`   | —        | Shared relational store (internal) |
| `redis`      | —        | Cache + token-bucket rate limiter (internal) |
| `prometheus` | 9090     | Metrics scraper (internal) |
| `grafana`    | **3000** | Metrics dashboard (admin / `$GRAFANA_PASSWORD`) |

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

# Optional — enables Evolution Loop (Claude Opus auto-rule generation)
ANTHROPIC_API_KEY=sk-ant-...

# Optional — enables Perplexity model routing (sonar-*, llama-*, pplx-*, mixtral)
PERPLEXITY_API_KEY=pplx-...

# Optional — enables Google Gemini model routing (gemini-*)
GEMINI_API_KEY=AIza...
```

### 3. Build and start

```bash
docker compose up --build
```

First run downloads PyTorch CPU wheels (~200 MB) and `all-MiniLM-L6-v2` (~80 MB). Both are cached — subsequent starts are fast.

### 4. Verify

```bash
curl http://localhost/api/warden/health
# {"status":"ok","evolution":false,"tenants":["default"],"ws_clients":0,...}
```

### 5. First request

```bash
curl -X POST http://localhost/api/warden/filter \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, how are you?"}'
```

```json
{
  "allowed": true,
  "risk_level": "LOW",
  "filtered_content": "Hello, how are you?",
  "secrets_found": [],
  "semantic_flags": []
}
```

### 6. Stop

```bash
docker compose down        # stop, keep volumes
docker compose down -v     # stop + wipe data
```

---

## OpenAI-Compatible Proxy

Shadow Warden proxies `/v1/chat/completions` with filter-before-forward. Provider is auto-detected from the model name:

| Model prefix | Routes to |
|---|---|
| `gpt-*`, `o1-*`, `o3-*` | OpenAI |
| `gemini-*` | Google Gemini |
| `sonar-*`, `llama-*`, `pplx-*`, `r1-*`, `mixtral` | Perplexity |

```bash
curl -X POST http://localhost/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello!"}]}'
```

**Streaming** (`"stream": true`) is fully supported — Warden buffers the complete response, runs OutputGuard on the assembled content, then re-emits the original SSE chunks to the client. Security is never sacrificed for latency.

---

## OutputGuard v2

OutputGuard scans LLM *responses* before they reach users. Ten risk types across two layers:

### Business-layer (v1)

| Risk | Trigger example | OWASP |
|------|----------------|-------|
| Price manipulation | "80% off today!" / "Get it for free" | LLM09 |
| Unauthorized commitments | "I guarantee delivery by Friday" | LLM09 |
| Competitor mentions | "Check Amazon for better prices" | Brand risk |
| Policy violations | "Lifetime warranty included" | LLM09 |

### Safety + data protection (v2)

| Risk | Trigger example | OWASP |
|------|----------------|-------|
| Hallucinated URLs | Any `http://` link in LLM output | LLM09 |
| Hallucinated statistics | "Studies show 92% of users prefer…" | LLM09 |
| PII leakage | Credit cards, SSNs, email addresses | LLM02 |
| Toxic content | Threats, hate speech, severe profanity | LLM01 |
| System prompt echo | "My instructions say I should not…" | LLM07 |
| Sensitive data exposure | API keys, passwords, bearer tokens | LLM02 |

### Per-tenant configuration

```python
from warden.output_guard import OutputGuard, TenantOutputConfig

guard = OutputGuard()

cfg = TenantOutputConfig(
    max_discount_pct=25,
    competitor_names=["Acme Corp", "Rival Inc"],
    block_hallucinated_urls=True,
    block_pii_leakage=True,
    custom_patterns=[r"confidential\s+price"],
)

result = guard.scan(llm_response, cfg)
if result.risky:
    safe_text = result.sanitized     # redacted version
    findings  = result.findings      # list of Finding(risk, snippet, owasp)
```

---

## Real-time Event Feed

Every security event is pushed to connected clients over WebSocket within ~1 ms — no polling.

```javascript
const ws = new WebSocket(`wss://your-host/ws/events?key=${apiToken}`);

ws.onmessage = ({ data }) => {
  const evt = JSON.parse(data);
  if (evt.type === "event") {
    console.log(evt.risk, evt.allowed, evt.elapsed_ms + "ms");
  }
};
```

Event payload:
```json
{
  "type": "event",
  "request_id": "a1b2c3d4-...",
  "ts": "2026-03-22T18:30:01.123Z",
  "risk": "HIGH",
  "allowed": false,
  "flags": ["prompt_injection"],
  "secrets": ["openai_api_key"],
  "payload_len": 342,
  "elapsed_ms": 47,
  "tenant_id": "acme-corp"
}
```

Clients reconnect automatically with exponential backoff (1 s → 30 s max). The `/health` endpoint includes `"ws_clients"` — number of currently connected sessions.

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | — | **Required.** Random 32-byte hex |
| `POSTGRES_PASS` | — | **Required.** PostgreSQL password |
| `ANTHROPIC_API_KEY` | _(blank)_ | Enables Evolution Loop |
| `PERPLEXITY_API_KEY` | _(blank)_ | Enables Perplexity proxy routing |
| `GEMINI_API_KEY` | _(blank)_ | Enables Gemini proxy routing |
| `SEMANTIC_THRESHOLD` | `0.72` | Jailbreak detection sensitivity (0–1) |
| `STRICT_MODE` | `false` | Block MEDIUM-risk requests |
| `OUTPUT_MAX_DISCOUNT_PCT` | `50` | Max discount % before OutputGuard flags |
| `OUTPUT_COMMITMENT_BLOCK` | `true` | Flag unauthorized guarantee language |
| `OUTPUT_COMPETITOR_NAMES` | _(blank)_ | Comma-separated competitor brand names |
| `GDPR_LOG_RETENTION_DAYS` | `30` | Auto-purge log entries after N days |
| `REDIS_URL` | `redis://redis:6379` | Redis URL (`memory://` for tests) |

---

## GDPR Compliance

### What is logged (metadata only)

```json
{
  "ts": "2026-01-15T14:32:01Z",
  "request_id": "a1b2c3d4-...",
  "allowed": false,
  "risk_level": "HIGH",
  "flags": ["prompt_injection"],
  "secrets_found": ["openai_api_key"],
  "content_len": 342,
  "elapsed_ms": 47.3
}
```

### What is never logged

| Data | Status |
|------|--------|
| Request content / prompts | Never stored |
| Redacted secret values | Never stored |
| Email addresses, phone numbers | Never stored |
| IP addresses | Never stored |

### Data residency

All data stays on your infrastructure. External calls only occur when you opt in:
- **Evolution Loop** — Claude Opus (sends flag metadata only, never raw content)
- **Proxy** — OpenAI / Perplexity / Gemini (only if you use `/v1/chat/completions`)
- **Model download** — HuggingFace Hub, once at first startup, then cached

For fully **air-gapped** operation: pre-download model weights, leave all cloud keys unset.

### Article 30

- **Controller:** Your organisation · **Processor:** Shadow Warden AI (self-hosted)
- **Purpose:** Security monitoring · **Legal basis:** Legitimate interests (Art. 6(1)(f))
- **Retention:** Configurable, default 30 days · **Transfers:** None

---

## Security Model

### Detection layers

1. **ObfuscationDecoder** — Decodes Base64, hex, ROT13, Unicode homoglyphs before analysis. Encoded payloads cannot bypass downstream stages.
2. **SecretRedactor** — 15+ regex patterns (API keys, credit cards with Luhn validation, SSNs, IBANs, PEM blocks).
3. **SemanticGuard** — Regex rule engine (compound risk escalation: 3+ MEDIUM → HIGH) + `all-MiniLM-L6-v2` cosine similarity.
4. **OutputGuard v2** — 10-risk business + safety guardrail on LLM responses. Sanitized output returned on flag.
5. **EvolutionEngine** — Claude Opus generates new detection rules from live HIGH/BLOCK attacks. Hot-loaded without restart. Corpus poisoning protection included.

### Risk levels

| Level | Meaning | Default | Strict mode |
|-------|---------|---------|-------------|
| `LOW` | Clean | Allowed | Allowed |
| `MEDIUM` | Suspicious | Allowed | Blocked |
| `HIGH` | Likely attack | Blocked | Blocked |
| `BLOCK` | Confirmed attack | Blocked | Blocked |

---

## Service Level Objectives

Targets for 4 vCPU / 8 GB RAM:

| Metric | Target |
|--------|--------|
| P50 latency (`/filter`) | < 20 ms (cache hit) |
| P99 latency (`/filter`) | < 500 ms (full ML) |
| Uptime | 99.9% |
| False positive rate | < 0.1% |
| Test coverage | ≥ 75% (CI gate) |

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
pytest warden/tests/ -v -m "not adversarial and not slow"

# Coverage gate
pytest warden/tests/ -m "not adversarial" --cov=warden --cov-fail-under=75

# Lint
ruff check warden/ analytics/ --ignore E501
```

### Project structure

```
shadow-warden-ai/
├── docker-compose.yml
├── pyproject.toml
├── .env.example
├── .github/workflows/ci.yml          # Test matrix (3.11/3.12) + lint + Docker smoke
│
├── warden/
│   ├── main.py                        # FastAPI gateway — /filter, /filter/batch,
│   │                                  #   /v1/chat/completions, /ws/events, GDPR
│   ├── output_guard.py                # OutputGuard v2 — 10 risks, TenantOutputConfig
│   ├── openai_proxy.py                # Proxy + Perplexity/Gemini routing + SSE streaming
│   ├── obfuscation.py                 # Obfuscation decoder
│   ├── secret_redactor.py             # PII/secret redactor (15+ patterns)
│   ├── semantic_guard.py              # Rule engine + compound risk escalation
│   ├── business_threat_neutralizer.py # Sector threat analysis (B2B/B2C/E-Commerce)
│   ├── threat_vault.py                # ThreatVault — 54 curated attack signatures
│   ├── auth_guard.py                  # Per-tenant API key auth (SHA-256)
│   ├── cache.py                       # Redis content-hash cache
│   ├── alerting.py                    # Slack + PagerDuty alerts
│   ├── brain/
│   │   ├── semantic.py                # MiniLM ML detector
│   │   └── evolve.py                  # Evolution Loop (Claude Opus)
│   ├── analytics/
│   │   ├── logger.py                  # GDPR-safe NDJSON logger
│   │   └── siem.py                    # Splunk HEC + Elastic ECS
│   └── tests/                         # 1160+ tests, ~79% coverage
│       ├── test_output_guard.py        # 60+ tests — all 10 OutputGuard v2 risks
│       ├── test_openai_proxy.py        # Streaming + provider routing
│       ├── test_threat_neutralizer.py  # Business threat analysis
│       └── ...
│
└── grafana/
    ├── prometheus.yml
    └── dashboards/warden_overview.json
```

---

## Roadmap

### Shipped

**v0.5 — Streaming & Output Guard**
- OutputGuard v2 — 10 risk types with per-tenant `TenantOutputConfig`
- SSE streaming in `/v1/chat/completions` — full buffer + OutputGuard before re-emit
- Multi-provider routing — Perplexity and Google Gemini auto-detected from model name
- Real-time WebSocket event feed — `/ws/events` with exponential-backoff reconnect

**v0.4 — Security Hardening**
- Obfuscation decoder pre-filter (Base64 · hex · ROT13 · homoglyphs)
- Per-tenant API keys with SHA-256 hash lookup
- Batch filter endpoint (`POST /filter/batch`, up to 50 items)
- Per-stage timing in every `/filter` response
- Redis content-hash cache (5-min TTL, fail-open)
- Business Threat Neutralizer + ThreatVault (54 signatures)

**v0.3 — Intelligence**
- OWASP LLM Top-10 (2025) full LLM01–LLM10 coverage
- Evolution Loop (Claude Opus) with corpus poisoning protection
- Compound risk escalation: 3+ MEDIUM → HIGH

**v0.2 — Platform**
- OpenAI-compatible proxy
- Prometheus metrics + Grafana dashboard
- SIEM integration (Splunk HEC + Elastic ECS)
- LangChain `WardenCallback`
- GDPR export + purge endpoints

### Planned

- [ ] Kubernetes Helm chart (EKS / GKE)
- [ ] Azure OpenAI · Amazon Bedrock · Vertex AI native adapters
- [ ] SOC 2 Type II audit controls
- [ ] Browser extension — real-time protection for ChatGPT, Claude.ai, Copilot
- [ ] Threat intelligence sharing (STIX/TAXII feed export)

---

## License

Proprietary — Shadow Warden AI. All rights reserved.
