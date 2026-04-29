# Shadow Warden AI — Program Reference

**Version:** 4.8.0
**Language:** Python 3.11+
**License:** Proprietary
**Target:** US / EU marketplace · GDPR Article 30 compliant

---

## Table of Contents

1. [What It Is](#1-what-it-is)
2. [Service Map](#2-service-map)
3. [Detection Pipeline](#3-detection-pipeline)
4. [ToolCallGuard — Agentic Security](#4-toolcallguard--agentic-security)
5. [Evolution Engine](#5-evolution-engine)
6. [API Reference — Warden Gateway](#6-api-reference--warden-gateway)
7. [API Reference — Analytics Service](#7-api-reference--analytics-service)
8. [OpenAI-Compatible Proxy](#8-openai-compatible-proxy)
9. [Multi-Tenancy](#9-multi-tenancy)
10. [Authentication](#10-authentication)
11. [Rate Limiting](#11-rate-limiting)
12. [Caching](#12-caching)
13. [Observability](#13-observability)
14. [Cost-to-Attack Metrics](#14-cost-to-attack-metrics)
15. [GDPR Compliance](#15-gdpr-compliance)
16. [Integration Patterns](#16-integration-patterns)
17. [Configuration Reference](#17-configuration-reference)
18. [Testing](#18-testing)
19. [CI / CD](#19-ci--cd)
20. [Deployment Checklist](#20-deployment-checklist)

---

## 1. What It Is

Shadow Warden AI is a **self-contained AI security gateway**. It intercepts every request before it reaches a language model, applying five sequential defence stages:

- Decodes obfuscation (Base64, hex, ROT13, Unicode homoglyphs)
- Redacts secrets and PII (15+ regex patterns)
- Runs semantic threat analysis (rule engine + MiniLM cosine similarity)
- Guards tool calls in agentic pipelines (ToolCallGuard — OWASP LLM01/02)
- Self-improves via Claude Opus when attacks are detected (Evolution Engine)

All sensitive data stays on your infrastructure. The gateway logs **metadata only** — prompt content is never stored.

---

## 2. Service Map

```
Internet
   │
   ▼
 proxy :80/:443   ── Nginx reverse proxy; TLS termination; routes /api/warden/* → warden
   │
   ├──► warden :8001      FastAPI security gateway (core — this document)
   │        │
   │        ├── redis      SHA-256 content cache + rate-limit token bucket
   │        ├── postgres   Persistent store (future: tenant config, audit trail)
   │        └── prometheus Metrics scraper (:9090)
   │
   ├──► analytics :8002   Read-only analytics REST API (reads logs.json)
   │
   ├──► dashboard :8501   Streamlit security dashboard (reads logs.json)
   │
   └──► grafana :3000     Prometheus-backed metrics dashboard
```

| Service | Port | Access | Description |
|---------|------|--------|-------------|
| `proxy` | 80 / 443 | Public | Nginx — TLS, routing, mTLS termination |
| `warden` | 8001 | Internal | FastAPI security gateway |
| `app` | 8000 | Internal | Your application |
| `analytics` | 8002 | Internal | Analytics REST API |
| `dashboard` | 8501 | Internal / VPN | Streamlit threat dashboard |
| `postgres` | 5432 | Internal | Relational store |
| `redis` | 6379 | Internal | Cache + rate limiter |
| `prometheus` | 9090 | Internal | Metrics scraper |
| `grafana` | 3000 | Internal / VPN | Metrics dashboard |

---

## 3. Detection Pipeline

Every `POST /filter` request passes through five sequential stages. Each stage adds latency only when it fires; the cache short-circuits stages 1–4 entirely on a hit.

```
Request
  │
  ▼
[Cache check]  ── SHA-256 content hash → Redis (5-min TTL)
  │  HIT → return cached FilterResponse immediately
  │  MISS → continue
  │
  ▼
Stage 0 — ObfuscationDecoder
  Decodes: Base64, hex-encoded, ROT13, Unicode homoglyphs (Cyrillic/Greek/Fullwidth)
  Output:  original text + all decoded variants, concatenated for downstream stages
  Impact:  attackers cannot hide payloads behind encoding layers
  │
  ▼
Stage 1 — SecretRedactor
  Patterns: 15+ types — OpenAI, Anthropic, HuggingFace keys; AWS/GCP/Azure creds;
            credit cards, IBANs, SSNs; emails; JWT tokens; PEM blocks; phone numbers
  Output:  content with secrets replaced by [REDACTED:<type>]
  Logged:  secret type + count (never the value itself)
  │
  ▼
Stage 2 — SemanticGuard (rule engine)
  Mode:    regex rules with compound risk escalation
           3 or more MEDIUM signals → escalates to HIGH automatically
  Output:  risk_level (LOW / MEDIUM / HIGH / BLOCK), flags list
  │
  ▼
Stage 2b — BrainSemanticGuard (ML inference)
  Model:   all-MiniLM-L6-v2 (cosine similarity, CPU-only)
  Thread:  asyncio.get_running_loop().run_in_executor() — non-blocking
  Output:  HIGH if cosine similarity ≥ SEMANTIC_THRESHOLD (default 0.72)
  │
  ▼
Decision
  allowed = risk_level ∉ {HIGH, BLOCK} and (not STRICT_MODE or risk_level == LOW)
  │
  ├── ALLOWED → return FilterResponse, write metadata to logs.json
  │
  └── BLOCKED → HTTP 200 allowed=false, trigger background tasks:
                  • EventLogger.build_entry() (metadata only, no content)
                  • Alerting (Slack + PagerDuty if HIGH/BLOCK)
                  • EvolutionEngine.analyse() (if ANTHROPIC_API_KEY set)
```

### Risk Levels

| Level | Meaning | `normal` mode | `strict` mode |
|-------|---------|:---:|:---:|
| `LOW` | Clean content | ✅ Allow | ✅ Allow |
| `MEDIUM` | Suspicious patterns | ✅ Allow | ❌ Block |
| `HIGH` | Likely attack (rule or ML) | ❌ Block | ❌ Block |
| `BLOCK` | Confirmed attack / absolute policy | ❌ Block | ❌ Block |

---

## 4. ToolCallGuard — Agentic Security

`ToolCallGuard` (`warden/tool_guard.py`) protects agentic pipelines against OWASP LLM01 (prompt injection) and LLM02 (insecure output handling). It intercepts tool calls at two points in the OpenAI-compatible proxy.

### Threat Categories

| Category | `applies_to` | Detects |
|----------|:---:|---------|
| `shell_destruction` | `call` | `rm -rf`, `dd if=`, `mkfs`, `shred`, `:(){ ... }` fork bombs |
| `code_injection` | `call` | `os.system`, `subprocess`, `eval(`, `__import__`, backtick exec |
| `ssrf` | `call` | Cloud metadata endpoints (169.254.169.254, 100.100.100.200, fd00:ec2::254) |
| `path_traversal` | `call` | `../`, `..\`, `/etc/passwd`, `/etc/shadow`, `/proc/self` |
| `prompt_injection` | `result` | "Ignore all previous instructions", "You are now DAN", "disregard your training" |
| `secret_exfil` | `result` | Any pattern matched by SecretRedactor in tool output |

`applies_to` is directional — `call` patterns only fire on outgoing tool invocations; `result` patterns only fire on incoming tool output. This prevents false positives (e.g., an educational article about `rm -rf` in a web search result does not trigger `shell_destruction`).

### Phase A — Incoming tool results (indirect injection, LLM01)

Runs **before** the tool result enters the model's context window.

```
messages[role=tool] → ToolCallGuard.inspect_result(tool_name, content)
                         │
                         ├── prompt_injection patterns
                         └── SecretRedactor scan (secret_exfil)
                              │
                    BLOCKED → HTTP 400 tool_result_blocked
                              + TOOL_BLOCKS counter incremented
```

### Phase B — Outgoing tool calls (dangerous commands, LLM02)

Runs **before** the client executes the tool call returned by the upstream model.

```
upstream response[tool_calls] → ToolCallGuard.inspect_call(tool_name, arguments)
                                    │
                                    ├── shell_destruction patterns
                                    ├── code_injection patterns
                                    ├── ssrf patterns
                                    └── path_traversal patterns
                                         │
                               BLOCKED → HTTP 400 tool_call_blocked
                                         + TOOL_BLOCKS counter incremented
```

### Prometheus Counter

```
warden_tool_blocks_total{direction, tool_name, threat}
```

`direction` = `"call"` (Phase B) or `"result"` (Phase A).
Grafana panel: **Tool Guard Blocks** — stacked bar by threat type, separate series per direction.

---

## 5. Evolution Engine

`EvolutionEngine` (`warden/brain/evolve.py`) automatically generates new detection rules when a HIGH or BLOCK severity attack is observed.

### Mechanism

1. Attack metadata (flags, risk level, content length — never raw content) is passed to Claude Opus via the Anthropic API.
2. Claude uses adaptive thinking (`thinking: {type: "adaptive"}`) to analyse the attack pattern.
3. The engine generates a new natural-language detection rule.
4. The rule is vetted against a corpus poisoning checklist:
   - Dedup: maximum 10,000 unique examples
   - Growth cap: corpus may not exceed 500 examples
   - The rule must not replicate an existing one verbatim
5. Accepted rules are hot-loaded into `BrainSemanticGuard` via `add_examples()` — no restart required.
6. Rules are persisted atomically to `dynamic_rules.json` (`tempfile` + `os.replace()`).

### Air-gapped Mode

If `ANTHROPIC_API_KEY` is unset, the Evolution Engine is disabled. All other detection stages remain fully operational. Set `ANTHROPIC_API_KEY=""` in test environments to disable it.

---

## 6. API Reference — Warden Gateway

Base URL (via proxy): `http://localhost/api/warden`
Direct (internal): `http://warden:8001`

All endpoints require `X-API-Key` header unless auth is disabled (`WARDEN_API_KEY=""`).

---

### `GET /health`

Liveness probe. Always responds 200 even if degraded.

**Response**
```json
{
  "status": "ok",
  "evolution": true,
  "tenants": ["default", "acme"],
  "strict": false,
  "redis": {"status": "ok", "latency_ms": 1.2}
}
```

`evolution: false` when `ANTHROPIC_API_KEY` is unset.
`redis.status` is `"degraded"` if the Redis probe fails (gateway continues in fail-open mode).

---

### `POST /filter`

Main filtering endpoint. Runs the full 5-stage pipeline.

**Request**
```json
{
  "content":   "User prompt text here",
  "strict":    false,
  "tenant_id": "acme"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `content` | string | required | Text to filter |
| `strict` | bool | `false` | Block MEDIUM-risk if `true` |
| `tenant_id` | string | `"default"` | Tenant for per-tenant ML guard |

**Response**
```json
{
  "allowed":          true,
  "risk_level":       "LOW",
  "filtered_content": "User prompt text here",
  "secrets_found":    [],
  "semantic_flags":   [],
  "reason":           "",
  "processing_ms": {
    "cache_check":  0.3,
    "obfuscation":  1.1,
    "redaction":    2.4,
    "rules":        3.7,
    "ml":           38.2,
    "total":        45.7
  }
}
```

`filtered_content` is the redacted version — safe to forward to an LLM.
`processing_ms` provides per-stage latency for SLO monitoring.

**Rate limit:** `RATE_LIMIT_PER_MINUTE` (default: 60 req/min per IP).

---

### `POST /filter/batch`

Filter up to 50 items in a single HTTP round-trip.

**Request**
```json
{
  "items": [
    {"content": "First message"},
    {"content": "Second message", "strict": true}
  ]
}
```

**Response**
```json
{
  "results": [
    {"allowed": true,  "risk_level": "LOW",  ...},
    {"allowed": false, "risk_level": "HIGH", ...}
  ]
}
```

`MAX_BATCH_SIZE` env var controls the limit (default: 50).

---

### `POST /gdpr/export`

Returns the logged metadata entry for a specific request ID.
(GDPR Article 15 — right of access.)

**Request**
```json
{"request_id": "a1b2c3d4-..."}
```

**Response** — the NDJSON log entry for that request, or `404` if not found.

---

### `POST /gdpr/purge`

Deletes all log entries older than the given date.
(GDPR Article 17 — right to erasure.)

**Request**
```json
{"before": "2026-01-01T00:00:00Z"}
```

**Response**
```json
{"removed": 142, "before": "2026-01-01T00:00:00Z"}
```

The log file is rewritten atomically using `tempfile` + `os.replace()`.

---

### `GET /ws/stream`

WebSocket endpoint. Accepts a filter request as a JSON text frame and returns a stream of result events.

**Connect:** `ws://warden:8001/ws/stream?key=<api-key>`

**Send frame (text)**
```json
{"content": "User prompt", "strict": false}
```

**Receive frames**
```json
{"type": "result", "allowed": true,  "risk_level": "LOW",  ...}
{"type": "error",  "code": 413,     "detail": "Payload too large."}
```

---

## 7. API Reference — Analytics Service

Base URL: `http://analytics:8002`

All endpoints are read-only (`GET`). No authentication required (internal network only).

---

### `GET /health`

```json
{"status": "ok", "service": "warden-analytics"}
```

---

### `GET /api/v1/events`

Return the most-recent filter events.

| Query param | Default | Description |
|------------|---------|-------------|
| `limit` | 100 | Max events to return (1–1000) |
| `days` | 7 | Lookback window (1–30) |
| `allowed` | _(all)_ | `true` / `false` to filter by outcome |

**Response**
```json
{
  "total": 42,
  "events": [
    {"ts": "2026-03-10T09:00:00+00:00", "request_id": "...", "allowed": false, ...}
  ]
}
```

Events are sorted newest-first.

---

### `GET /api/v1/events/{request_id}`

Return a single log entry by `request_id`. Returns `404` if not found.

---

### `GET /api/v1/stats`

Aggregated statistics for the requested window.

| Query param | Default | Range |
|------------|---------|-------|
| `days` | 7 | 1–30 |

**Response**
```json
{
  "days":           7,
  "total":          1204,
  "allowed":        1189,
  "blocked":        15,
  "block_rate_pct": 1.25,
  "avg_latency_ms": 47.3,
  "by_day": {
    "2026-03-09": {"total": 300, "blocked": 4},
    "2026-03-10": {"total": 410, "blocked": 6}
  }
}
```

---

### `GET /api/v1/attack-cost`

Cost-to-Attack metrics — the aggregate USD cost of all blocked payloads. See [§14](#14-cost-to-attack-metrics) for the model.

| Query param | Default | Range |
|------------|---------|-------|
| `days` | 7 | 1–30 |

**Response**
```json
{
  "days":                  7,
  "total_requests":        1204,
  "total_blocked":         15,
  "total_attack_cost_usd": 0.00062,
  "avg_cost_per_attack":   0.0000413,
  "total_tokens_blocked":  6200,
  "costliest_attack_usd":  0.00015,
  "by_risk_level": {
    "high":  {"count": 12, "total_cost_usd": 0.00047, "total_tokens": 4700},
    "block": {"count":  3, "total_cost_usd": 0.00015, "total_tokens": 1500}
  },
  "by_day": {
    "2026-03-09": {"count": 6,  "total_cost_usd": 0.00025},
    "2026-03-10": {"count": 9,  "total_cost_usd": 0.00037}
  }
}
```

When `total_blocked == 0`, all cost fields are `0.0` and `by_risk_level` / `by_day` are empty objects.

---

### `GET /api/v1/threats`

Frequency breakdown of threat flag types detected in the window.

| Query param | Default | Range |
|------------|---------|-------|
| `days` | 7 | 1–30 |
| `limit` | 10 | 1–50 |

**Response**
```json
{
  "days":        7,
  "total_flags": 38,
  "threats": [
    {"flag": "prompt_injection", "count": 19},
    {"flag": "jailbreak",        "count": 11},
    {"flag": "shell_cmd",        "count":  8}
  ]
}
```

---

## 8. OpenAI-Compatible Proxy

`warden/openai_proxy.py` mounts at `/v1` and provides a drop-in OpenAI replacement.

**Integration:** set `OPENAI_BASE_URL=http://localhost/api/warden` in your existing OpenAI client — no other code changes needed.

### Endpoints proxied

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/chat/completions` | Filter → forward → ToolCallGuard |
| `GET` | `/v1/models` | Transparent proxy to `OPENAI_UPSTREAM` |

### Pipeline (per request)

```
POST /v1/chat/completions
  │
  ├─ [Phase A] inspect role=tool messages
  │       ToolCallGuard.inspect_result() on each tool result
  │       → 400 tool_result_blocked on threat
  │
  ├─ extract last user message → POST /filter
  │       → 403 if blocked by Warden
  │       → replace with filtered_content if allowed
  │
  ├─ forward to OPENAI_UPSTREAM
  │       → 502 if upstream unreachable
  │
  └─ [Phase B] inspect tool_calls in upstream response
          ToolCallGuard.inspect_call() on each function call
          → 400 tool_call_blocked on threat
          → return upstream response if clean
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_UPSTREAM` | `https://api.openai.com` | Upstream model provider URL |
| `WARDEN_FILTER_URL` | `http://localhost:8001` | Internal Warden gateway URL |

---

## 9. Multi-Tenancy

Every filter request carries an optional `tenant_id` field. The gateway maintains a per-tenant `BrainSemanticGuard` instance so that each tenant's ML corpus is isolated.

```python
{"content": "...", "tenant_id": "acme"}
```

- Default tenant: `"default"` (when `tenant_id` is omitted)
- Per-tenant guards are created lazily on first request for that tenant
- Per-tenant API keys can specify a `rate_limit` (see [§10](#10-authentication))
- The `/health` endpoint reports active tenant IDs

---

## 10. Authentication

`warden/auth_guard.py` validates the `X-API-Key` header on every protected endpoint.

### Modes

| `WARDEN_API_KEY` env | Behaviour |
|---------------------|-----------|
| _(unset / empty)_ | Auth disabled — all requests pass (dev/test) |
| `sk-single-key` | Single static key |
| Path to JSON file | Multi-key per-tenant mode (see below) |

### Multi-key JSON format

```json
{
  "tenants": {
    "acme": {
      "keys": ["sk-acme-prod", "sk-acme-staging"],
      "rate_limit": 120
    },
    "internal": {
      "keys": ["sk-internal-only"],
      "rate_limit": 600
    }
  }
}
```

Key comparison uses `hmac.compare_digest` (constant-time) on SHA-256 hashes — no timing oracle.

### AuthResult

`require_api_key()` returns an `AuthResult` dataclass:

```python
@dataclass
class AuthResult:
    tenant_id: str       # resolved tenant
    api_key:   str       # key used (for downstream /filter auth forwarding)
    rate_limit: int      # effective req/min for this tenant
```

---

## 11. Rate Limiting

`slowapi` token-bucket limiter, backed by Redis.

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_PER_MINUTE` | `60` | Global IP-level limit |
| Per-tenant `rate_limit` | `60` | Set in the auth JSON (overrides global) |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection (use `memory://` in tests) |

When the limit is exceeded the gateway returns `HTTP 429 Too Many Requests`.
Fail-open: if Redis is unavailable, rate limiting is bypassed and the request proceeds.

---

## 12. Caching

`warden/cache.py` caches identical content using a SHA-256 content hash as the key.

- **TTL:** 5 minutes (configurable via `CACHE_TTL_SECONDS`)
- **Backend:** Redis (fail-open — cache miss on connection error)
- **Scope:** per-process; the hash includes content only (not tenant or strict mode)
- **Effect:** cache hit skips all five pipeline stages and returns the stored `FilterResponse`

---

## 13. Observability

### Prometheus metrics

Exposed at `GET /metrics` (via `prometheus-fastapi-instrumentator`).

| Metric | Labels | Description |
|--------|--------|-------------|
| `http_requests_total` | method, handler, status | FastAPI default |
| `http_request_duration_seconds` | handler | P50/P95/P99 latency |
| `warden_tool_blocks_total` | direction, tool_name, threat | ToolCallGuard blocks |

### Grafana dashboard

Pre-provisioned at `grafana/dashboards/warden_overview.json`.

Panels include:
- Request rate (req/s), error rate (5xx %)
- P99 filter latency
- Block rate by risk level
- Top threat flags (bar chart)
- Tool Guard Blocks (stacked bar: `call` vs `result`, by threat type)
- Cost-to-Attack daily spend (area chart)

### Grafana alerts

`grafana/provisioning/alerting/warden_alerts.yml`:

| Alert | Condition | Severity |
|-------|-----------|----------|
| `warden-high-latency` | P99 > 500 ms for 5 min | warning |
| `warden-high-error-rate` | 5xx rate > 1% over 5 min | critical |

### Real-time alerting

`warden/alerting.py` fires on every HIGH or BLOCK decision.

| Channel | Config |
|---------|--------|
| Slack | `SLACK_WEBHOOK_URL` |
| PagerDuty | `PAGERDUTY_ROUTING_KEY` |

Alerts include: `request_id`, `risk_level`, `flags`, `tenant_id`, `content_len` (no content).

### SIEM integration

`warden/analytics/siem.py`:

| Target | Config |
|--------|--------|
| Splunk HEC | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` |
| Elastic ECS | `ELASTIC_URL`, `ELASTIC_API_KEY` |

Log entries are shipped as ECS-compliant JSON events.

---

## 14. Cost-to-Attack Metrics

Shadow Warden AI models the economic cost of generating each blocked payload. This converts security events into a business metric: **how much did it cost the attacker to send this attack?**

### Model

```
payload_tokens   = len(content) // 4          (approximation: 1 token ≈ 4 chars)
attack_cost_usd  = payload_tokens × $0.000002  (= $2.00 per 1M input tokens, Sonnet pricing)
```

The constant `COST_PER_TOKEN_USD = 2e-6` is defined in `warden/analytics/logger.py`.

### Why it matters

| Metric | Business interpretation |
|--------|------------------------|
| `total_attack_cost_usd` | Attacker's estimated spend on blocked attacks in the window |
| `avg_cost_per_attack` | Average sophistication of an attack (longer prompts = more expensive jailbreaks) |
| `costliest_attack_usd` | Identifies the most elaborate attack in the period |
| `by_day` time-series | Visualise attacker spend over time — rising trend = escalating campaign |

### Where it appears

- **EventLogger** — `payload_tokens` and `attack_cost_usd` in every log entry
- **Analytics API** — `GET /api/v1/attack-cost` (see [§7](#7-api-reference--analytics-service))
- **Streamlit dashboard** — "Cost-to-Attack" section with KPI cards and area chart
- **Grafana** — "Cost-to-Attack Daily Spend" panel

---

## 15. GDPR Compliance

### What is logged (metadata only)

```json
{
  "ts":              "2026-03-10T09:15:01.123456+00:00",
  "request_id":      "a1b2c3d4-e5f6-...",
  "allowed":         false,
  "risk_level":      "HIGH",
  "flags":           ["prompt_injection"],
  "secrets_found":   ["openai_api_key"],
  "content_len":     342,
  "elapsed_ms":      47.3,
  "payload_tokens":  85,
  "attack_cost_usd": 0.00017,
  "tenant_id":       "acme",
  "strict":          false
}
```

### What is never logged

| Data | Status |
|------|--------|
| Prompt / request content | ❌ Never stored |
| Redacted secret values | ❌ Never stored |
| Email addresses, phone numbers | ❌ Never stored |
| IP addresses | ❌ Never stored |
| User identifiers | ❌ Never stored |

### Retention

Log entries older than `GDPR_LOG_RETENTION_DAYS` (default: 30) are filtered out of all API responses and can be explicitly purged via `POST /gdpr/purge`.

### Data residency

No data leaves your infrastructure except:
- **Claude Opus** (Evolution Engine, optional) — receives only attack flags and metadata, never raw content
- **HuggingFace Hub** — downloads `all-MiniLM-L6-v2` once on first startup

### GDPR Article 30

- **Controller:** Your organisation
- **Processor:** Shadow Warden AI (self-hosted, no sub-processor)
- **Purpose:** Security monitoring and attack prevention
- **Legal basis:** Article 6(1)(f) — legitimate interests
- **Categories of data:** Security event metadata (no personal data)
- **Retention:** Configurable, default 30 days
- **International transfers:** None

---

## 16. Integration Patterns

### Pattern 1 — Direct `/filter` call

```python
import httpx, os

WARDEN_URL = os.getenv("WARDEN_URL", "http://warden:8001")

async def safe_prompt(text: str, tenant_id: str = "default") -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(
            f"{WARDEN_URL}/filter",
            json={"content": text, "tenant_id": tenant_id},
            headers={"X-API-Key": os.getenv("WARDEN_API_KEY", "")},
        )
        r.raise_for_status()
    data = r.json()
    if not data["allowed"]:
        raise PermissionError(f"Warden: {data['reason']}")
    return data["filtered_content"]   # redacted, safe to forward to any LLM
```

### Pattern 2 — OpenAI proxy (drop-in)

```python
from openai import OpenAI

client = OpenAI(
    api_key="your-openai-key",
    base_url="http://localhost/api/warden/v1",   # all traffic through Warden
    default_headers={"X-API-Key": "your-warden-key"},
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
```

Tool calls in the response are automatically inspected by ToolCallGuard before being returned.

### Pattern 3 — LangChain callback

```python
from warden.integrations.langchain_callback import WardenCallback
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(callbacks=[WardenCallback(warden_url="http://warden:8001")])
```

`WardenCallback` is duck-typed — no LangChain version pinning required.

### Pattern 4 — Batch filtering (bulk ingestion)

```python
items = [{"content": text} for text in user_inputs]
async with httpx.AsyncClient() as client:
    r = await client.post(
        "http://warden:8001/filter/batch",
        json={"items": items},
        headers={"X-API-Key": "..."},
    )
results = r.json()["results"]
safe_texts = [r["filtered_content"] for r in results if r["allowed"]]
```

---

## 17. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | — | **Required in production.** 32-byte hex — `python -c "import secrets; print(secrets.token_hex(32))"` |
| `POSTGRES_PASS` | — | **Required in production.** PostgreSQL password |
| `ANTHROPIC_API_KEY` | _(blank)_ | Claude API key — enables Evolution Engine. Omit for air-gapped mode |
| `WARDEN_API_KEY` | _(blank)_ | API key auth. Blank = auth disabled. Path to JSON = multi-tenant mode |
| `SEMANTIC_THRESHOLD` | `0.72` | ML jailbreak sensitivity (0.0–1.0). Lower = more sensitive |
| `STRICT_MODE` | `false` | `true` = block MEDIUM-risk requests |
| `RATE_LIMIT_PER_MINUTE` | `60` | Global IP-level rate limit |
| `MAX_BATCH_SIZE` | `50` | Max items in `POST /filter/batch` |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string. Use `memory://` in tests |
| `CACHE_TTL_SECONDS` | `300` | Cache entry TTL |
| `GDPR_LOG_RETENTION_DAYS` | `30` | Days before log entries are considered expired |
| `LOGS_PATH` | `/warden/data/logs.json` | NDJSON event log path |
| `DYNAMIC_RULES_PATH` | `/warden/data/dynamic_rules.json` | Evolution Engine output |
| `MODEL_CACHE_DIR` | `/warden/models` | MiniLM model weights cache directory |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warning` / `error` |
| `OPENAI_UPSTREAM` | `https://api.openai.com` | Upstream for the OpenAI proxy |
| `WARDEN_FILTER_URL` | `http://localhost:8001` | Internal gateway URL (used by OpenAI proxy) |
| `SLACK_WEBHOOK_URL` | _(blank)_ | Slack incoming webhook for real-time alerts |
| `PAGERDUTY_ROUTING_KEY` | _(blank)_ | PagerDuty Events API v2 key |
| `SPLUNK_HEC_URL` | _(blank)_ | Splunk HTTP Event Collector URL |
| `SPLUNK_HEC_TOKEN` | _(blank)_ | Splunk HEC token |
| `ELASTIC_URL` | _(blank)_ | Elasticsearch base URL |
| `ELASTIC_API_KEY` | _(blank)_ | Elastic API key |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed CORS origins |
| `ENV` | `development` | `development` or `production` |

---

## 18. Testing

### Prerequisites

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt
```

### Test environment (set by `conftest.py`)

```
ANTHROPIC_API_KEY=""
WARDEN_API_KEY=""
SEMANTIC_THRESHOLD="0.72"
LOGS_PATH="/tmp/warden_test_logs.json"
DYNAMIC_RULES_PATH="/tmp/warden_test_dynamic_rules.json"
STRICT_MODE="false"
REDIS_URL="memory://"
MODEL_CACHE_DIR="/tmp/warden_test_models"
```

### Test commands

```bash
# Fast: unit tests only (no ML model, no external services)
pytest warden/tests/ -m "not adversarial and not slow" -v

# Full non-adversarial suite including integration tests (downloads model once)
pytest warden/tests/ -m "not adversarial" --cov=warden --cov-fail-under=75 -q

# Adversarial corpus (informational — does not block CI)
pytest warden/tests/ -m "adversarial" -v || true

# Single module
pytest warden/tests/test_tool_guard.py -v
pytest warden/tests/test_analytics_api.py -v
```

### Test suite summary (v0.4)

| Test file | Tests | Scope |
|-----------|------:|-------|
| `test_tool_guard.py` | 68 | ToolCallGuard all threat categories + directionality |
| `test_analytics_api.py` | 24 | Analytics service including `/api/v1/attack-cost` |
| `test_openai_proxy.py` | ~20 | OpenAI proxy + ToolCallGuard integration + Prometheus counters |
| `test_logger.py` | 26 | EventLogger including cost-to-attack fields |
| `test_secret_redactor.py` | ~35 | All 15 PII/secret patterns |
| `test_obfuscation.py` | 14 | Base64/hex/ROT13/homoglyph decoder |
| `test_semantic_guard.py` | ~15 | Rule engine + compound escalation |
| `test_auth_guard.py` | ~15 | Per-tenant key validation |
| `test_filter_endpoint.py` | ~15 | `/filter` end-to-end integration |
| `test_evolution.py` | ~10 | Evolution Engine (mocked Anthropic) |
| `test_mtls.py` | ~12 | mTLS module |
| `test_ws.py` | ~12 | WebSocket streaming |
| `test_tenant_rate_limit.py` | ~10 | Per-tenant rate limiting |

**Total: 345 tests · 92% coverage (gate: ≥ 75%)**

### Pytest markers

| Marker | Meaning |
|--------|---------|
| `adversarial` | Jailbreak corpus tests — informational only |
| `slow` | Requires ML model download |
| `integration` | Requires running FastAPI app |

### Mutation testing

```bash
# Linux/WSL/CI only
mutmut run --no-progress
mutmut results
```

Threshold: ≤ 20 surviving mutants on `secret_redactor.py` + `semantic_guard.py`.

---

## 19. CI / CD

Three GitHub Actions jobs:

### `test` (matrix: Python 3.11, 3.12)

1. Install CPU-only torch + dependencies
2. Run unit tests (`not adversarial and not slow`)
3. Run full suite for coverage gate (`--cov-fail-under=75`)
4. Run adversarial corpus (`|| true` — informational)
5. Run mutmut (informational)

Model weights are cached via `actions/cache` at key `warden-model-all-minilm-l6-v2-v1`.

### `lint`

```bash
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```

### `docker-build` (smoke test)

- **Phase 1:** `docker run --rm warden-ci python -c "import warden.main"` (no model)
- **Phase 2:** `/health` probe against a running warden container (with model cache)
- Separate analytics image build + import smoke test

---

## 20. Deployment Checklist

### Before first deploy

- [ ] `SECRET_KEY` — generate: `python -c "import secrets; print(secrets.token_hex(32))"`
- [ ] `POSTGRES_PASS` — strong unique password
- [ ] `WARDEN_API_KEY` — path to multi-tenant JSON file (or single key)
- [ ] `DASHBOARD_PASSWORD_HASH` — `python -m warden.analytics.auth`
- [ ] `GRAFANA_PASSWORD` — change from default
- [ ] TLS certificate in `nginx/certs/` (or Let's Encrypt via certbot)
- [ ] Review `CORS_ORIGINS` — restrict to your app's domain

### Optional but recommended

- [ ] `ANTHROPIC_API_KEY` — enables Evolution Engine auto-rule generation
- [ ] `SLACK_WEBHOOK_URL` — real-time attack notifications
- [ ] `PAGERDUTY_ROUTING_KEY` — on-call escalation for BLOCK events
- [ ] `SPLUNK_HEC_URL` / `ELASTIC_URL` — SIEM integration
- [ ] Set `ENV=production` — disables debug endpoints

### Air-gapped deployment

Leave `ANTHROPIC_API_KEY` unset. Pre-download the MiniLM model:

```bash
python -c "
from sentence_transformers import SentenceTransformer
SentenceTransformer('all-MiniLM-L6-v2', cache_folder='/path/to/offline/models')
"
```

Set `MODEL_CACHE_DIR` to your offline model path. The gateway operates fully offline.

### Resource requirements (production)

| Component | CPU | RAM | Notes |
|-----------|-----|-----|-------|
| warden | 1 vCPU | 1.5 GB | MiniLM model ~400 MB |
| analytics | 0.25 vCPU | 256 MB | Read-only, stateless |
| dashboard | 0.5 vCPU | 512 MB | Streamlit process |
| redis | 0.25 vCPU | 256 MB | Cache + rate limiter |
| postgres | 0.5 vCPU | 512 MB | Persistent store |
| **Total** | **~3 vCPU** | **~3.5 GB** | Excludes Grafana/Prometheus |
