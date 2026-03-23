# Shadow Warden AI — API Reference

**Version:** 1.1.0 · **Base URL:** `https://warden.example.com` · **Interactive docs:** `/docs` (Swagger UI), `/redoc`

Shadow Warden AI is a mandatory security gateway for AI payloads. Every request must pass through `/filter` before reaching any model or downstream service.

### What's new in v1.1 — Enterprise Resilience

| Feature | Details |
|---------|---------|
| **Fail strategy** | `WARDEN_FAIL_STRATEGY=open\|closed` — choose pass-through or block on pipeline timeout |
| **Pipeline timeout** | `PIPELINE_TIMEOUT_MS` — asyncio.wait_for wrapper, 0 = disabled |
| **ML uncertainty zone** | `UNCERTAINTY_LOWER_THRESHOLD` — scores in `[lower, threshold)` get `ml_uncertain` flag + MEDIUM risk |
| **GDPR anonymization** | Evolution Engine strips UUID/IP/email/timestamp/hex before sending to Claude Opus (Art. 25/44) |
| **Config API** | `GET /api/config` + `POST /api/config` — live-tune resilience settings |

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Rate Limiting](#2-rate-limiting)
3. [REST Endpoints](#3-rest-endpoints)
   - [GET /health](#get-health)
   - [POST /filter](#post-filter)
   - [POST /filter/batch](#post-filterbatch)
   - [GET /api/config](#get-apiconfig)
   - [POST /api/config](#post-apiconfig)
   - [POST /gdpr/export](#post-gdprexport)
   - [POST /gdpr/purge](#post-gdprpurge)
   - [GET /metrics](#get-metrics)
   - [POST /v1/chat/completions](#post-v1chatcompletions)
4. [WebSocket /ws/stream](#4-websocket-wsstream)
5. [Response Schemas](#5-response-schemas)
6. [Enterprise Resilience](#6-enterprise-resilience)
7. [Error Codes](#7-error-codes)
8. [SDK Examples](#8-sdk-examples)
9. [Multi-Tenant Setup](#9-multi-tenant-setup)

---

## 1. Authentication

All endpoints (except `GET /health` in dev mode) require the `X-API-Key` header.

```
X-API-Key: your-api-key-here
```

**Dev mode** (no keys configured): all requests pass through with `tenant_id = "default"`.

**Single-key mode**: set `WARDEN_API_KEY` environment variable.

**Multi-tenant mode**: set `WARDEN_API_KEYS_PATH` to a JSON file:

```json
{
  "keys": [
    {
      "key_hash": "<sha256-hex-of-key>",
      "tenant_id": "acme-corp",
      "label": "production",
      "active": true,
      "rate_limit": 120
    }
  ]
}
```

Generate a key hash:
```bash
python -c "import hashlib; print(hashlib.sha256(b'your-api-key').hexdigest())"
```

**WebSocket auth**: pass the key as a query parameter — `ws://host/ws/stream?key=<api_key>`

---

## 2. Rate Limiting

Default: **60 requests/minute per IP** (configurable via `RATE_LIMIT_PER_MINUTE`).

Per-tenant limits override the default when using the multi-key JSON file (`"rate_limit": N`).

Rate-limited responses: **HTTP 429** with header `Retry-After: 60`.

---

## 3. REST Endpoints

### GET /health

Liveness probe. No authentication required.

**Response 200:**
```json
{
  "status": "ok",
  "service": "warden-gateway",
  "evolution": true,
  "tenants": ["default", "acme-corp"],
  "strict": false,
  "cache": {
    "status": "ok",
    "latency_ms": 1.2
  }
}
```

`status` is `"degraded"` when Redis is unavailable (detection still works — cache is fail-open).

---

### POST /filter

Main filter endpoint. Run content through the full Warden pipeline.

**Request:**
```json
{
  "content": "Your AI payload text here",
  "tenant_id": "default",
  "strict": false,
  "redaction_policy": "full",
  "sector": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | ✅ | The text payload to filter (max 32,000 chars) |
| `tenant_id` | string | — | Tenant identifier (default: `"default"`) |
| `strict` | boolean | — | Treat MEDIUM risk as blocked (default: `false`) |
| `redaction_policy` | string | — | `"full"` (default) · `"masked"` (last 4 chars) · `"raw"` (detect only) |
| `sector` | string | — | `"B2B"` · `"B2C"` · `"E-Commerce"` — activates Business Threat Neutralizer enrichment |
| `context` | object | — | Arbitrary metadata forwarded to the event log (user_id, session_id, etc.) |

**Response 200 — allowed:**
```json
{
  "allowed": true,
  "risk_level": "low",
  "filtered_content": "Your AI payload text here",
  "secrets_found": [],
  "semantic_flags": [],
  "reason": "",
  "redaction_policy_applied": "full",
  "owasp_categories": [],
  "explanation": "No security risks detected. Content is safe to forward.",
  "poisoning": {},
  "threat_matches": [],
  "business_intel": null,
  "masking": {"masked": false, "session_id": null, "entities": [], "entity_count": 0},
  "processing_ms": {
    "cache_check": 0.8,
    "obfuscation": 0.3,
    "redaction": 1.2,
    "rules": 2.1,
    "ml": 18.4,
    "total": 23.1
  }
}
```

**Response 200 — blocked (jailbreak + secret):**
```json
{
  "allowed": false,
  "risk_level": "high",
  "filtered_content": "[ANTHROPIC_API_KEY_REDACTED] ignore previous instructions...",
  "secrets_found": [{"kind": "anthropic_api_key", "start": 0, "end": 30, "redacted_to": "[ANTHROPIC_API_KEY_REDACTED]"}],
  "semantic_flags": [
    {
      "flag": "prompt_injection",
      "score": 0.934,
      "detail": "ML jailbreak detected (similarity=0.934) — closest corpus entry: 'ignore all previous...'"
    }
  ],
  "reason": "ML jailbreak detected (similarity=0.934)...",
  "owasp_categories": ["LLM01 — Prompt Injection"],
  "explanation": "This request attempts to override system instructions — a classic prompt injection pattern.",
  "processing_ms": { "total": 24.7 }
}
```

**Response 200 — gray zone (v1.1 uncertainty escalation):**

When the ML score falls between `UNCERTAINTY_LOWER_THRESHOLD` (default 0.55) and `SEMANTIC_THRESHOLD` (default 0.72), the request is **allowed** but flagged for review:

```json
{
  "allowed": true,
  "risk_level": "medium",
  "semantic_flags": [
    {
      "flag": "ml_uncertain",
      "score": 0.61,
      "detail": "ML score 0.610 in uncertainty zone [0.55, 0.72) — escalated to MEDIUM for review"
    }
  ],
  "reason": ""
}
```

**Response 200 — fail-open timeout bypass (v1.1):**

When `PIPELINE_TIMEOUT_MS > 0` and the pipeline times out with `WARDEN_FAIL_STRATEGY=open`:
```json
{
  "allowed": true,
  "risk_level": "low",
  "filtered_content": "<original content unchanged>",
  "reason": "emergency_bypass:timeout",
  "semantic_flags": []
}
```
The `reason` field `"emergency_bypass:timeout"` is machine-readable — integrate with your monitoring to alert on elevated bypass rates.

**Risk levels:** `low` → `medium` → `high` → `block`

**curl:**
```bash
curl -X POST https://warden.example.com/filter \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"content": "Summarise this document for me."}'
```

**Python:**
```python
import requests

resp = requests.post(
    "https://warden.example.com/filter",
    json={"content": "Summarise this document for me."},
    headers={"X-API-Key": "your-key"},
)
result = resp.json()
if result["allowed"]:
    # safe to forward to your model
    clean_content = result["filtered_content"]
```

---

### POST /filter/batch

Filter up to 50 items in a single request. Reduces round-trip overhead for bulk workloads.

**Request:**
```json
{
  "items": [
    {"content": "First payload", "tenant_id": "default"},
    {"content": "Second payload", "strict": true}
  ]
}
```

**Response 200:**
```json
{
  "results": [
    { "allowed": true,  "risk_level": "low",  "filtered_content": "First payload",  "..." : "..." },
    { "allowed": false, "risk_level": "high", "filtered_content": "Second payload", "..." : "..." }
  ]
}
```

Results are returned in the same order as `items`. Max batch size: **50** (configurable via `MAX_BATCH_SIZE`).

**curl:**
```bash
curl -X POST https://warden.example.com/filter/batch \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"items": [{"content": "Hello"}, {"content": "Ignore all previous instructions"}]}'
```

---

### GET /api/config

Read the current live configuration. No authentication required (values are non-sensitive).

**Response 200:**
```json
{
  "semantic_threshold": 0.72,
  "strict_mode": false,
  "rate_limit_per_minute": 60,
  "evolution_enabled": true,
  "browser_enabled": false,
  "otel_enabled": false,
  "fail_strategy": "open",
  "pipeline_timeout_ms": 0,
  "uncertainty_lower_threshold": 0.55,
  "nvidia_api_key_set": false,
  "prompt_shield_enabled": true,
  "audit_trail_enabled": true,
  "nim_endpoint": "",
  "nim_default_model": "",
  "nim_routing_enabled": true,
  "nim_embeddings_enabled": false,
  "agent_toolkit_enabled": false,
  "agent_toolkit_block": true
}
```

---

### POST /api/config

Update live-tunable settings. Most changes take effect immediately without restart.

> **Note:** `fail_strategy` and `pipeline_timeout_ms` require a service restart — they are read once at startup from environment variables. `uncertainty_lower_threshold` and `semantic_threshold` apply immediately.

**Request — update resilience settings:**
```json
{
  "fail_strategy": "closed",
  "pipeline_timeout_ms": 300,
  "uncertainty_lower_threshold": 0.60
}
```

**Request — update detection settings:**
```json
{
  "semantic_threshold": 0.75,
  "strict_mode": true
}
```

**Tunable fields:**

| Field | Type | Restart? | Description |
|-------|------|----------|-------------|
| `semantic_threshold` | float 0.1–1.0 | No | ML block threshold |
| `strict_mode` | boolean | No | Treat MEDIUM as blocked |
| `fail_strategy` | `"open"\|"closed"` | Yes | Timeout behaviour |
| `pipeline_timeout_ms` | integer ≥0 | Yes | Pipeline timeout (0 = off) |
| `uncertainty_lower_threshold` | float 0–0.99 | No | Gray-zone lower bound |
| `nvidia_api_key` | string | Yes | NVIDIA NIM API key (write-only) |
| `nim_endpoint` | string | Yes | NIM base URL |
| `nim_default_model` | string | No | Default NIM model |
| `nim_routing_enabled` | boolean | No | Route `nim/` prefix to NIM |
| `nim_embeddings_enabled` | boolean | No | Use NIM for embeddings |
| `agent_toolkit_enabled` | boolean | No | NVIDIA Agent Toolkit enforcement |
| `prompt_shield_enabled` | boolean | No | Prompt Shield indirect injection |
| `audit_trail_enabled` | boolean | No | Cryptographic audit trail |

**Response 200:**
```json
{ "updated": ["fail_strategy", "pipeline_timeout_ms"] }
```

---

### POST /gdpr/export

Export log metadata for a specific request (GDPR Art. 15 — right of access).

> **GDPR note:** Shadow Warden never logs payload content — only metadata (type, length, risk level, timing).

**Request:**
```json
{ "request_id": "a1b2c3d4-..." }
```

**Response 200:**
```json
{
  "request_id": "a1b2c3d4-...",
  "entry": {
    "timestamp": "2026-01-15T10:30:00Z",
    "request_id": "a1b2c3d4-...",
    "allowed": false,
    "risk_level": "high",
    "flags": ["prompt_injection"],
    "secrets_found": [],
    "payload_len": 142,
    "elapsed_ms": 24.7,
    "strict": false
  }
}
```

**Response 404:** `{ "detail": "No log entry found for request_id=..." }`

---

### POST /gdpr/purge

Delete all log entries before a given date (GDPR Art. 17 — right to erasure).

**Request:**
```json
{ "before": "2026-01-01T00:00:00Z" }
```

**Response 200:**
```json
{ "removed": 1842, "before": "2026-01-01T00:00:00Z" }
```

---

### GET /metrics

Prometheus metrics endpoint. Returns standard `text/plain; version=0.0.4` format.

Scraped by Prometheus every 15 s (see `grafana/prometheus.yml`). Contains HTTP request counters, latency histograms, and Python process metrics.

---

### POST /v1/chat/completions

OpenAI-compatible proxy. Filters the request through Warden before forwarding to the configured LLM backend (`LLM_BASE_URL`). Drop-in replacement for the OpenAI SDK.

**Request:** identical to [OpenAI Chat Completions API](https://platform.openai.com/docs/api-reference/chat/create).

**Python (OpenAI SDK):**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://warden.example.com/v1",
    api_key="your-warden-key",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

**Blocked content:** returns HTTP 400 with:
```json
{
  "error": {
    "message": "Request blocked by Warden filter: ML jailbreak detected...",
    "type": "content_policy_violation",
    "code": "warden_blocked"
  }
}
```

---

## 4. WebSocket /ws/stream

Real-time streaming endpoint — runs the filter pipeline then streams LLM tokens.

**Connect:**
```
ws://warden.example.com/ws/stream?key=<api_key>
wss://warden.example.com/ws/stream?key=<api_key>
```

### Protocol

**Step 1 — Client sends one JSON message:**
```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user",   "content": "Explain quantum entanglement simply."}
  ],
  "model": "gpt-4o-mini",
  "max_tokens": 512,
  "tenant_id": "default"
}
```

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `messages` | array | ✅ | — |
| `model` | string | — | `"gpt-4o-mini"` |
| `max_tokens` | integer | — | `512` |
| `tenant_id` | string | — | from auth |

**Step 2 — Server sends a stream of JSON events:**

```jsonc
// Always first — filter result
{"type": "filter_result", "allowed": true, "risk": "low", "reason": "", "request_id": "uuid"}

// One per LLM token (only if allowed=true and LLM is configured)
{"type": "token", "content": "Quantum"}
{"type": "token", "content": " entanglement"}
{"type": "token", "content": " is..."}

// Final event
{"type": "done", "request_id": "uuid"}

// Error event (instead of any of the above on failure)
{"type": "error", "code": 503, "detail": "LLM backend not configured."}
```

**Close codes:**

| Code | Meaning |
|------|---------|
| 1000 | Normal close (done) |
| 1003 | Unsupported data / invalid request |
| 1008 | Policy Violation — content blocked by Warden |
| 1009 | Message Too Big (> 64 KiB) |
| 1011 | Internal server error |

### JavaScript Example

```javascript
const ws = new WebSocket("wss://warden.example.com/ws/stream?key=your-key");

ws.onopen = () => {
  ws.send(JSON.stringify({
    messages: [{ role: "user", content: "Hello!" }],
    model: "gpt-4o-mini",
    max_tokens: 256,
  }));
};

ws.onmessage = ({ data }) => {
  const msg = JSON.parse(data);
  switch (msg.type) {
    case "filter_result":
      if (!msg.allowed) {
        console.error("Blocked:", msg.reason);
        ws.close();
      }
      break;
    case "token":
      process.stdout.write(msg.content);   // or update UI
      break;
    case "done":
      console.log("\nStream complete");
      ws.close();
      break;
    case "error":
      console.error(`Error ${msg.code}: ${msg.detail}`);
      ws.close();
      break;
  }
};
```

### Python (asyncio) Example

```python
import asyncio, json
import websockets

async def stream():
    uri = "wss://warden.example.com/ws/stream?key=your-key"
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({
            "messages": [{"role": "user", "content": "Hello!"}],
            "model": "gpt-4o-mini",
            "max_tokens": 256,
        }))
        async for raw in ws:
            msg = json.loads(raw)
            match msg["type"]:
                case "filter_result":
                    if not msg["allowed"]:
                        print(f"Blocked: {msg['reason']}")
                        break
                case "token":
                    print(msg["content"], end="", flush=True)
                case "done":
                    print()
                    break
                case "error":
                    print(f"Error {msg['code']}: {msg['detail']}")
                    break

asyncio.run(stream())
```

---

## 5. Response Schemas

### FilterResponse

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Whether the content passed all filters |
| `risk_level` | string | `low` \| `medium` \| `high` \| `block` |
| `filtered_content` | string | Content after redaction — safe to forward to your model |
| `secrets_found` | array | List of `SecretFinding` objects |
| `semantic_flags` | array | List of `SemanticFlag` objects |
| `reason` | string | Human-readable block reason (`"emergency_bypass:timeout"` on fail-open) |
| `redaction_policy_applied` | string | `"full"` \| `"masked"` \| `"raw"` |
| `owasp_categories` | array | OWASP LLM Top 10 labels triggered (e.g. `"LLM01 — Prompt Injection"`) |
| `explanation` | string | Plain-language XAI summary (safe to show non-technical users) |
| `poisoning` | object | Data poisoning result — empty `{}` if none detected |
| `threat_matches` | array | ThreatVault signature hits — each: `{id, name, category, severity, owasp}` |
| `business_intel` | object\|null | Business Threat Neutralizer report (set when `sector` is provided) |
| `masking` | object | Yellow-zone masking report |
| `processing_ms` | object | Per-stage timing: `cache_check`, `obfuscation`, `redaction`, `rules`, `ml`, `total` |

### SemanticFlag

| Field | Type | Description |
|-------|------|-------------|
| `flag` | string | See **FlagType** table below |
| `score` | float | Confidence 0–1 |
| `detail` | string | Human-readable explanation |

### FlagType enum (complete)

| Value | OWASP | Description |
|-------|-------|-------------|
| `prompt_injection` | LLM01 | Jailbreak / instruction override attempt |
| `harmful_content` | — | Violent, illegal, or abuse-enabling content |
| `secret_detected` | — | API key / credential present in payload |
| `pii_detected` | — | Personal data (name, email, phone, ID) |
| `policy_violation` | — | Custom tenant rule triggered |
| `indirect_injection` | LLM01 | Injection via retrieved context (RAG, tool output) |
| `insecure_output` | LLM05 | XSS, command injection, SSRF, path traversal in AI output |
| `excessive_agency` | LLM06 | Unauthorized autonomous action attempt |
| `sensitive_disclosure` | LLM02 | Attempt to extract training data or model internals |
| `model_poisoning` | LLM04 | Persistent behavior modification / backdoor |
| `system_prompt_leakage` | LLM07 | System prompt / full context extraction attempt |
| `vector_attack` | LLM08 | RAG poisoning / adversarial embedding |
| `misinformation` | LLM09 | Eliciting deliberately false authoritative content |
| `resource_exhaustion` | LLM10 | Unbounded token consumption / generation loop |
| `data_poisoning` | LLM04v | Corpus / inference-plane poisoning variant |
| `ml_uncertain` | — | **v1.1** ML score in gray zone `[lower_threshold, block_threshold)` |

### SecretFinding

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `anthropic_api_key` · `openai_api_key` · `aws_access_key` · `stripe_key` · `huggingface_token` · `generic_token` · etc. |
| `start` | integer | Character offset in original content |
| `end` | integer | Character offset end |
| `redacted_to` | string | Replacement token in `filtered_content` |

### processing_ms breakdown

| Key | Stage | Notes |
|-----|-------|-------|
| `cache_check` | Redis SHA-256 lookup | <1 ms typical |
| `obfuscation` | Base64/hex/ROT13/homoglyph decoder | ~0.3 ms |
| `redaction` | SecretRedactor (15 regex patterns) | ~1 ms |
| `rules` | SemanticGuard (rule engine + compound escalation) | ~2 ms |
| `ml` | MiniLM-L6-v2 cosine similarity | 15–25 ms CPU |
| `total` | End-to-end pipeline | sum of above |

> **Timeout note (v1.1):** when `PIPELINE_TIMEOUT_MS` fires, `processing_ms` reflects the partial time only. The `reason` field will contain `"emergency_bypass:timeout"`.

---

## 6. Enterprise Resilience (v1.1)

### Fail Strategy

Controlled by `WARDEN_FAIL_STRATEGY` environment variable (requires restart).

| Strategy | Env value | Timeout behaviour | Use case |
|----------|-----------|-------------------|----------|
| Fail-open | `open` (default) | Pass request through unchanged | High-throughput / business-critical APIs |
| Fail-closed | `closed` | Return HTTP 503 | Security-critical / Finance / Healthcare |

**Detection (client-side):**
```python
result = warden.filter(content)
if result["reason"] == "emergency_bypass:timeout":
    metrics.increment("warden.bypass.timeout")
    alert_oncall_if_rate_exceeds(threshold=0.05)  # >5% bypass rate
```

### Pipeline Timeout

Set `PIPELINE_TIMEOUT_MS` (integer, milliseconds). Recommended values:

| Environment | Recommended | Notes |
|-------------|-------------|-------|
| Production CPU | `300` | Covers P99 MiniLM latency with headroom |
| High-throughput | `200` | Allows 5 req/s per worker |
| Disabled | `0` | Default — no timeout |

### ML Uncertainty Escalation

Scores between `UNCERTAINTY_LOWER_THRESHOLD` (default `0.55`) and `SEMANTIC_THRESHOLD` (default `0.72`) produce an `ml_uncertain` flag at MEDIUM risk — request is **allowed but logged** for review.

```
Score = 0.0 ─────── 0.55 ────────── 0.72 ──── 1.0
                [uncertain zone]  [blocked]
                   MEDIUM risk
```

Tune the zone by adjusting either threshold via `POST /api/config` (no restart needed).

**Grafana alert for gray-zone traffic:**
```promql
sum(rate(http_requests_total{flag="ml_uncertain"}[5m])) > 10
```

### GDPR — Evolution Engine Anonymization

Before any blocked content is forwarded to Claude Opus for rule generation, `_anonymize_for_evolution()` strips:

| Pattern | Replacement |
|---------|-------------|
| UUID v1–v5 (with and without hyphens) | `[UUID]` |
| IPv4 addresses | `[IPv4]` |
| IPv6 addresses | `[IPv6]` |
| Email addresses | `[EMAIL]` |
| ISO 8601 timestamps | `[TIMESTAMP]` |
| Hex strings ≥ 16 chars (tokens, hashes) | `[HEX]` |

This satisfies **GDPR Art. 25** (data protection by design) and **Art. 44** (transfers to third countries — Claude Opus API).

> The original unredacted content is never stored or forwarded. Even `DEBUG=true` does not bypass anonymization — it is applied unconditionally in `evolve.py` before the Claude API call.

---

## 7. Error Codes

| HTTP | Warden Code | Meaning |
|------|-------------|---------|
| 200 | — | Success (check `allowed` field — blocked content also returns 200) |
| 400 | `invalid_request` | Malformed request body |
| 401 | `unauthorized` | Missing or invalid `X-API-Key` |
| 422 | `validation_error` | Pydantic schema validation failure |
| 429 | `rate_limited` | Per-IP or per-tenant rate limit exceeded |
| 500 | `internal_error` | Unexpected server error |
| 503 | `pipeline_timeout` | **v1.1** Pipeline exceeded `PIPELINE_TIMEOUT_MS` with `WARDEN_FAIL_STRATEGY=closed` |

All error responses follow:
```json
{ "detail": "Human-readable error message", "request_id": "uuid" }
```

**503 body (fail-closed timeout):**
```json
{
  "detail": "Filter pipeline timeout — request blocked (fail-closed strategy). Retry or contact support."
}
```

---

## 8. SDK Examples

### Python — Drop-in Guard

```python
import requests
from functools import wraps

WARDEN_URL = "https://warden.example.com"
WARDEN_KEY = "your-api-key"

def warden_filter(fn):
    """Decorator that filters any 'content' kwarg before calling fn."""
    @wraps(fn)
    def wrapper(*args, content: str, **kwargs):
        resp = requests.post(
            f"{WARDEN_URL}/filter",
            json={"content": content},
            headers={"X-API-Key": WARDEN_KEY},
        ).json()
        if not resp["allowed"]:
            raise ValueError(f"Warden blocked request: {resp['reason']}")
        return fn(*args, content=resp["filtered_content"], **kwargs)
    return wrapper

@warden_filter
def call_llm(content: str) -> str:
    # your LLM call here
    return f"LLM response to: {content}"
```

### Node.js / TypeScript

```typescript
import fetch from "node-fetch";

interface FilterResult {
  allowed: boolean;
  risk_level: string;
  filtered_content: string;
  reason: string;
}

async function filterContent(content: string, apiKey: string): Promise<FilterResult> {
  const resp = await fetch("https://warden.example.com/filter", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
    },
    body: JSON.stringify({ content }),
  });
  if (!resp.ok) throw new Error(`Warden error: ${resp.status}`);
  return resp.json() as Promise<FilterResult>;
}

// Usage
const result = await filterContent("User input here", process.env.WARDEN_API_KEY!);
if (!result.allowed) {
  throw new Error(`Blocked (${result.risk_level}): ${result.reason}`);
}
// result.filtered_content is safe to forward
```

### LangChain (Python) — Callback

```python
from warden.integrations.langchain_callback import WardenCallback

from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    callbacks=[WardenCallback(
        warden_url="https://warden.example.com",
        api_key="your-key",
        strict=False,
    )],
)

# All LLM inputs are automatically filtered — blocked content raises ValueError
response = llm.invoke("Summarise this document...")
```

---

## 9. Multi-Tenant Setup

Each tenant gets an isolated ML brain corpus that evolves independently.

**1. Create API keys JSON:**
```json
{
  "keys": [
    {
      "key_hash": "abc123...",
      "tenant_id": "acme-corp",
      "label": "ACME Production",
      "active": true,
      "rate_limit": 120
    },
    {
      "key_hash": "def456...",
      "tenant_id": "beta-llc",
      "label": "Beta LLC Staging",
      "active": true,
      "rate_limit": 30
    }
  ]
}
```

**2. Set environment:**
```bash
WARDEN_API_KEYS_PATH=/etc/warden/keys.json
```

**3. Use per-tenant key:**
```bash
curl -X POST https://warden.example.com/filter \
  -H "X-API-Key: acme-prod-key" \
  -H "Content-Type: application/json" \
  -d '{"content": "...", "tenant_id": "acme-corp"}'
```

The `tenant_id` from the API key takes precedence over the body field. Each tenant's ML guard evolves separately — rules learned from ACME's attacks don't contaminate Beta LLC's corpus.

**View active tenants:**
```bash
curl https://warden.example.com/health | jq '.tenants'
# ["default", "acme-corp", "beta-llc"]
```
