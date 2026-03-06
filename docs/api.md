# Shadow Warden AI — API Reference

**Version:** 0.4.0 · **Base URL:** `https://warden.example.com` · **Interactive docs:** `/docs` (Swagger UI), `/redoc`

Shadow Warden AI is a mandatory security gateway for AI payloads. Every request must pass through `/filter` before reaching any model or downstream service.

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Rate Limiting](#2-rate-limiting)
3. [REST Endpoints](#3-rest-endpoints)
   - [GET /health](#get-health)
   - [POST /filter](#post-filter)
   - [POST /filter/batch](#post-filterbatch)
   - [POST /gdpr/export](#post-gdprexport)
   - [POST /gdpr/purge](#post-gdprpurge)
   - [GET /metrics](#get-metrics)
   - [POST /v1/chat/completions](#post-v1chatcompletions)
4. [WebSocket /ws/stream](#4-websocket-wsstream)
5. [Response Schemas](#5-response-schemas)
6. [Error Codes](#6-error-codes)
7. [SDK Examples](#7-sdk-examples)
8. [Multi-Tenant Setup](#8-multi-tenant-setup)

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
  "strict": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | ✅ | The text payload to filter |
| `tenant_id` | string | — | Tenant identifier (default: `"default"`) |
| `strict` | boolean | — | Strict mode — treat MEDIUM risk as blocked (default: `false`) |

**Response 200:**
```json
{
  "allowed": true,
  "risk_level": "low",
  "filtered_content": "Your AI payload text here",
  "secrets_found": [],
  "semantic_flags": [],
  "reason": "",
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

**Blocked response:**
```json
{
  "allowed": false,
  "risk_level": "high",
  "filtered_content": "[ANTHROPIC_API_KEY_REDACTED] ignore previous instructions...",
  "secrets_found": [{"kind": "anthropic_api_key", "start": 0, "end": 30}],
  "semantic_flags": [
    {
      "flag": "prompt_injection",
      "score": 0.934,
      "detail": "ML jailbreak detected (similarity=0.934) — closest corpus entry: 'ignore all previous...'"
    }
  ],
  "reason": "ML jailbreak detected (similarity=0.934)...",
  "processing_ms": { "total": 24.7 }
}
```

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
| `filtered_content` | string | Content with secrets redacted (safe to forward) |
| `secrets_found` | array | List of `{kind, start, end}` objects |
| `semantic_flags` | array | List of `{flag, score, detail}` objects |
| `reason` | string | Human-readable block reason (empty if allowed) |
| `processing_ms` | object | Per-stage timing breakdown |

### SemanticFlag

| Field | Type | Description |
|-------|------|-------------|
| `flag` | string | Flag type: `prompt_injection`, `harmful_intent`, `system_override`, `data_exfiltration`, `social_engineering` |
| `score` | float | Confidence score 0–1 |
| `detail` | string | Detailed explanation |

### SecretFinding

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Secret type: `anthropic_api_key`, `openai_api_key`, `aws_access_key`, `stripe_key`, `generic_token`, etc. |
| `start` | integer | Start offset in original content |
| `end` | integer | End offset in original content |

---

## 6. Error Codes

| HTTP | Warden Code | Meaning |
|------|-------------|---------|
| 200 | — | Success |
| 400 | `invalid_request` | Malformed request body |
| 401 | `unauthorized` | Missing or invalid X-API-Key |
| 422 | `validation_error` | Pydantic schema validation failure |
| 429 | `rate_limited` | Per-IP or per-tenant rate limit exceeded |
| 500 | `internal_error` | Unexpected server error |

All error responses follow:
```json
{ "detail": "Human-readable error message", "request_id": "uuid" }
```

---

## 7. SDK Examples

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

## 8. Multi-Tenant Setup

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
