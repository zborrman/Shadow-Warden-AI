# Shadow Warden AI — API Reference

**Base URL:** `https://api.shadow-warden-ai.com`
**Auth:** `X-API-Key: <your-key>` header on every request
**OpenAPI UI:** `https://api.shadow-warden-ai.com/docs`
**OpenAPI JSON:** `https://api.shadow-warden-ai.com/openapi.json` (also at repo root `openapi.json`)

---

## Authentication

```http
X-API-Key: sw_live_xxxxxxxxxxxxxxxx
```

- Keys are per-tenant. Generate in **Portal → Settings → API Keys**.
- Multi-key support: pass multiple keys via `WARDEN_API_KEYS_PATH` JSON file.
- Constant-time comparison — safe against timing attacks.
- Missing key with `ALLOW_UNAUTHENTICATED=false` (default): `401 Unauthorized`.

---

## Error format

```json
{
  "detail": "Human-readable message",
  "status": 422
}
```

| Code | Meaning |
|---|---|
| 400 | Bad request |
| 401 | Missing or invalid API key |
| 402 | Feature requires an add-on purchase |
| 403 | Feature requires a higher tier |
| 404 | Resource not found |
| 422 | Validation error |
| 429 | Rate limit exceeded |
| 500 | Internal error (fail-open — does not block filter) |

---

## Core

### `POST /filter`

Run the 9-layer AI security filter on a text or file.

**Request:**
```json
{
  "content": "string",
  "tenant_id": "default",
  "file_base64": "base64-encoded-bytes (optional)",
  "file_filename": "upload.bin"
}
```

**Response:**
```json
{
  "allowed": true,
  "blocked": false,
  "risk_level": "low",
  "risk_score": 0.12,
  "flags": [],
  "processing_ms": 1.4,
  "request_id": "req_01JXYZ..."
}
```

`risk_level`: `low | medium | high | block`

### `POST /filter/batch`

Filter up to 50 requests in one call. Request body: `{"requests": [FilterRequest, ...]}`.

### `GET /health`

No auth required. Returns `{"status":"ok","version":"5.6.0","uptime_seconds":12345}`.

### `GET /metrics`

Prometheus text format metrics. Protected by `X-API-Key`.

---

## Communities (`/communities`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/communities` | List all communities for `?tenant_id=` |
| `POST` | `/communities/create` | Create community |
| `GET` | `/communities/{id}` | Get community details |
| `GET` | `/communities/{id}/members` | List members |
| `POST` | `/communities/{id}/invite` | Invite member (returns knock token) |
| `POST` | `/communities/{id}/rotate` | Rotate keypair |
| `POST` | `/communities/{id}/upgrade-pqc` | Upgrade to ML-DSA-65 (Enterprise) |
| `GET` | `/public/community` | GDPR-safe aggregate stats (no auth) |
| `GET` | `/public/leaderboard` | Anonymised top-10 reputation (no auth) |

### SEP — Syndicate Exchange Protocol (`/sep`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/sep/ueciid/{id}` | Resolve UECIID |
| `GET` | `/sep/ueciid/search` | Prefix + display name search |
| `POST` | `/sep/ueciid` | Register new UECIID |
| `GET/POST/DELETE` | `/sep/pod-tags/{entity_id}` | Sovereign pod tag CRUD |
| `GET/POST` | `/sep/peerings` | List / create peering |
| `POST` | `/sep/peerings/{id}/accept` | Accept peering request |
| `POST` | `/sep/peerings/{id}/transfer` | Transfer entity to peer community |
| `POST` | `/sep/transfers/{id}/verify-proof` | Verify Causal Transfer Proof |
| `POST` | `/sep/knock/issue` | Issue Knock-and-Verify token |
| `POST` | `/sep/knock/accept` | Accept knock (join community) |
| `GET` | `/sep/pods` | List Sovereign Data Pods |
| `POST` | `/sep/pods` | Register pod |
| `POST` | `/sep/pods/{id}/probe` | Health-check pod |
| `GET` | `/sep/audit-chain/{community_id}` | STIX 2.1 audit chain entries |
| `GET` | `/sep/audit-chain/{community_id}/verify` | Verify chain integrity |
| `GET` | `/sep/audit-chain/{community_id}/export` | Export OASIS JSONL |

---

## Marketplace (`/marketplace`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/marketplace/agents/register` | Register AI agent (issues DID) |
| `GET` | `/marketplace/agents/{id}` | Get agent |
| `GET` | `/marketplace/agents/{id}/trust` | Trust rank + Sybil risk |
| `PUT` | `/marketplace/agents/{id}/capabilities` | Update capabilities |
| `POST` | `/marketplace/listings` | Create listing |
| `GET` | `/marketplace/listings` | List listings (`?community_id&asset_type&status`) |
| `GET` | `/marketplace/listings/{id}` | Get listing |
| `POST` | `/marketplace/listings/{id}/purchase` | Purchase → creates escrow |
| `GET` | `/marketplace/escrow/{id}` | Get escrow |
| `POST` | `/marketplace/escrow/{id}/fund` | Buyer funds escrow |
| `POST` | `/marketplace/escrow/{id}/confirm` | Buyer confirms receipt |
| `POST` | `/marketplace/escrow/{id}/dispute` | Raise dispute |
| `GET/POST` | `/marketplace/governance/proposals` | List / create DAO proposals |
| `POST` | `/marketplace/governance/proposals/{id}/vote` | Cast vote |
| `GET` | `/marketplace/stats` | Aggregate statistics |
| `GET` | `/marketplace/analytics/summary` | Time-windowed analytics |
| `GET` | `/marketplace/analytics/volume` | Daily volume series |
| `GET` | `/marketplace/analytics/agents` | Agent leaderboard |

---

## Compliance (`/compliance`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/compliance/posture` | Real-time posture score (GDPR/SOC2/ISO27001/HIPAA) |
| `GET` | `/compliance/posture/gaps` | Gap list with remediation |
| `GET` | `/compliance/posture/{framework}` | Per-framework score + controls |
| `POST` | `/compliance/posture/recalculate` | Force recompute, flush cache |
| `GET` | `/compliance/history` | 168-hour score ring buffer |
| `GET` | `/compliance/iso27001` | Full 93-control ISO 27001:2022 matrix |
| `GET` | `/compliance/soc2/evidence` | SOC 2 Type II control guide |
| `WS` | `/compliance/ws` | WebSocket — 30s push of posture updates |
| `GET` | `/compliance/posture/export/pdf` | Export compliance report as PDF (reportlab; falls back to HTML) |

Requires: `X-Tenant-Tier: pro` or Enterprise.

**WebSocket message format:**
```json
{
  "overall_score": 84,
  "grade": "B",
  "frameworks": { "gdpr": 91, "soc2": 80, "iso27001": 78, "hipaa": 87 },
  "gaps_open": 3,
  "computed_at": "2026-06-13T10:00:00Z"
}
```

---

## Semantic Layer (`/semantic-layer`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/semantic-layer/models` | List all models (built-in + tenant) |
| `GET` | `/semantic-layer/models/{id}` | Get model definition |
| `POST` | `/semantic-layer/query` | Run structured query → SQL + rows |
| `POST` | `/semantic-layer/ai-query` | Natural-language query (Pro+) |
| `POST` | `/semantic-layer/models/catalog` | Register custom tenant model |

Built-in model IDs: `filter_events`, `ers_scores`, `billing_usage`, `incidents`,
`vendor_contracts`, `agentic_orders`, `tunnel_sessions`, `compliance_attestations`, `ai_spend`.

---

## Document Intelligence (`/document-intel`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/document-intel/convert` | File (base64) → Markdown |
| `POST` | `/document-intel/scan` | Scan Markdown through security pipeline |
| `GET` | `/document-intel/stats` | Conversion statistics + cache hit rate |
| `GET` | `/document-intel/cache/entries` | List cached document hashes (admin) |
| `DELETE` | `/document-intel/cache/clear` | Flush SHA-256 Redis cache for a tenant |

Supported formats: PDF, DOCX, XLSX, PPTX, HTML, MP3, MP4, PNG, JPG, and more.
Max 50 MB (`DOC_INTEL_MAX_BYTES`). Timeout 30s (`DOC_INTEL_TIMEOUT_S`).

---

## Agentic Commerce (`/business-community/commerce`)

AP2 mandates, UCP procurement protocol, and multi-agent auctions.
Tier: **Community Business+**.

| Method | Path | Description |
|---|---|---|
| `POST` | `/business-community/commerce/mandates` | Create AP2 spending mandate |
| `GET` | `/business-community/commerce/mandates/{id}` | Get mandate details |
| `POST` | `/business-community/commerce/orders` | Submit UCP purchase order |
| `GET` | `/business-community/commerce/orders` | List orders (`?tenant_id&status`) |
| `POST` | `/business-community/commerce/auctions` | Create multi-agent auction |
| `GET` | `/business-community/commerce/auctions/{id}` | Get auction state + bids |
| `POST` | `/business-community/commerce/auctions/{id}/bid` | Submit agent bid |
| `GET` | `/business-community/commerce/budget/check` | Check Commerce Budget Guardian |

**Example — create mandate:**
```bash
curl -s -X POST https://api.shadow-warden-ai.com/business-community/commerce/mandates \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","max_amount_usd":500,"allowed_merchants":["marketplace"]}'
```

---

## Sovereign AI Cloud (`/sovereign`)

MASQUE tunnels, jurisdiction routing, and sovereignty attestation.
Tier: **Enterprise**.

| Method | Path | Description |
|---|---|---|
| `GET` | `/sovereign/jurisdictions` | List 8 jurisdictions + compliance frameworks |
| `GET` | `/sovereign/jurisdictions/{code}` | Jurisdiction detail + transfer rules |
| `POST` | `/sovereign/compliance/check` | Cross-border transfer compliance check |
| `GET/POST` | `/sovereign/policy` | Read / update per-tenant routing policy |
| `GET` | `/sovereign/tunnels` | List MASQUE tunnels |
| `POST` | `/sovereign/tunnels` | Register tunnel (runs preflight checks) |
| `DELETE` | `/sovereign/tunnels/{id}` | Remove tunnel |
| `POST` | `/sovereign/tunnels/{id}/probe` | Health-check tunnel |
| `POST` | `/sovereign/route` | Get routing decision for a request |
| `POST` | `/sovereign/attest` | Issue sovereignty attestation (HMAC-SHA256) |
| `GET` | `/sovereign/attest/{id}` | Retrieve attestation |
| `POST` | `/sovereign/attest/{id}/verify` | Verify attestation signature |
| `GET` | `/sovereign/report` | Sovereignty summary report |

**Preflight checks on `POST /sovereign/tunnels`:**

Before registering a tunnel, the endpoint verifies that MinIO, Redis, and the Warden API
are reachable in the target jurisdiction. Returns **503** if any check fails.

Pass `"skip_preflight": true` in the request body to bypass (emergency use only).

```json
{
  "label": "eu-primary",
  "jurisdiction": "EU",
  "protocol": "MASQUE_H3",
  "skip_preflight": false
}
```

503 response body:
```json
{
  "detail": {
    "message": "Preflight check failed — tunnel not registered",
    "failed_services": ["minio"],
    "checks": [
      {"service": "minio", "status": "fail", "latency_ms": 5001.0, "error": "Connection refused"}
    ]
  }
}
```

---

## Settings (`/settings`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/settings/summary` | Current config snapshot |
| `GET/POST/DELETE` | `/settings/api-keys` | Manage API keys |
| `GET/POST/DELETE` | `/settings/secrets` | Manage secrets references |
| `GET/PATCH` | `/settings/agents` | SOVA / MasterAgent config |
| `GET/POST/DELETE` | `/settings/notifications` | Slack / PagerDuty channels |
| `GET/PATCH` | `/settings/commerce` | Agentic Commerce config |
| `GET/PATCH` | `/settings/semantic` | Semantic Layer config |

---

## Agentic SOC (`/agent`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/agent/sova` | Run SOVA query (Pro+) |
| `DELETE` | `/agent/sova/{session_id}` | Clear conversation history |
| `POST` | `/agent/sova/task/{job}` | Trigger ARQ scheduled job manually |
| `POST` | `/agent/master` | Run MasterAgent decompose + sub-agent loop (Pro+) |
| `POST` | `/agent/approve/{token}` | Approve or reject HITL pending action |
| `GET` | `/agent/approve/{token}` | Check approval status |

---

## Financial (`/financial`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/financial/impact` | Dollar impact report (IBM 2024 benchmarks) |
| `GET` | `/financial/cost-saved` | Costs saved by blocking |
| `GET` | `/financial/roi` | ROI analysis |
| `POST` | `/financial/generate-proposal` | Generate ROI proposal PDF |
| `GET/POST` | `/financial/allocation` | Cost allocation per department/vendor |
| `GET/POST` | `/financial/budget/status` | Budget caps + spend vs cap |

---

## Event Streaming (`/streams`)

> **Tier gate:** Pro+ or `event_streaming_pack` add-on.

| Method | Path | Description |
|---|---|---|
| `GET` | `/streams/health` | Kafka/Redis pub-sub connection health |
| `POST` | `/streams/events` | Publish a raw marketplace event to the bus |
| `GET` | `/streams/flink/jobs` | List active FlinkAgentRunner stateful jobs |

---

## Agent Tokenomics (`/tokenomics`)

> **Tier gate:** Enterprise or `agent_tokenomics_pack` add-on.

| Method | Path | Description |
|---|---|---|
| `POST` | `/tokenomics/mint` | Mint WAT tokens to an agent wallet |
| `POST` | `/tokenomics/transfer` | Transfer WAT between agent wallets |
| `GET` | `/tokenomics/balance/{agent_id}` | Current WAT balance for an agent |
| `GET` | `/tokenomics/ledger/{agent_id}` | Full transaction history |
| `POST` | `/tokenomics/outcome-price` | Calculate outcome-based price for a task |

---

## USDC Payments (`/payments/usdc`)

> **Tier gate:** Enterprise or `usdc_payments_pack` add-on.

| Method | Path | Description |
|---|---|---|
| `POST` | `/payments/usdc/intents` | Create a USDC payment intent |
| `GET` | `/payments/usdc/intents/{intent_id}` | Poll intent status (`PENDING` / `CONFIRMED` / `FAILED`) |

---

## ANS Certificates (`/marketplace`)

> **Tier gate:** Enterprise or `ans_certificate_pack` add-on.

| Method | Path | Description |
|---|---|---|
| `POST` | `/marketplace/agents/{agent_id}/certificate` | Issue an X.509 ANS certificate for an agent |
| `DELETE` | `/marketplace/agents/{agent_id}/certificate` | Revoke agent certificate (adds to CRL) |
| `GET` | `/marketplace/agents/{agent_id}/certificate` | Download current certificate PEM |
| `POST` | `/marketplace/certificates/verify` | Verify a PEM certificate (chain + CRL check) |

Subject CN format: `agent-{agent_id}.{community_id}.shadow-warden.ai`

---

## Edge Agent Packs (`/agents`)

> **Tier gate:** Pro+ or `edge_agent_packs` add-on.

| Method | Path | Description |
|---|---|---|
| `GET` | `/agents/packs` | List all registered edge agent packs |
| `POST` | `/agents/packs/{name}/deploy` | Deploy a pack to a target endpoint |
| `POST` | `/agents/packs/{name}/analyze` | Run analysis with sensor data |

Built-in packs: `crop_health_monitor`, `yield_optimizer`, `disease_detector`.

---

## Pagination

Endpoints returning lists accept `?limit=` (default 50, max 200) and `?offset=` query params.
Responses include a `"count"` field with the total number of matching items.

---

## Rate limits

| Tier | Requests / month | Burst (req/s) |
|---|---|---|
| Starter | 1,000 | 5 |
| Individual | 5,000 | 10 |
| Community Business | 10,000 | 20 |
| Pro | 50,000 | 50 |
| Enterprise | Unlimited | 200 |

Rate limit headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
