# Shadow Warden AI — Architecture Overview

**Version:** 5.6 | **Audience:** Engineers, architects, technical evaluators

---

## 1. High-level diagram

<!-- SCREENSHOT: Full architecture diagram rendered from draw.io or Mermaid -->
<!-- TODO: capture and save as docs/images/architecture-overview.png -->
<!-- Figure 1: High-level architecture showing Caddy → warden → 11 services -->

```
Internet
    │
    ▼
┌─────────────┐
│  Caddy v2   │  :80/:443  HTTPS + QUIC/HTTP3, HSTS, vhost routing
└──────┬──────┘
       │  routes by hostname
       ├─── api.shadow-warden-ai.com   ──► warden (8001)
       ├─── app.shadow-warden-ai.com   ──► portal (Next.js 14, 3001)
       ├─── dash.shadow-warden-ai.com  ──► dashboard (Next.js 14, 3002)
       └─── analytics.shadow-warden-ai.com ─► Streamlit (8501)

┌───────────────────────────────────────────────────────────────┐
│  warden (FastAPI, Python 3.12)  — port 8001                   │
│                                                               │
│  POST /filter ──► 9-layer Security Pipeline (< 2 ms)         │
│  /communities  /marketplace  /compliance  /semantic-layer     │
│  /document-intel  /sovereign  /sep  /xai  /agent  /settings  │
└──────────┬───────────────────────────────────────────────────┘
           │
    ┌──────┴──────────────────────────┐
    │                                 │
    ▼                                 ▼
┌────────┐  ┌────────┐  ┌────────┐  ┌─────────┐  ┌──────────┐
│Postgres│  │ Redis  │  │ MinIO  │  │Prometheus│  │  Grafana │
│(meta,  │  │(cache, │  │(S3-compat│  │(metrics)│  │ (3000)  │
│ audit) │  │ ERS,   │  │ evidence)│  └────────┘  └──────────┘
└────────┘  │ memory)│  └────────┘
            └────────┘

┌──────────────────────────────────────────────────────────────┐
│  Background workers (ARQ)                                    │
│  sova_morning_brief · sova_threat_sync (6h) · sova_rotation  │
│  sova_visual_patrol (03:00 UTC) · sova_corpus_watchdog (30m) │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Security Pipeline (9 layers)

Every `POST /filter` request passes through these stages in order, target < 2 ms:

| # | Stage | Module | What it does |
|---|---|---|---|
| 1 | **TopologicalGatekeeper** | `warden/topology_guard.py` | n-gram point cloud → β₀/β₁ Betti numbers; fast noise/DoS filter |
| 2 | **ObfuscationDecoder** | `warden/obfuscation.py` | base64, hex, ROT13, Caesar, word-split, UUencode, homoglyphs; depth-3 recursive |
| 3 | **SecretRedactor** | `warden/secret_redactor.py` | 15 regex patterns + Shannon entropy scan for unknown secrets |
| 4 | **SemanticGuard** (rules) | `warden/semantic_guard.py` | Rule-based keyword/regex engine; 3×MEDIUM escalates to HIGH |
| 5 | **HyperbolicBrain** | `warden/brain/semantic.py` | MiniLM → Poincaré ball; 70% cosine + 30% hyperbolic distance |
| 6 | **CausalArbiter** | `warden/causal_arbiter.py` | Bayesian DAG, Pearl do-calculus, 5 nodes, backdoor correction |
| 7 | **PhishGuard** | `warden/phishing_guard.py` | URL phishing + social engineering detection (SE-Arbiter) |
| 8 | **ERS** | `warden/metrics.py` + Redis | Sliding-window reputation score; shadow ban at ≥ 0.75 |
| 9 | **Decision** | `warden/main.py` | Final verdict: ALLOW / FLAG / BLOCK; triggers EvolutionEngine on BLOCK |

**EvolutionEngine** (background): Claude Opus analyses BLOCK events, generates new rules via `add_examples()`, hot-reloads corpus — no restart required.

---

## 3. Key product modules

### 3.1 Business Community & Marketplace

```
Community Hub  ──► SEP (UECIID provenance)
                   Peering (MIRROR/REWRAP/FULL_SYNC)
                   Causal Transfer Guard (P≥0.70 exfil block)
                   STIX 2.1 Audit Chain

Marketplace ──► Agent Registry (DID: did:shadow:{32 base62})
                Asset Tokenizer (rule | model | signals)
                Listings → Escrow → Confirm | Dispute
                Trust Graph + Sybil Guard
                DAO Governance Proposals
```

### 3.2 Agentic SOC

```
SOVA ──► Claude Opus 4.6 agentic loop (≤10 iterations)
         30 tools: health/stats/config/CVE/rotation/ArXiv/visual-patrol/…
         Redis memory (sova:conv:{sid}, 6h TTL, 20 turns)
         ARQ cron: morning brief, threat sync, SLA report, visual patrol

MasterAgent ──► 4 sub-agents (SOVAOperator / ThreatHunter / ForensicsAgent / ComplianceAgent)
                HMAC-SHA256 task tokens (cross-agent injection prevention)
                Human-in-the-Loop: REQUIRES_APPROVAL → Slack → /agent/approve/{token}

WardenHealer ──► CB, bypass spike, corpus DEGRADED, canary probe
                 OLS trend prediction (WARN if predicted bypass > 15%)
                 Claude Haiku incident classification + SQLite recipe cache
```

### 3.3 Semantic Layer (Headless BI)

Deterministic SQL generator over 9 built-in models:
`filter_events | ers_scores | billing_usage | incidents | vendor_contracts | agentic_orders | tunnel_sessions | compliance_attestations | ai_spend`

```
POST /semantic-layer/query   ──► QueryObject → SQL → rows
POST /semantic-layer/ai-query ──► natural language → QueryObject → SQL → rows
POST /semantic-layer/models/catalog ──► register custom tenant model
```

Redis cache: `sl:query:{sha256[:24]}`, TTL 600s, fail-open.

### 3.4 Document Intelligence

MarkItDown converts PDF, DOCX, audio, images → Markdown → 9-layer filter hook.
50 MB gate; SHA-256 Redis cache (PDF 24h, audio 7d, images 1h).

### 3.5 Sovereign AI Cloud (Enterprise)

8 jurisdictions (EU/US/UK/CA/SG/AU/JP/CH) with MASQUE tunnels, TOFU TLS pinning,
per-tenant routing policy, HMAC-SHA256 sovereignty attestation (7-year Redis TTL),
transfer rules matrix (CLASSIFIED: never; PHI: US/EU/UK/CA/CH only).

### 3.6 Compliance Posture (CP-30)

19 controls across GDPR(6)/SOC2(5)/ISO27001(4)/HIPAA(4).
Redis cache `compliance:posture:{tenant_id}` (TTL 300s), Redis Pub/Sub on recompute.
WebSocket `/compliance/ws` pushes updates every 30s.

---

## 4. Data flow for a typical request

```
1. Client → POST /filter  {"content": "...", "tenant_id": "acme"}
2. Caddy terminates TLS, proxies to warden:8001
3. auth_guard  — constant-time API key compare (per-tenant multi-key)
4. Redis SHA-256 cache check  (5-min TTL, fail-open)
5. 9-layer pipeline  (< 2 ms, CPU-only torch, MiniLM ONNX)
6. Decision:
   ALLOW → 200 {"allowed":true, "risk_level":"low", "processing_ms":1.4}
   BLOCK → 200 {"allowed":false, "blocked":true, "flags":["jailbreak"]}
         → background: EvolutionEngine.add_examples()
         → ERS score update → possible shadow ban
         → Slack/PagerDuty alert (if risk ≥ HIGH)
         → MinIO evidence bundle write (fail-open)
7. NDJSON metadata log (content NEVER logged — GDPR hard rule)
8. Prometheus counter incremented
9. OTel span emitted (GDPR-safe attributes only)
```

---

## 5. Technology stack

| Layer | Technology |
|---|---|
| Runtime | Python 3.12, FastAPI 0.111, Uvicorn |
| ML | sentence-transformers/all-MiniLM-L6-v2 (ONNX, CPU-only), numpy |
| Frontend | Next.js 14.2 (App Router, TanStack Query, Recharts, Tailwind) |
| Analytics UI | Streamlit 1.35 |
| Marketing site | Astro 4 (static, TypeScript) |
| Database | PostgreSQL 16 + TimescaleDB |
| Cache / messaging | Redis 7 |
| Object store | MinIO (S3-compatible) |
| Reverse proxy | Caddy v2.8+ (QUIC/HTTP3) |
| Observability | Prometheus, Grafana 10, OpenTelemetry, Jaeger |
| Web3 | Solidity mandate contract (Sepolia/Polygon/Arbitrum), Web3.py |
| Auth | Ed25519 + ML-DSA-65 (liboqs), FIDO2/WebAuthn |
| Containerisation | Docker 24+, Docker Compose v2 |
| CI/CD | GitHub Actions (test matrix 3.11/3.12, ruff, mypy, mutmut, cosign) |

---

## 6. Design principles

| Principle | Implementation |
|---|---|
| **Defense in depth** | 9 independent pipeline layers; each can block independently |
| **Zero trust** | Per-tenant API keys, HMAC task tokens, agent DIDs, FIDO2 |
| **Fail-open on infrastructure** | Redis/S3/MISP failures never block the filter response |
| **Fail-closed on auth** | Missing API key vars → `RuntimeError` at startup |
| **GDPR by default** | Content NEVER logged; only type/length/timing metadata |
| **Deterministic AI** | Semantic Layer generates parameterised SQL, no LLM in query path |
| **Air-gap capable** | No `ANTHROPIC_API_KEY` = evolution disabled; all detection still works |
| **PQC-ready** | Hybrid Ed25519+ML-DSA-65 signer; X25519+ML-KEM-768 KEM; liboqs fail-open |
