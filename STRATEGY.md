# Shadow Warden AI — Strategic Architecture
# v4.7 · April 2026

---

## Executive Summary

Shadow Warden AI is a **self-contained, GDPR-compliant AI security gateway**
that sits in front of every AI request in an organisation. It blocks jailbreak
attempts, strips secrets and PII, shadow-bans attackers, enforces agentic
safety guardrails, self-improves via Claude Opus — all without sending
sensitive data to third parties.

**Revenue model:** Lemon Squeezy SaaS subscriptions (Merchant of Record,
EU/UK VAT handled automatically).

**Current status (v4.7):** 9-stage detection pipeline, 30-tool SOVA agent,
4-sub-agent MasterAgent, PQC hybrid signatures (ML-DSA-65 + ML-KEM-768),
Sovereign AI Cloud (8 jurisdictions, MASQUE tunnels), Shadow AI Discovery
(18 providers, /24 subnet probe + DNS syslog), Explainable AI (9-stage DAG,
HTML/PDF reports), Syndicate Exchange Protocol (UECIID, inter-community
peering, Causal Transfer Guard, STIX 2.1 audit chain, Sovereign Data Pods).

---

## Pricing — v4.7

| Tier | Price | Requests/mo | Target buyer |
|------|-------|-------------|--------------|
| **Starter** | Free | 1,000 | Developers evaluating |
| **Individual** | $5/mo | 5,000 | Solo developers, hobbyists |
| **Pro** | $69/mo | 50,000 | Mid-market SaaS, SMB dev teams |
| **Enterprise** | $249/mo | Unlimited | Banks, fintech, government, healthcare |

**Add-ons (Lemon Squeezy one-time or recurring):**

| Add-on | Price | Min Tier | Unlocks |
|--------|-------|----------|---------|
| XAI Audit Reports | +$9/mo | Individual | `/xai/*` HTML + PDF reports |
| Shadow AI Discovery | +$15/mo | Pro | `/shadow-ai/scan`, syslog sink |
| MasterAgent | Included in Pro | Pro | `/agent/master` 4-sub-agent SOC |

**Enterprise-only (not available as add-ons):**
- Post-Quantum Cryptography (ML-DSA-65 + ML-KEM-768)
- Sovereign AI Cloud (8-jurisdiction MASQUE tunnels + attestations)

**HTTP status code convention for billing gates:**
- `HTTP 403` — tenant tier below `min_tier` (upgrade CTA)
- `HTTP 402` — eligible tier but add-on not purchased (checkout CTA)

---

## Architecture — 6 Pillars

### Pillar 1 — Core Detection Pipeline (9 stages)

```
POST /filter
  Stage 1 · TopologicalGatekeeper      n-gram → β₀/β₁ Betti numbers, < 2ms
  Stage 2 · ObfuscationDecoder         base64/hex/ROT13/homoglyphs, depth-3
  Stage 3 · SecretRedactor             15 regex + Shannon entropy
  Stage 4 · SemanticGuard              10 rules, compound escalation
  Stage 5 · HyperbolicBrain            MiniLM → Poincaré ball, 70/30 blend
  Stage 6 · CausalArbiter              Bayesian DAG, Pearl do-calculus
  Stage 7 · PhishGuard + SE-Arbiter    URL phishing + social engineering
  Stage 8 · ERS + Shadow Ban           Redis sliding window, gaslight/delay
  Stage 9 · Decision
              ↓
    EvolutionEngine (background)  ← HIGH/BLOCK triggers
```

**XAI chain:** every request's 9-stage verdict is stored for
`GET /xai/explain/{request_id}` — counterfactual remediations per non-PASS stage.

### Pillar 2 — Agentic SOC

**SOVA** (`warden/agent/sova.py`): Claude Opus 4.6 agentic loop, 30 tools,
7 ARQ cron jobs. Redis memory (6h TTL). WardenHealer: LLM-free 4-check
autonomous anomaly detection — delegates from `sova_corpus_watchdog`.

**MasterAgent** (`warden/agent/master.py`): supervisor loop, 4 sub-agents
(SOVAOperator / ThreatHunter / ForensicsAgent / ComplianceAgent). HMAC-SHA256
task tokens. Human-in-the-loop: `REQUIRES_APPROVAL` → Slack → Redis 1h TTL →
`/agent/approve/{token}`. Anthropic Batches API for 50% token discount on
decompose + synthesis. `_SUB_AGENT_MAX_ITER=5` + `_SUB_AGENT_TOKEN_BUDGET=8192`.

### Pillar 3 — Post-Quantum Authentication

**HybridSigner** (FIPS 204): Ed25519 (64B) + ML-DSA-65 (3309B) hybrid sig.
**HybridKEM** (FIPS 203): X25519 + ML-KEM-768. Shared secret = HKDF(X25519_ss XOR mlkem_ss[:32]).

Community keypair kid convention: `"v1-hybrid"` suffix.
`upgrade_to_hybrid(kp)` upgrades existing classical keypairs.
liboqs fail-open: `PQCUnavailableError` if liboqs not installed; classical still works.

CTP PQC signing: `sign_transfer_proof(community_keypair=kp)` → `pqc_signature` field.
Both HMAC-SHA256 and ML-DSA-65 must pass `verify_transfer_proof()`.

Enterprise-only gate: `pqc_enabled`.

### Pillar 4 — Shadow AI Governance

**ShadowAIDetector**: async /24 subnet probe (18 AI provider fingerprints,
max 50 concurrent, 3s timeout). Optional scapy ARP pre-probe (60–80% faster,
`SHADOW_AI_USE_SCAPY=true`). Redis findings store (1,000-entry cap per tenant).

**DNS syslog sink** (`syslog_sink.py`): async UDP listener, parses
dnsmasq/BIND9/Zeek lines, feeds `classify_dns_event()` in real time.
Started in FastAPI lifespan when `SHADOW_AI_SYSLOG_ENABLED=true`.

**Policy modes:** MONITOR / BLOCK_DENYLIST / ALLOWLIST_ONLY (Redis-backed).

SOVA tool #29 (`scan_shadow_ai`) calls `ShadowAIDetector.scan()` directly.

### Pillar 5 — Sovereign AI Cloud

**8 jurisdictions:** EU, US, UK, CA, SG, AU, JP, CH — compliance frameworks
+ AI regulations + data classification transfer rules matrix.

**MASQUE tunnels** (`warden/sovereign/tunnel.py`): MASQUE_H3/H2/CONNECT_TCP.
TOFU TLS pinning. Lifecycle: PENDING → ACTIVE → DEGRADED → OFFLINE.

**Routing algorithm:** load policy → allowed jurisdictions per data_class →
ACTIVE tunnels in those jurisdictions → prefer `preferred_tunnel_id` →
else min(home_jurisdiction_first, lowest_latency).

**Sovereignty attestation:** HMAC-SHA256, Redis 7yr TTL, 10,000 cap per tenant.

**Transfer rules (key):** CLASSIFIED → never cross-border; PHI → EU/US/UK/CA/CH only.

Enterprise-only gate: `sovereign_enabled`.

### Pillar 6 — Syndicate Exchange Protocol (SEP)

End-to-end framework for inter-community encrypted document exchange.

**UECIID** — `SEP-{11 base-62}` from 64-bit Snowflake. Lexicographic =
chronological. SQLite index `sep_ueciid_index` in `SEP_DB_PATH`.

**Inter-community peering** — HMAC handshake token; MIRROR_ONLY /
REWRAP_ALLOWED / FULL_SYNC. `transfer_entity()` pipeline:

```
1. Resolve entity data_class from pod tag
2. Causal Transfer Guard (evaluate_transfer_risk)
   - Bayesian DAG maps SEP context → arbitrate() evidence
   - Block threshold TRANSFER_RISK_THRESHOLD (default 0.70)
   - REJECTED status written to DB + STIX chain (never silently dropped)
3. Sign CTP (HMAC-SHA256 + optional ML-DSA-65 pqc_signature)
4. Append to STIX 2.1 audit chain (always — including REJECTED)
```

**Sovereign Data Pods** — per-jurisdiction MinIO routing. Fernet-encrypted
secret keys (SHA-256 of `COMMUNITY_VAULT_KEY`). Resolution:
jurisdiction → data_class → primary → first ACTIVE pod.

**STIX 2.1 Audit Chain** — SHA-256 prev_hash chain. 4 STIX objects per bundle.
Genesis: `"0"×64`. `verify_chain()` re-hashes all bundles. `export_chain_jsonl()`
→ SIEM-importable JSONL. Satisfies SOC 2 CC6.3 + GDPR Art. 30.

**Knock-and-Verify** — one-time Redis invitation tokens (72h TTL).

---

## Infrastructure

**11 Docker services:** `proxy` (Caddy, 80/443/UDP443), `warden` (8001),
`app` (8000), `analytics` (8002), `dashboard` (8501), `postgres`,
`redis`, `prometheus`, `grafana` (3000), `minio` (9000/9001), `minio-init`.

**Caddy v2.8+** replaces nginx. HTTP/3 (QUIC) on UDP 443 native. Auto
`Alt-Svc: h3=":443"` header. Hostname-based routing:
`api.` → warden:8001, `app.` → portal:3001, `analytics.` → analytics:8002,
root → `/srv/landing`. HSTS 2yr + security headers in reusable snippet.

**Named Docker volumes:** `warden-models` (ONNX model, persists across git ops),
`caddy-data` (ACME state + certs), `warden-logs`.

**MinIO** (on-prem S3): Evidence Vault (`warden-evidence/`) + logs
(`warden-logs/`) + screencasts (`screencasts/`). Fail-open on all MinIO paths.

---

## Compliance Posture

| Standard | Controls |
|----------|----------|
| GDPR Art. 5 | Content never logged — only metadata |
| GDPR Art. 30 | STIX 2.1 audit chain (records of processing activities) |
| GDPR Art. 35 | DPIA documented in `docs/dpia.md` |
| SOC 2 CC6.3 | Causal Transfer Proof + STIX chain for data-sharing authorisation |
| SOC 2 CC6.7 | mlock/VirtualLock for Fernet + HMAC keys |
| SOC 2 CC7.2 | WardenHealer + Grafana SLO alerts + Evidence Vault |
| ISO 27001 A.8.3 | STIX 2.1 information transfer records |
| EU AI Act | TDA Gatekeeper + CausalArbiter provide mathematically-auditable decisions |
| FIPS 203/204 | ML-KEM-768 + ML-DSA-65 via liboqs (Enterprise) |

---

## Roadmap 2026–2028

### Q2 2026 — v4.8 (next)

- **Kubernetes Helm charts** — production-grade Enterprise deployment; HPA on
  `warden` pods; GPU node pool for ONNX acceleration
- **NVIDIA NIM integration** — local LLM inference option for air-gapped
  Enterprise deployments (Nemotron 49B for Evolution Engine)
- **SOC 2 Type II readiness** — automated evidence collection pipeline
  (ScreencastRecorder + STIX export → auditor portal)
- **STIX 2.1 Nexus Feed** — federated worm fingerprint sharing across Warden
  fleet with Bayesian consensus gate (Trust_Score ≥ 0.80 threshold)

### Q3 2026 — v4.9

- **Browser Extension v2** — MV3 Chrome/Firefox/Edge; `world: "MAIN"` intercept;
  GPO/MDM rollout for Enterprise; OIDC auth (Google + Azure AD)
- **TimescaleDB continuous aggregates** for SEP transfer analytics
- **Multi-region active-active** — Caddy global load balancing + data
  residency routing via Sovereign tunnel selection

### Q4 2026 — v5.0

- **Agentic Mandate Validator 2.0** — AP2-style payment instruction validator
  with ML-DSA-65 signed mandate tokens
- **Warden Nexus** — global fleet intelligence network with STIX 2.1 Indicator
  bundles + Bayesian consensus gate (no PII ever leaves node)
- **Enterprise air-gap mode** — `THREAT_FEED_RECEIVE_ONLY=true` (Intelligence
  Feed add-on, consume without contributing)

### 2027–2028

- Signal Double Ratchet upgrade to PQC (HKDF-SHA3 + ML-KEM ratchet steps)
- FIPS 140-3 HSM integration for root key material
- APAC regional expansion: Singapore + Japan data centre pods
- EU AI Act Article 9 risk management system integration

---

## GTM Motion

| Segment | Channel | ACV |
|---------|---------|-----|
| Solo / Indie developers | Product-led (Starter → Individual self-serve) | $60/yr |
| Mid-market SaaS | Content marketing → Pro self-serve | $828/yr |
| SMB (legal, finance, healthcare) | SEP Communities feature → Pro + add-ons | $996–$1,188/yr |
| Enterprise / MSP | Sales-led → Enterprise annual contract | $2,988+/yr |

**Positioning:** "The only AI gateway that proves compliance mathematically —
Betti numbers, causal DAGs, STIX 2.1 audit chains, and ML-DSA-65 signatures,
not a vendor promise."

**Key differentiators over competitors:**
1. No data sent to third parties — on-prem MinIO, CPU-only inference
2. Post-quantum signatures on every document transfer (FIPS 204 — not just TLS)
3. STIX 2.1 tamper-evident chain exportable directly into Splunk/Elastic
4. `< 2ms` TDA pre-filter blocks DoS/bot noise before any LLM call
5. Autonomous self-healing (WardenHealer) — no pager on the happy path
