# Community Creation Guide

Shadow Warden AI v5.6 · Community Hub

---

## Overview

A **Shadow Warden Community** is a sovereign, cryptographically-attested collaboration space for
tenants who share security intelligence, AI governance rules, and compliance evidence. Every
community gets:

- A **SEP UECIID** — a base-62 provenance identifier (`SEP-{11 chars}`) for all transfers.
- An **Ed25519 keypair** (optionally upgraded to Hybrid PQC: Ed25519 + ML-DSA-65).
- A **STIX 2.1 tamper-evident audit chain** for every data transfer.
- A **Causal Transfer Guard** that blocks exfiltration risk ≥ 0.70 in < 20 ms.
- Optional **Document Intelligence** auto-scanning of all uploaded files.
- Optional **Evolution Engine** for sharing anonymized jailbreak-detection rule bundles.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Tier | Community Business+ or Pro/Enterprise |
| API Key | `WARDEN_API_KEY` set in portal settings |
| Vault key | `VAULT_MASTER_KEY` (Fernet) — required for keypair encryption |
| PQC upgrade | Enterprise tier + liboqs installed |
| Evolution Engine | `ANTHROPIC_API_KEY` set (fail-open otherwise) |

---

## Creating a Community via Portal Wizard

Navigate to **Community Hub → New Community** (or `/community-hub/create`) to launch the
6-step wizard.

### Step 1 — Identity

Set the fundamental identity of the community.

| Field | Required | Notes |
|---|---|---|
| Name | Yes | Max 80 characters |
| Description | No | Max 500 characters — context for members and auditors |
| Visibility | Yes | **Private**: hidden from directory · **Public**: discoverable |
| Join Policy | Yes | **Invite Only** / **Approval** (admin reviews) / **Open** (anyone) |

### Step 2 — Security

Choose the cryptographic mode for the community keypair.

**Classical Ed25519 (default)**
- 256-bit elliptic curve digital signature algorithm.
- NIST-recommended. Fast operations (~100 µs sign/verify).
- Generated at community creation; private key Fernet-encrypted with `VAULT_MASTER_KEY`.

**Hybrid PQC — Ed25519 + ML-DSA-65** _(Enterprise only)_
- Post-quantum safe: protected against both classical and quantum adversaries.
- Signature size: 3,373 bytes (Ed25519: 64 B + ML-DSA-65: 3,309 B).
- Activated via `POST /communities/{id}/upgrade-pqc` after community creation.
- Key ID suffix: `-hybrid` (e.g. `v1-hybrid`).
- KEM: X25519 + ML-KEM-768 (FIPS 203) for key exchange.
- Requires liboqs-python; fails open to Ed25519-only if unavailable.

### Step 3 — Members

Invite participants by Tenant ID before the community is created.

- Each entry becomes an `addMember()` call after creation.
- Roles: **Admin** (full control) · **Member** (standard) · **Observer** (read-only).
- Members receive a Knock-and-Verify token (72-hour TTL, one-time use).
- Additional members can be added at any time from the community settings page.

> You can skip this step — the creating tenant is automatically added as Owner.

### Step 4 — Peering & Tunnels

Configure federation with other Shadow Warden communities.

**Data Transfer Policy**

| Policy | Behavior |
|---|---|
| `MIRROR_ONLY` | Read-only replication. Peers receive data but cannot write back. |
| `REWRAP_ALLOWED` | Peers may re-encrypt and redistribute with their own keys. |
| `FULL_SYNC` | Bidirectional synchronization. Use only with fully trusted peers. |

**MASQUE Tunnel Regions**

Select jurisdictions through which federated traffic is routed:
`EU · US · UK · CA · SG · AU · JP · CH`

- Each tunnel supports MASQUE_H3, MASQUE_H2, CONNECT_TCP protocols.
- TOFU TLS pinning applied on first connection.
- Lifecycle: PENDING → ACTIVE → DEGRADED → OFFLINE.
- Cross-border transfers validated against Sovereign AI Cloud policy.
- The **Causal Transfer Guard** runs on every `transfer_entity()` call:
  - Evaluates data_class, transfer velocity, peering age/policy, burst pattern.
  - Blocks if `P(HIGH_RISK|evidence) ≥ TRANSFER_RISK_THRESHOLD` (default 0.70).
  - Runs in < 20 ms; produces a REJECTED transfer record (full audit trail kept).

### Step 5 — Compliance & Audit

**STIX 2.1 Tamper-Evident Audit Chain** _(recommended: on)_
- Every transfer appended as a STIX 2.1 bundle with SHA-256 prev_hash chain.
- Genesis block: `prev_hash = "0" * 64`.
- `verify_chain()` re-hashes all bundles from canonical JSON (sorted keys, no whitespace).
- Exportable as OASIS-compliant JSONL for SIEM import.
- Available at `GET /sep/audit-chain/{community_id}`.

**Document Intelligence Auto-scan** _(recommended: on)_
- All uploaded files are converted via MarkItDown (PDF, DOCX, images, audio).
- Converted markdown is run through the full 9-stage security filter pipeline.
- Conversion cache: Redis SHA-256 key, TTL by file type (PDF/DOCX 24 h, images 1 h, audio 7 d).
- Size gate: 50 MB (`DOC_INTEL_MAX_BYTES`); timeout: 30 s.

**Community Charter**
- Define governance rules, acceptable use policy, and member responsibilities.
- Uploaded via `POST /communities/{id}/charter`.
- Status lifecycle: DRAFT → ACTIVE → SUPERSEDED.
- Members are tracked for acceptance via `validate_charter_compliance()`.

**Compliance Frameworks**
Select frameworks to monitor continuously (Pro+):

| Framework | Controls |
|---|---|
| GDPR | 6 controls — data minimization, consent, Art. 30 register, DPA |
| SOC 2 | 5 controls — access, change management, availability, incident |
| ISO 27001:2022 | 4 controls (93-control full matrix in Streamlit page 18) |
| HIPAA | 4 controls — PHI handling, breach notification, access control |

Compliance posture cached in Redis (`compliance:posture:{tenant_id}`, TTL 300 s).
Real-time WebSocket push at `ws://…/compliance/ws` (30-second loop).

### Step 6 — Integrations & Finish

**Evolution Engine**
- Shares anonymized jailbreak-detection rule bundles with federated communities.
- Rule types: `regex_pattern`, `embedding_example`, `jailbreak_signature`, `compound_rule`.
- All bundles screened through the security filter before sharing.
- **Every bundle requires explicit admin approval** before import into target community.
- Operates in fail-open mode without `ANTHROPIC_API_KEY`.

**Notification Channels**
- **Slack Webhook**: receives HIGH/BLOCK events, charter acceptance, transfer alerts.
- **Microsoft Teams Webhook**: same event set forwarded to Teams.

Click **Create Community** to execute the full provisioning sequence.

---

## Creating a Community via API

### 1. Create the community

```bash
curl -X POST https://api.shadow-warden-ai.com/communities \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "APAC Security Alliance",
    "description": "Cross-regional AI threat intelligence sharing",
    "creator_tenant_id": "tenant_acme",
    "visibility": "private",
    "join_policy": "approval"
  }'
```

Response includes `community_id` — save it for subsequent calls.

### 2. Upgrade to Hybrid PQC (Enterprise only)

```bash
curl -X POST https://api.shadow-warden-ai.com/communities/$CID/upgrade-pqc \
  -H "X-API-Key: $WARDEN_API_KEY"
```

### 3. Add members

```bash
curl -X POST https://api.shadow-warden-ai.com/communities/$CID/members \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant_partner", "role": "member", "display_name": "Partner Corp"}'
```

### 4. Issue Knock-and-Verify invitation

```bash
curl -X POST https://api.shadow-warden-ai.com/sep/knock \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"community_id": "'$CID'", "invitee_tenant_id": "tenant_new"}'
```

Returns a one-time token (72-hour TTL). The invitee calls `POST /sep/knock/verify` to accept.

### 5. Configure peering

```bash
# Create a peering with another community
curl -X POST https://api.shadow-warden-ai.com/sep/peerings \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{
    "source_community_id": "'$CID'",
    "target_community_id": "comm_partner_id",
    "policy": "REWRAP_ALLOWED"
  }'
```

### 6. Upload community charter

```bash
curl -X POST https://api.shadow-warden-ai.com/communities/$CID/charter \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"content": "Charter text...", "version": 1}'
```

### 7. Share an evolution rule bundle

```bash
curl -X POST https://api.shadow-warden-ai.com/communities/$CID/evolution/share \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{
    "publisher_tenant_id": "tenant_acme",
    "rule_type": "jailbreak_signature",
    "rule_content": "ignore previous instructions"
  }'
```

### 8. Transfer a document to a peer community

```bash
curl -X POST https://api.shadow-warden-ai.com/sep/peerings/$PEERING_ID/transfer \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"entity_id": "SEP-abc123XYZ45", "target_community_id": "comm_partner_id"}'
```

---

## Post-Creation Configuration

### Upload documents

```bash
curl -X POST https://api.shadow-warden-ai.com/communities/$CID/data/upload \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -F "file=@report.pdf" \
  -F "context=Q3 threat report"
```

All uploads are assigned a UECIID (`SEP-{11 chars}`) and optionally scanned by Document
Intelligence if enabled.

### Register a Sovereign Data Pod

Route community data to a specific jurisdiction (EU, US, etc.):

```bash
curl -X POST https://api.shadow-warden-ai.com/sep/pods \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{
    "community_id": "'$CID'",
    "jurisdiction": "EU",
    "data_class": "PHI",
    "is_primary": true
  }'
```

### Scan documents with SOVA

```bash
curl -X POST https://api.shadow-warden-ai.com/agent/sova \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"query": "Scan all community documents for PII and summarize risk posture"}'
```

---

## Managing the Community

### Dashboards

| Dashboard | URL | Data |
|---|---|---|
| SOC Dashboard | `http://host:3002/community/{id}` | 6 tabs: Overview/Members/Data/Compliance/Evolution/Analytics |
| Streamlit Hub | `:8501 → page 22 Community Hub` | 7 tabs with live data |
| Compliance | `:8501 → page 21 Compliance Dashboard` | 5-tab gap manager, 30 s refresh |
| ISO 27001 | `:8501 → page 18 ISO 27001` | 93-control matrix |

### Key API endpoints

| Endpoint | Purpose |
|---|---|
| `GET /communities/{id}` | Fetch community details |
| `GET /communities/{id}/members` | List members |
| `GET /communities/{id}/data` | List uploaded files |
| `GET /communities/{id}/compliance` | Compliance report |
| `GET /communities/{id}/evolution/stats` | Evolution bundle statistics |
| `GET /sep/audit-chain/{id}` | STIX 2.1 audit chain |
| `POST /sep/audit-chain/{id}/verify` | Verify chain integrity |
| `GET /sep/audit-chain/{id}/export` | Export as OASIS JSONL |
| `DELETE /communities/{id}` | Delete (owner only, irreversible) |

### WebSocket live compliance push

```javascript
const ws = new WebSocket('wss://api.shadow-warden-ai.com/compliance/ws')
ws.onmessage = ({ data }) => {
  const report = JSON.parse(data)
  console.log(report.score, report.gaps)
}
```

---

## FAQ

**Q: Who is automatically added as Owner when a community is created?**  
A: The `creator_tenant_id` supplied at creation. Owners cannot be removed; transfer ownership via
admin settings.

**Q: Can I change the join policy after creation?**  
A: Yes — `PATCH /communities/{id}` with `{"join_policy": "open"}`.

**Q: What happens if a transfer is blocked by the Causal Transfer Guard?**  
A: The transfer record is written with status `REJECTED` (not raised as an exception). The STIX
audit chain records it. The entity remains in the source community.

**Q: How do I verify the STIX audit chain hasn't been tampered with?**  
A: `POST /sep/audit-chain/{id}/verify` re-hashes all bundles from canonical JSON and compares
prev_hash values. Returns `{"valid": true, "entries": N}` or a list of broken links.

**Q: Can I use the Evolution Engine without an Anthropic API key?**  
A: Yes — the engine operates in fail-open mode. Rule bundles can still be shared and imported
manually, but auto-synthesis from ArXiv papers and AI-assisted rule generation are disabled.

**Q: What is the maximum number of communities per tenant?**  
A: Community Business tier: 3 communities × 10 members each. Pro/Enterprise: unlimited.

**Q: How do I export all community data for GDPR compliance?**  
A: `GET /communities/{id}/data` lists all files. Use `GET /sep/audit-chain/{id}/export` for the
full STIX 2.1 JSONL audit trail. Use `POST /compliance/posture/recalculate` to force a fresh
compliance report before export.

**Q: Can the charter be updated after activation?**  
A: Yes — upload a new version (`POST /communities/{id}/charter`). The old version is archived
with status `SUPERSEDED`. Member re-acceptance is tracked separately.

**Q: What data is logged?**  
A: Shadow Warden is GDPR-compliant — content is **never logged**, only metadata (request type,
length, timing, decision). Full audit trail is in the STIX chain and the `data/logs.json`
NDJSON store (purge via `POST /gdpr/purge`).
