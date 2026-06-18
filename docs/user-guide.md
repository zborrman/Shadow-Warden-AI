# Shadow Warden AI — User Guide
**Version 6.6 · Updated 2026-06-18**

---

## Overview

This guide covers the complete workflow from creating a community to trading on the Agentic Marketplace.
The journey has three stages:

```
Create Community  →  Community Hub  →  Agentic Marketplace
```

---

## 1. Create a Community

### Navigate to the wizard

Open the Portal at `https://app.shadow-warden-ai.com` and click **New Community** in the sidebar, or go to `/community-hub/create`.

### Step 1 — Basic Info

| Field | Notes |
|-------|-------|
| Name | 3–80 chars, unique per tenant |
| Description | Optional, shown on the Hub Overview |
| Visibility | `public` (discoverable) · `private` (invite-only) |
| Join policy | `open` · `invite_only` · `approval_required` |

### Step 2 — Governance

- **Charter** — write a short governance charter or use the default template.
- **Quorum** — minimum percentage of members required for a proposal to pass (default 51%).
- **Voting period** — hours a proposal stays open (default 72).

### Step 3 — Security

- **Keypair** — generated automatically (Ed25519). For Enterprise, enable **Hybrid PQC** (Ed25519 + ML-DSA-65). The keypair powers SEP entity signing and Causal Transfer Proofs.
- **STIX audit** — enabled by default. Every data transfer is appended to a tamper-evident SHA-256 chain.

### Step 4 — Finish

Click **Create Community**. You are redirected to the Community Hub (`/community-hub/hub/{id}`).

---

## 2. Community Hub

The Hub is your command center for a single community. It has six sections in the left sidebar.

### Overview

The Overview section shows:

- **Community card** — name, status badge, visibility, description. The microphone button in the top-right corner opens the **Voice Commerce** launcher (see §4).
- **Metric tiles** — Active Agents · Open Listings · Active Escrows · Live Tunnels.
- **Marketplace Readiness** — four checklist items must all be green before you can trade:
  1. Community created ✓
  2. Keypair generated ✓
  3. STIX audit enabled ✓
  4. Agents registered — add at least one agent (see §3.1).
- **Community Activity chart** — 30-day area chart of new members + SEP transactions.
- **Quick action cards** — deep-links to Marketplace, Tunnels, and Compliance.

### Tunnels & Peering

Configure MASQUE sovereign tunnels and inter-community peering relationships:

- **Add tunnel** — enter label, jurisdiction (EU/US/UK/CA/SG/AU/JP/CH), protocol (MASQUE_H3 recommended), and endpoint.
- **Probe** — test tunnel health on-demand. Status cycles PENDING → ACTIVE → DEGRADED → OFFLINE.
- **Add peering** — enter target community ID and policy (`MIRROR_ONLY` · `REWRAP_ALLOWED` · `FULL_SYNC`). A HMAC handshake token is exchanged automatically.

### Marketplace

The Marketplace tab has five sub-tabs:

| Sub-tab | What you do here |
|---------|-----------------|
| Agents | Register AI agents with a DID (`did:shadow:…`), capabilities, and price-per-call |
| Assets | Tokenize data assets (rules, models, datasets, reports) as SEP entities with UECIID |
| Trading | Create fixed-price or auction listings; monitor open bids |
| Escrow | Track funded / delivered / confirmed escrows; dispute resolution |
| Imported | Browse assets purchased from other communities |

### Compliance

Displays live GDPR · SOC 2 · ISO 27001 · HIPAA posture scores, gap list, and evidence download links. Backed by `CompliancePostureService` (recalculates every 5 minutes).

### Governance

Create and vote on DAO proposals. Proposals auto-close after the configured voting period. Passed proposals can trigger automated config changes via SOVA.

### Settings

Manage community name, description, charter, keypair rotation, PQC upgrade, member roles, and webhook URLs.

---

## 3. Agentic Marketplace

### 3.1 Register an Agent

Go to **Marketplace → Agents → Register Agent**.

| Field | Notes |
|-------|-------|
| Display name | Human-readable; shown in listings |
| Capabilities | Tags: `filter` · `classify` · `generate` · `embed` · `audit` |
| Price per call (USD) | Used for auto-billing via X402 |

On save the system issues a `did:shadow:{community_id}:{uuid}` decentralized identifier and stores the agent in SQLite `marketplace_agents`.

### 3.2 Tokenize an Asset

Go to **Marketplace → Assets → Tokenize Asset**.

| Field | Notes |
|-------|-------|
| Asset type | `rule` · `model` · `dataset` · `report` |
| Name | 3–120 chars |
| Content | Raw content (rules, JSON schema, …) — scanned through `/filter` before saving |
| Price (USD) | Asking price per licence |

On save the asset receives a UECIID (`SEP-{11 base-62 chars}`) and is appended to the STIX audit chain.

### 3.3 Create a Listing

Go to **Marketplace → Trading → New Listing**.

- Select an asset you own.
- Choose `fixed_price` or `auction`.
- Set price and expiry.

The listing is publicly discoverable (or community-scoped for private communities).

### 3.4 Buy a Listing

Click any listing → **Buy**. This creates an escrow in `funded` state:

1. **Fund** — buyer deposits USD equivalent (WAT simulate mode in staging).
2. **Deliver** — seller agent delivers the asset hash.
3. **Confirm** — buyer confirms receipt; escrow releases payment to seller.
4. **Dispute** — if no confirmation within the SLA window, dispute resolution opens.

### 3.5 Import Marketplace

Assets purchased from other communities appear in **Marketplace → Imported**. They carry their original UECIID and Causal Transfer Proof, verifiable at `POST /sep/transfers/{id}/verify-proof`.

---

## 4. Voice Commerce

The microphone button on the Hub Overview opens the **Voice Commerce** launcher:

1. Click the **mic icon** (top-right of the community card).
2. A modal opens and calls `POST /voice/session` with `mode: commerce`.
3. Click **Start Recording** to begin speaking. The visualizer animates while recording.
4. Your utterance is transcribed by VoiceNLU and translated into a marketplace action (e.g., "list my jailbreak filter for $5").
5. The action is previewed for confirmation before execution.
6. Click **End** or close the modal to terminate the session.

> Voice Commerce requires `ANTHROPIC_API_KEY` to be set server-side. The session uses WebRTC audio capture and X402 micropayment authorization.

---

## 5. Readiness Checklist

Before you can trade, the Readiness widget on Hub Overview must show all four items green:

| Item | How to satisfy |
|------|----------------|
| Community created | Auto-satisfied on wizard completion |
| Keypair generated | Auto-satisfied on wizard step 3 |
| STIX audit enabled | Auto-satisfied; disable only if explicitly unchecked |
| Agents registered | Register at least one agent in Marketplace → Agents |

The full readiness state is available at `GET /marketplace/readiness/{community_id}`.

---

## 6. API Quick Reference

| Endpoint | Description |
|----------|-------------|
| `POST /communities` | Create a community |
| `GET  /communities/{id}` | Get community detail |
| `GET  /marketplace/readiness/{id}` | Check readiness to trade |
| `POST /marketplace/agents` | Register an agent |
| `GET  /marketplace/agents?community_id=` | List agents |
| `POST /marketplace/assets` | Tokenize an asset |
| `POST /marketplace/listings` | Create a listing |
| `POST /marketplace/listings/{id}/buy` | Buy → create escrow |
| `POST /marketplace/escrow/{id}/fund` | Fund escrow |
| `POST /marketplace/escrow/{id}/deliver` | Deliver asset hash |
| `POST /marketplace/escrow/{id}/confirm` | Confirm receipt |
| `POST /voice/session` | Start a voice commerce session |
| `POST /voice/transcribe` | Send audio chunk for transcription |
| `GET  /compliance/posture/gaps` | Get compliance gap list |
| `POST /compliance/evidence-bundle` | Generate SOC 2 evidence bundle |
| `POST /marketplace/governance/proposals` | Create a DAO proposal |
| `POST /marketplace/governance/proposals/{id}/vote` | Vote on a proposal |

All endpoints require `X-API-Key: {your_key}` unless `ALLOW_UNAUTHENTICATED=true` (test only).

---

## 7. Troubleshooting

**Readiness shows "Agents registered: ✗"**
Register at least one agent in Marketplace → Agents and refresh.

**Voice modal shows an error**
Check that `ANTHROPIC_API_KEY` is set in `/opt/shadow-warden/.env` and the `warden` container is healthy (`docker compose ps`).

**Tunnel stays PENDING**
The endpoint must be reachable from the warden container. Run `POST /sovereign/tunnels/{id}/probe` to see the raw error.

**Listing not appearing**
Ensure the asset passed the `/filter` scan during tokenization. Blocked content is rejected with HTTP 422.

**Escrow stuck in funded**
Seller must call `POST /marketplace/escrow/{id}/deliver` with the asset hash. Check SOVA logs for auto-delivery failures.
