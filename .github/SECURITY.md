# Security Policy

**Version 4.7 · Last updated 2026-04**

## Reporting a Vulnerability

Shadow Warden AI is a security-critical system. If you discover a vulnerability,
**do not** open a public GitHub issue — this could expose customers before a fix
is deployed.

Report privately through one of these channels:

| Channel | Contact |
|---------|---------|
| Email (preferred) | security@shadowwarden.ai |
| Web form | https://shadowwarden.ai/contact |
| PGP key | Available on request via email |

**Response SLA:**

| Stage | Target |
|-------|--------|
| Acknowledgement | ≤ 24 hours |
| Initial assessment | ≤ 72 hours |
| Patch for Critical/High | ≤ 14 days |
| Patch for Medium | ≤ 30 days |
| Coordinated disclosure | After patch is deployed |

Please include in your report:

- Description of the vulnerability and affected component(s)
- Steps to reproduce (curl commands, PoC code, or request samples)
- Potential impact — data exfiltration, bypass, DoS, etc.
- Suggested mitigations if any

We credit researchers who report valid issues in our release notes (opt-in).

## Scope

### In scope

- `warden/` — filter pipeline, agent subsystem, API endpoints
- `warden/crypto/` — PQC (HybridSigner, HybridKEM), key management
- `warden/communities/` — SEP protocol, peering, Transfer Guard
- `warden/sovereign/` — routing, attestation, MASQUE tunnels
- Authentication bypass (`auth_guard.py`, admin endpoints)
- GDPR violations — content logging, PII in Redis keys, non-atomic writes
- Secrets redaction false-negatives in `secret_redactor.py`
- Evolution Engine prompt injection (corpus poisoning via `evolve.py`)
- Shadow Ban bypass (`shadow_ban.py`, ERS sliding window)

### Out of scope

- Rate limiting on public demo endpoints (no SLA guarantee)
- Third-party CDN/infrastructure (Vercel, Cloudflare)
- Social engineering attacks against staff
- Denial-of-service via intentionally malformed large payloads

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 4.7.x   | ✅ Active  | Current release — PQC + SEP + Sovereign Cloud |
| 4.6.x   | ✅ Security patches only | SEP protocol |
| 4.5.x   | ⚠️ Critical only | Billing tier gates |
| < 4.5   | ❌ EOL | Upgrade required |

## Security Architecture (brief)

Shadow Warden AI is a 9-layer security gateway. Key hardening points:

- **GDPR §G-01**: Content is never logged — only metadata (type, length, timing)
- **S-03**: All API key comparisons use `hmac.compare_digest()` (constant-time)
- **S-06**: Secrets at rest encrypted with Fernet; no plaintext in Redis
- **PQC**: Ed25519 + ML-DSA-65 hybrid signatures; X25519 + ML-KEM-768 KEM
- **Causal Transfer Guard**: Bayesian risk gate (P ≥ 0.70) on every SEP entity transfer
- **Admin endpoints**: `X-Admin-Key` header required, checked via `_require_admin()`

See [`docs/security-model.md`](../docs/security-model.md) for the full 9-layer threat model.

## Proprietary Software Notice

This repository contains proprietary software. Access is governed by a separate
license agreement or NDA. Unauthorized access, copying, or distribution is
strictly prohibited. See [LICENSE](../LICENSE) for details.
