# ANS Certificate Authority — MKT-13

**Version:** v6.6  
**Tier:** Enterprise  
**Add-on:** `ans_certificate_pack` — $25/mo

## Overview

Agentic Naming System (ANS) X.509 certificate authority. Issues verifiable identity certificates to marketplace agents so downstream systems can cryptographically authenticate agent provenance. Revocation is enforced via Redis CRL.

## Architecture

```
CertificateAuthority.issue_agent_certificate(agent_id, community_id, public_key_pem)
    → subject CN: agent-{agent_id}.{community_id}.shadow-warden.ai
    ├── [cryptography installed] → Ed25519PrivateKey CA → real X.509 DER → PEM
    └── [fallback]               → JSON synthetic cert with SHA-256 signature

CertificateAuthority.revoke_certificate(agent_id)
    → DB: ans_certificates.revoked = TRUE
    → Redis: SADD ans:crl:{community_id} {cert_id}

CertificateAuthority.verify_certificate(cert_pem)
    → DB lookup by cert fingerprint
    → CRL check (Redis SISMEMBER)
    → Expiry check (expires_at > now)
    → Returns {valid: bool, reason: str}
```

## Subject CN Format

```
agent-{agent_id}.{community_id}.shadow-warden.ai
```

Example: `agent-a8f2b1c3.community-finance.shadow-warden.ai`

## Files

| File | Role |
|------|------|
| `warden/security/__init__.py` | Package init |
| `warden/security/certificate_authority.py` | `CertificateAuthority` class + `get_ca()` singleton |
| `warden/security/api.py` | FastAPI router `/marketplace/agents/{id}/certificate` |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/marketplace/agents/{id}/certificate` | Issue X.509 certificate |
| `GET` | `/marketplace/agents/{id}/certificate` | Download active certificate |
| `DELETE` | `/marketplace/agents/{id}/certificate` | Revoke active certificate |
| `POST` | `/marketplace/certificates/verify` | Verify a PEM certificate |

## Database

SQLite table `ans_certificates` in `ANS_DB_PATH` (default: `SEP_DB_PATH`).

| Column | Type | Description |
|--------|------|-------------|
| `cert_id` | TEXT PK | UUID4 certificate identifier |
| `agent_id` | TEXT | Agent identifier |
| `community_id` | TEXT | Community identifier |
| `subject_cn` | TEXT | Certificate subject common name |
| `cert_pem` | TEXT | PEM-encoded certificate (or JSON synthetic) |
| `issued_at` | TEXT | ISO-8601 issue timestamp |
| `expires_at` | TEXT | ISO-8601 expiry timestamp |
| `revoked` | INTEGER | 0 = active, 1 = revoked |

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `ANS_DB_PATH` | `SEP_DB_PATH` or `/tmp/warden_sep.db` | SQLite database path |
| `ANS_CERT_VALIDITY_DAYS` | `365` | Certificate validity period |
| `ANS_CA_KEY_PATH` | `data/ans_ca.pem` | CA private key (auto-generated if missing) |

## Prometheus Metrics

| Metric | Description |
|--------|-------------|
| `warden_ans_certs_issued_total` | Total certificates issued |
| `warden_ans_certs_revoked_total` | Total certificates revoked |
