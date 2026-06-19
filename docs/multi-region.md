# Shadow Warden AI — Multi-Region Active-Active

**Feature:** SC-03 · **Version:** v6.1 · **Status:** Shipped

---

## Overview

Shadow Warden AI supports multi-region active-active deployments. Every instance serves traffic independently; there is no primary/replica distinction at the gateway layer. Sovereign routing (`warden/sovereign/router.py`) handles data-residency compliance across regions.

Supported regions: `eu`, `us`, `ap`, `uk`, `sg`, `au`

---

## Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-Region-Prefer: eu` | Request → Warden | Client hint for preferred region |
| `X-Region: eu` | Warden → Client | Always set — identifies the responding instance |
| `X-Region-Latency-Ms: 12` | Warden → Client | Processing time in milliseconds |
| `X-Region-Redirect: us` | Warden → Client | Set when the responding region differs from preferred |

---

## Middleware

`warden/middleware/region.py` — `RegionMiddleware` (Starlette `BaseHTTPMiddleware`):

```python
# Registered in warden/main.py lifespan:
app.add_middleware(RegionMiddleware)
```

The region identity is set via `WARDEN_REGION` env var (default: `eu`). The middleware reads `X-Region-Prefer` from every request and sets `X-Region-Redirect` when the client should retry against a closer instance.

---

## Configuration

```bash
# In /opt/shadow-warden/.env
WARDEN_REGION=eu          # Options: eu | us | ap | uk | sg | au
```

---

## Sovereign Routing Integration

`warden/sovereign/router.py` reads `X-Region-Prefer` to select MASQUE tunnels in the preferred jurisdiction. Transfer rules from `warden/sovereign/jurisdictions.py` enforce GDPR adequacy decisions:

- EU ↔ UK, CA, JP, CH: adequacy transfers allowed
- PHI: US/EU/UK/CA/CH only
- CLASSIFIED: no cross-region transfer

---

## Active-Active Deployment

Each region runs the full 11-service stack independently:

```
proxy  → warden (8001)  → redis (local)
                        → postgres (replicated, regional leader)
                        → minio (regional bucket)
```

**Consistency model:** eventual. Redis state (ERS scores, shadow bans, session memory) is local to each region. Postgres replication handles billing and community data. MinIO evidence vault uses cross-region bucket replication.

---

## Health Check

```bash
curl -H "X-Region-Prefer: us" https://api.shadow-warden-ai.com/health
# Response headers:
# X-Region: eu
# X-Region-Redirect: us     ← redirect hint if us instance available
```

---

## Helm Values — Per-Region Override

```yaml
# charts/shadow-warden/values.prod-us.yaml
global:
  region: us

warden:
  env:
    - name: WARDEN_REGION
      value: us
    - name: POSTGRES_URL
      value: postgresql://postgres-us:5432/warden
```

Apply with:
```bash
helm upgrade warden charts/shadow-warden \
  -f charts/shadow-warden/values.yaml \
  -f charts/shadow-warden/values.prod-us.yaml
```
