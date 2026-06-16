# Production Launch Checklist — Shadow Warden AI v6.6

M2M Agentic Marketplace full-stack release.

---

## Pre-launch

### Code Quality
- [ ] All Python tests passing: `pytest -v --cov=warden --cov-fail-under=80 -m "not adversarial"`
- [ ] Linting clean: `ruff check warden/ analytics/ --ignore E501`
- [ ] Production readiness smoke tests: `pytest warden/tests/test_production_readiness.py -v`
- [ ] Pre-deploy script passes: `bash scripts/pre_deploy_check.sh`

### Frontend Builds
- [ ] Portal builds: `cd portal && npm run build`
- [ ] Dashboard builds: `cd dashboard && npm run build`
- [ ] Astro site builds: `cd site && npm run build`

### Environment Configuration
- [ ] `.env` copied from `.env.example` with all values filled
- [ ] `WARDEN_API_KEY` — strong random hex (min 32 chars)
- [ ] `SECRET_KEY` — strong random hex (min 32 chars)
- [ ] `VAULT_MASTER_KEY` — valid Fernet key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
- [ ] `DB_PASSWORD` — strong password for PostgreSQL
- [ ] `PORTAL_JWT_SECRET` — strong random hex
- [ ] `ANTHROPIC_API_KEY` — for SOVA agent + Evolution Engine
- [ ] `SLACK_WEBHOOK_URL` — for alerting
- [ ] `MARKETPLACE_CONTRACT_ADDRESS` — Sepolia escrow contract (or leave blank for off-chain)
- [ ] `S3_ENABLED=true` + MinIO credentials configured
- [ ] `ALLOW_UNAUTHENTICATED=false` — CRITICAL: never true in production
- [ ] `CORS_ORIGINS` — includes `https://shadow-warden-ai.com,https://app.shadow-warden-ai.com,https://dash.shadow-warden-ai.com`

### Infrastructure
- [ ] SSL certificates: Caddy auto-provisions via ACME (requires DNS pointing to server)
- [ ] DNS A records set: `api.`, `app.`, `dash.`, `docs.` → VPS IP `91.98.234.160`
- [ ] Firewall: ports 80/443 (TCP+UDP) open; 22 restricted to deploy IPs
- [ ] Database backups configured (PostgreSQL daily pg_dump to MinIO)
- [ ] Grafana admin password changed from default

---

## Launch Sequence

```bash
# 1. Pull latest code
cd /opt/shadow-warden
git pull origin main

# 2. Verify environment
grep -c "change-me" .env && echo "WARNING: change-me values found in .env!" || echo "No change-me values"

# 3. Build images (no-cache for fresh start)
docker compose build --no-cache admin arq-worker
docker compose build warden analytics portal dashboard

# 4. Start services
docker compose up -d --remove-orphans

# 5. Wait for health (up to 5 min — ML model load time)
for i in $(seq 1 60); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/health)
  [ "$STATUS" = "200" ] && echo "✔ Warden healthy after ${i}x5s" && break
  echo "attempt $i/60 — HTTP $STATUS — waiting 5s..."
  sleep 5
done
```

---

## Smoke Tests

Run after services are up:

```bash
API_KEY="$WARDEN_API_KEY"

# Health
curl -f http://localhost:8001/health | jq .

# Filter — safe request
curl -s -X POST http://localhost:8001/filter \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is machine learning?"}' | jq .

# Marketplace — list agents
curl -s http://localhost:8001/marketplace/agents \
  -H "X-API-Key: $API_KEY" | jq .count

# Edge packs
curl -s http://localhost:8001/agents/packs \
  -H "X-API-Key: $API_KEY" | jq .count

# Prometheus metrics
curl -s http://localhost:8001/metrics | grep warden_requests_total | head -5

# Create smoke test community
curl -s -X POST http://localhost:8001/communities \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Smoke Test Community", "description": "Launch verification"}' | jq .community_id
```

---

## Healthcheck Table

| Service | URL | Expected |
|---------|-----|----------|
| Warden gateway | `http://localhost:8001/health` | `{"status":"ok"}` |
| Analytics API | `http://localhost:8002/health` | `{"status":"ok"}` |
| Streamlit dashboard | `http://localhost:8501` | HTTP 200 |
| Portal | `http://localhost:3001` | HTTP 200 |
| SOC Dashboard | `http://localhost:3002` | HTTP 200 |
| Prometheus | `http://localhost:9090/-/healthy` | HTTP 200 |
| Grafana | `http://localhost:3000/api/health` | `{"database":"ok"}` |
| MinIO | `http://localhost:9000/minio/health/live` | HTTP 200 |
| Redis | `redis-cli ping` | `PONG` |

---

## Post-launch Monitoring

### First 24h
- [ ] Grafana dashboards loading (`http://91.98.234.160:3000`)
- [ ] Prometheus scraping all targets (`http://91.98.234.160:9090/targets`)
- [ ] Test Slack alert (trigger from SOVA: `POST /agent/sova` → "send a test alert")
- [ ] Monitor error rate < 0.1% (Grafana: `warden_requests_total{status="5xx"}`)
- [ ] Monitor P99 latency < 50ms (Grafana: `warden_filter_duration_seconds p99`)
- [ ] MinIO Evidence Vault receiving bundles (`warden-evidence` bucket)
- [ ] SOVA morning brief fires at 08:00 UTC (check ARQ logs)

### Performance Baseline
- [ ] Run k6 smoke test: `k6 run k6/smoke_test.js --env BASE_URL=https://api.shadow-warden-ai.com`
- [ ] Document baseline P50/P95/P99 latency numbers
- [ ] Set Grafana SLO alert thresholds:
  - P99 latency > 50ms → warning
  - Error rate > 0.5% → critical
  - Availability < 99.9% → critical

---

## Rollback Procedure

```bash
# Identify last working commit
git log --oneline -10

# Rollback to previous version
git reset --hard <previous-sha>
docker compose down --remove-orphans
docker compose build warden
docker compose up -d --no-build --remove-orphans

# Verify health
curl -f http://localhost:8001/health
```

---

## Key Production URLs

| Service | URL |
|---------|-----|
| API Gateway | `https://api.shadow-warden-ai.com` |
| Customer Portal | `https://app.shadow-warden-ai.com` |
| SOC Dashboard | `https://dash.shadow-warden-ai.com` |
| API Docs (Redoc) | `https://docs.shadow-warden-ai.com` |
| Grafana | `http://91.98.234.160:3000` |
| Jaeger Traces | `http://91.98.234.160:16686` |

---

## Contact & Escalation

- **On-call alert**: Slack `#shadow-warden-alerts`
- **PagerDuty**: fires on BLOCK-level attacks + P99 > 50ms SLO breach
- **Incident register**: `POST /incidents` or Streamlit page 10
- **Break-glass**: `POST /admin/break-glass` (Enterprise only, HMAC-signed)
