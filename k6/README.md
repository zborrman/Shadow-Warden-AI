# Shadow Warden AI — Load Testing with k6

## Install k6

| Platform | Command |
|----------|---------|
| Windows  | `winget install k6` or `choco install k6` |
| macOS    | `brew install k6` |
| Linux    | `sudo snap install k6` |
| Docker   | `docker run --rm -i grafana/k6 run - < k6/load_test.js` |

---

## Scripts

| Script | Purpose | Duration |
|--------|---------|---------|
| `smoke_test.js` | CI pre-deploy gate — 1 VU | 30 s |
| `load_test.js`  | Full load + spike + soak scenarios | up to 45 min |

---

## Quick Start

```bash
# 1. Start the gateway (must be running before the test)
docker-compose up -d warden redis

# 2. Smoke test (confirm it's alive)
k6 run k6/smoke_test.js

# 3. Baseline — 5 VU for 60 s
k6 run k6/load_test.js --env SCENARIO=baseline

# 4. Ramp — 0→50→0 VU over 8 min (simulates office morning surge)
k6 run k6/load_test.js --env SCENARIO=ramp

# 5. Spike — 100 concurrent users for 1 min
k6 run k6/load_test.js --env SCENARIO=spike

# 6. Full suite (baseline → ramp → spike in sequence)
k6 run k6/load_test.js --env SCENARIO=all
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8001` | Warden gateway URL |
| `WARDEN_API_KEY` | `` (blank) | X-API-Key header value (blank = auth disabled) |
| `SCENARIO` | `all` | Which scenario to run: `baseline`, `ramp`, `spike`, `soak`, `all` |

```bash
# Production server example
k6 run k6/load_test.js \
  --env BASE_URL=https://warden.yourcompany.com \
  --env WARDEN_API_KEY=sk_prod_... \
  --env SCENARIO=spike
```

---

## SLO Thresholds

The test enforces these Service Level Objectives automatically:

| Metric | SLO | Notes |
|--------|-----|-------|
| `/filter` p50 latency | ≤ 300 ms | Fast path (cached + clean prompt) |
| `/filter` p95 latency | ≤ 800 ms | ML inference + Redis + logging |
| `/filter` p99 latency | ≤ 2 000 ms | Jailbreak + long prompt edge cases |
| `/health` p95 latency | ≤ 80 ms | Load balancer probe |
| Error rate | < 1 % | HTTP 5xx + network errors |

If any threshold is violated, k6 exits with code 1 — ideal for blocking CI/CD pipelines.

---

## Grafana Live Dashboard

Stream results to InfluxDB and view in Grafana in real time:

```bash
# 1. Start InfluxDB + Grafana (already in docker-compose.yml)
docker-compose up -d grafana prometheus

# 2. Run test with InfluxDB output
k6 run k6/load_test.js --out influxdb=http://localhost:8086/k6

# 3. Import the k6 Grafana dashboard
#    → Grafana → Dashboards → Import → ID: 2587
```

---

## Reading the Results

```
          /\      |‾‾| /‾‾/   /‾‾/
     /\  /  \     |  |/  /   /  /
    /  \/    \    |     (   /   ‾‾\
   /          \   |  |\  \ |  (‾)  |
  / __________ \  |__| \__\ \_____/ .io

  scenarios: (100.00%) 3 scenarios, 100 max VUs
  ✓ warden_filter_latency_ms..............: p(50)=142ms p(95)=387ms p(99)=891ms
  ✓ warden_health_latency_ms..............: p(95)=31ms
  ✓ warden_error_rate.....................: 0.00%
  ✓ warden_filter_blocked_total...........: 247      (injections + PII blocked)
  ✓ warden_filter_allowed_total...........: 1103     (clean prompts passed)
```

**Key numbers to capture for `docs/performance.md`:**

| What to record | Where in output |
|----------------|-----------------|
| p95 filter latency | `warden_filter_latency_ms p(95)` |
| p99 filter latency | `warden_filter_latency_ms p(99)` |
| Max concurrent VU before error rate > 1% | Try `--env SCENARIO=spike` and increase `target` |
| Requests/sec at sustained load | `http_reqs` / `duration` |
| Block rate under load | `warden_filter_blocked_total` / `http_reqs` |

---

## Interpreting Common Failures

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| p95 > 800 ms at 50 VU | MiniLM ML inference saturating CPU | Add `--workers 4` to uvicorn or scale horizontally |
| Error rate > 1% at spike | Redis connection pool exhausted | Increase `RATE_LIMIT_PER_MINUTE` or Redis `maxclients` |
| `/health` p95 > 200 ms | GIL contention from ML workers | Use Gunicorn + multiple worker processes |
| 429 Too Many Requests | Rate limiter firing | Expected behaviour — raise `RATE_LIMIT_PER_MINUTE` for load test tenant |
| 503 on `/filter` | Warden gateway not running | `docker-compose ps warden` — check health |

---

## Saving Results for CI

```bash
# Save JSON results
k6 run k6/load_test.js \
  --env SCENARIO=baseline \
  --out json=results/baseline_$(date +%Y%m%d_%H%M).json

# Save summary CSV
k6 run k6/load_test.js \
  --env SCENARIO=ramp \
  --summary-export=results/ramp_summary.json
```

Add to your CI pipeline (`.github/workflows/ci.yml`):

```yaml
- name: Performance smoke test
  run: |
    k6 run k6/smoke_test.js \
      --env BASE_URL=http://localhost:8001
```
