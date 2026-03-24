# Shadow Warden AI — Security & Operations Advisory

**Document version:** 1.1 — March 2026
**Applies to:** Shadow Warden AI v1.8
**Audience:** Blue Team, Security Operations, DevOps
**Status:** CONFIDENTIAL / INTERNAL USE ONLY

---

## How to Use This Document

Run `scripts/warden_doctor.py` first.  The tool prints a structured verdict for each check.  Find your symptom below, follow the numbered steps, and re-run the doctor to confirm resolution.

```bash
python scripts/warden_doctor.py --url http://localhost:80 --key $WARDEN_API_KEY
```

---

## P0 — Critical: Gateway Unreachable or Circuit Breaker Open

**Trigger:** `warden_doctor.py` reports `Health Check FAIL` (gateway unreachable, or `circuit_breaker.status = open`).

### Redis connection failure

```bash
# Confirm Redis is running and reachable from within the warden container
docker compose exec warden redis-cli -u $REDIS_URL ping
docker compose logs redis --tail 50
```

If `ping` returns `PONG` but the gateway still shows Redis as degraded, the `REDIS_URL` env var in `warden` may point to a different hostname than the actual container:

```bash
docker compose exec warden printenv REDIS_URL
# Should be: redis://redis:6379
```

Restart Redis if memory pressure is suspected:

```bash
docker compose exec redis redis-cli info memory | grep used_memory_human
docker compose restart redis
```

### Circuit breaker is open

The circuit breaker trips when the Warden pipeline records sustained failures (timeouts or 5xx from upstream).  It stays open for a cooldown period, then recovers automatically.

```bash
# Check current state and cooldown_remaining_s
curl -s http://localhost:80/health | python -m json.tool | grep -A5 circuit_breaker

# Inspect pipeline errors
docker compose logs warden --tail 100 | grep -E "error|5xx|timeout"
```

If the upstream LLM provider (OpenAI, Azure) is returning 5xx, the circuit will self-heal once the provider recovers.  To force an immediate reset (use only after confirming the root cause is resolved):

```bash
# Flush the circuit breaker key in Redis
docker compose exec redis redis-cli del warden:circuit:failures warden:circuit:open
```

### Disk full — Postgres / Audit Trail stalled

The SHA-256 audit trail writes to Postgres.  If the disk is full, writes stall silently.

```bash
df -h
docker compose exec postgres psql -U warden -c "SELECT pg_size_pretty(pg_database_size('warden'));"

# Free space: purge logs older than 30 days (GDPR-required anyway)
curl -X POST http://localhost:80/gdpr/purge \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"before_days": 30}'
```

---

## P1 — Degraded: High Latency (Benchmark WARN or FAIL)

**Trigger:** Text P99 > 150 ms (WARN) or > 500 ms (FAIL).  Multimodal P99 > 800 ms (FAIL).

### CPU throttling

```bash
docker stats --no-stream
```

If `warden` container CPU usage is above 85% sustained, the MiniLM inference threadpool is saturating the available cores.

Options (in order of preference):

1. **Scale horizontally** — add replicas behind the proxy:
   ```yaml
   # docker-compose.yml
   warden:
     deploy:
       replicas: 2
   ```

2. **Raise SEMANTIC_THRESHOLD** to reduce deep-analysis invocations on borderline requests (live-tunable, no restart):
   ```bash
   curl -X POST http://localhost:80/api/config/update \
        -H "X-API-Key: $WARDEN_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"semantic_threshold": 0.78}'
   ```

3. **Verify model pre-warm completed** — cold inference on the first request after startup is 5–10× slower:
   ```bash
   docker compose logs warden | grep -i "prewarmed\|model loaded\|MiniLM"
   ```

### Evolution Engine running during benchmarks

The Evolution Engine dispatches async background tasks to Claude Opus when HIGH/BLOCK events occur.  A benchmark that fires 50 attack payloads will queue 50 Opus calls, competing for CPU.

To benchmark cleanly:

```bash
# Disable Evolution Engine temporarily
ANTHROPIC_API_KEY="" python scripts/warden_doctor.py
```

Or benchmark on clean payloads only, which do not trigger the Evolution Engine.

### Multimodal P99 > 800 ms

CLIP (image) and Whisper (audio) are the heaviest inference steps.

1. Check model loading:
   ```bash
   docker compose logs warden | grep -E "CLIP|Whisper|ImageGuard|AudioGuard"
   ```

2. Limit upstream file sizes in the Nginx proxy (`proxy` service):
   ```nginx
   # nginx.conf
   client_max_body_size 5m;   # images
   ```
   Recommended limits: **5 MB** images, **10 MB** audio.

3. If CLIP fails to load (HuggingFace auth error), the ImageGuard fails-open with a warning log.  The pipeline continues but image scanning is disabled until `HF_TOKEN` is set:
   ```bash
   docker compose exec warden printenv HF_TOKEN
   ```

---

## P2 — Security Anomaly: ERS or Audit Integrity Alert

### Audit Integrity FAIL — SHA-256 chain broken

**Severity: CRITICAL.**  A broken attestation chain means one or more audit log entries were modified or deleted after they were written.

```bash
# Export the evidence bundle immediately for forensic preservation
curl -s http://localhost:80/compliance/evidence/<SESSION_ID> \
     -H "X-API-Key: $WARDEN_API_KEY" > evidence_$(date +%s).json

# Verify the bundle integrity locally
python -c "
import json, sys
from warden.compliance.bundler import EvidenceBundler
b = json.load(open(sys.argv[1]))
print('INTACT' if EvidenceBundler.verify_bundle(b) else 'TAMPERED')
" evidence_*.json
```

Next steps:
1. Compare the exported bundle against your most recent backup
2. Identify the first entry where `Cs` drops below 1.0 — that is the tamper window
3. Escalate to your CISO and legal team before any further writes to the audit store

### Excessive shadow bans (> 30% of traffic)

If a large fraction of legitimate users are being shadow-banned, the ERS thresholds may be miscalibrated for your traffic profile.

```bash
# Check current ERS thresholds (all tunable via env vars — no restart needed)
docker compose exec warden printenv | grep ERS_

# Default values
# ERS_MEDIUM_THRESHOLD=0.30
# ERS_HIGH_THRESHOLD=0.55
# ERS_SHADOW_BAN_THRESHOLD=0.75
# ERS_MIN_REQUESTS=5
# ERS_WINDOW_SECS=3600
```

Raise `ERS_SHADOW_BAN_THRESHOLD` if the shadow-ban rate is unexpectedly high on non-attack traffic:

```bash
docker compose exec warden sh -c 'ERS_SHADOW_BAN_THRESHOLD=0.85 kill -HUP 1'
# or restart the service with updated .env
```

Clear a specific entity's ERS score (false-positive clearance):

```bash
curl -X POST http://localhost:80/ers/reset \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -d "tenant_id=default&ip=<CLIENT_IP>"
```

### High ML_UNCERTAIN rate in Grafana

If the `ML_UNCERTAIN` flag is firing on more than 10% of requests, the MiniLM corpus may need calibration.  Requests with scores in the range `[UNCERTAINTY_LOWER_THRESHOLD, SEMANTIC_THRESHOLD)` are flagged as uncertain.

```bash
# Narrow the uncertainty band (live-tunable)
curl -X POST http://localhost:80/api/config/update \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"uncertainty_lower_threshold": 0.60}'
```

Check the last 100 uncertain requests in Grafana using the `warden_ml_uncertain_total` metric, then review whether the evolved rules in `dynamic_rules.json` have drifted toward the legitimate traffic distribution.  If so, prune the corpus:

```bash
# Wipe the evolved corpus and let the Evolution Engine rebuild from scratch
echo '{"rules": []}' > /warden/data/dynamic_rules.json
docker compose restart warden
```

---

## Operational Golden Rules

### Fail strategy

| Deployment context | Setting | Behaviour |
|-------------------|---------|-----------|
| Financial / regulated | `WARDEN_FAIL_STRATEGY=closed` | Pipeline timeout → request **blocked** |
| High-UX consumer product | `WARDEN_FAIL_STRATEGY=open` | Pipeline timeout → request **passes through** |

Default is `open`.  Change at runtime requires a container restart:

```bash
docker compose exec warden sh -c 'echo WARDEN_FAIL_STRATEGY=closed >> /etc/environment'
docker compose restart warden
```

### Model and corpus updates

Never deploy updated CLIP/Whisper weights or a new MiniLM checkpoint directly to production.  Always:

1. Stage the update
2. Run `python scripts/warden_doctor.py --url http://staging:80`
3. Confirm all benchmarks PASS before promoting

### Log retention (GDPR Article 5(1)(e))

Logs must not be retained beyond 30 days.  Automate purge via cron or the compliance endpoint:

```bash
# Cron: daily purge of logs older than 30 days
0 2 * * * curl -s -X POST http://localhost:80/gdpr/purge \
    -H "X-API-Key: $WARDEN_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"before_days": 30}' >> /var/log/warden-purge.log 2>&1
```

Content is **never** stored (GDPR Art. 5(1)(c) data minimisation — enforced in code).  The purge endpoint removes metadata records only.

### Evolution Engine failure (Claude API errors)

If the Anthropic API is unavailable (network outage, quota exhaustion), the Evolution Engine logs errors and stops queuing new rules.  All existing detection continues to work — the engine is fully optional.

Do **not** raise `STRICT_MODE` in response to Evolution Engine errors; that increases the block rate without improving detection accuracy.  The correct response is to monitor and wait for the API to recover, or set `ANTHROPIC_API_KEY=""` to switch to air-gapped mode.

```bash
docker compose logs warden | grep "EvolutionEngine"
# Error lines are informational — they do not affect the request pipeline
```

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `python scripts/warden_doctor.py` | Full diagnostics + benchmark |
| `python scripts/warden_doctor.py --json > r.json` | CI/CD report |
| `GET /health` | Gateway liveness + Redis + circuit state |
| `GET /api/config` | Current live config (thresholds, fail strategy) |
| `POST /api/config/update` | Hot-tune thresholds without restart |
| `GET /compliance/evidence/{id}` | Export signed evidence bundle |
| `POST /compliance/evidence/verify` | Verify bundle hash |
| `POST /gdpr/purge` | Purge logs by age |
| `POST /ers/reset` | Clear ERS score for an entity |
| `DELETE /agents/sessions/{id}` | Kill-switch: revoke agent session |
| `GET /api/compliance/gdpr/ropa` | Art. 30 Record of Processing Activities |

---

*For issues not covered in this document, export an evidence bundle, collect `docker compose logs`, and open an incident with the maintainer via [GitHub Issues](https://github.com/zborrman/Shadow-Warden-AI/issues).*
