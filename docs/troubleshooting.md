# Shadow Warden AI — Troubleshooting Guide

**Version:** 5.6 · **Audience:** Operators, DevSecOps, platform engineers

---

## How to use this guide

Each entry follows the same structure:

- **Symptom** — what you see (log line, HTTP code, UI message)
- **Cause** — why it happens
- **Fix** — concrete steps to resolve it
- **See also** — links to related documentation

---

## 1. Tunnel creation fails — preflight check error

**Symptom:**
```
POST /sovereign/tunnels → 503 Service Unavailable
{"detail": {"message": "Preflight check failed", "failed_services": ["minio"], ...}}
```

**Cause:**
Before registering a MASQUE tunnel, Shadow Warden verifies that MinIO, Redis, and
the internal Warden API are reachable from within the target jurisdiction. If any of
these dependencies is down, the tunnel is not created.

**Fix:**

| Failed service | Check | Fix |
|----------------|-------|-----|
| `minio` | `curl $MINIO_ENDPOINT/minio/health/live` | Start MinIO or fix `MINIO_ENDPOINT` |
| `warden_api` | `curl $WARDEN_INTERNAL_URL/health` | Ensure warden container is running |
| `redis` | `redis-cli -u $REDIS_URL ping` | Start Redis or fix `REDIS_URL` |

Emergency bypass (use only during planned maintenance):
```bash
curl -X POST .../sovereign/tunnels \
  -d '{"label":"...", "jurisdiction":"EU", "protocol":"MASQUE_H3", "skip_preflight": true}'
```

**See also:** [deployment-guide.md — Troubleshooting: Preflight Checks](deployment-guide.md#troubleshooting-preflight-checks)

---

## 2. RPC node unreachable — escrow deployment fails

**Symptom:**
```
POST /marketplace/escrow → 502 Bad Gateway
{"detail": {"message": "Blockchain network unavailable", "detail": "..."}}
```

**Cause:**
When a marketplace escrow contract is deployed to a real blockchain (Sepolia,
Polygon Amoy, Arbitrum Sepolia), Shadow Warden probes the configured RPC node
with up to 3 attempts (2 s → 4 s → 8 s back-off). If all attempts fail,
`EscrowDeploymentError` is raised and the API returns 502.

**Fix:**
1. Check which chain you are targeting: `chain` field in the request body.
2. Verify the RPC URL in `warden/web3/chains.py` or the corresponding env var:
   - Sepolia: `SEPOLIA_RPC_URL`
   - Polygon Amoy: `POLYGON_AMOY_RPC_URL`
   - Arbitrum Sepolia: `ARBITRUM_SEPOLIA_RPC_URL`
3. Test connectivity:
   ```bash
   curl -s -X POST $SEPOLIA_RPC_URL \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
   ```
4. If you do not need on-chain deployment, leave `rpc_url` empty in the chain
   config — Shadow Warden automatically falls back to simulation mode (SQLite
   tracking, no gas cost).

**See also:** [deployment-guide.md — RPC node validation for escrow](deployment-guide.md#rpc-node-validation-for-escrow)

---

## 3. Escrow stuck in "funded" state

**Symptom:**
An escrow remains in `funded` status indefinitely. The buyer has paid but no
asset has been delivered.

**Cause:**
The seller's AI agent has not called `POST /marketplace/escrow/{id}/deliver`
with the `asset_hash` of the delivered asset.

**Fix:**
1. Check the seller agent's logs:
   ```bash
   # SOVA tool: get escrow state
   # POST /agent/sova  {"message": "what is the status of escrow ESC-001?"}
   curl -s https://api.shadow-warden-ai.com/marketplace/escrow/ESC-001 \
     -H "X-API-Key: $WARDEN_API_KEY"
   ```
2. If `status` is `funded` and `delivered_at` is null, the seller did not
   call `/deliver`. Trigger it manually:
   ```bash
   curl -s -X POST .../marketplace/escrow/ESC-001/deliver \
     -H "Content-Type: application/json" \
     -d '{"asset_hash": "sha256:<hex>"}'
   ```
3. After 48 h (configurable via `ESCROW_DELIVERY_TIMEOUT_HOURS`), the escrow
   can be cancelled and funds refunded to the buyer.

**See also:** [marketplace-guide.md](marketplace-guide.md)

---

## 4. Compliance score not updating

**Symptom:**
The compliance posture score on the Portal or SOC Dashboard does not change
even after remediating a gap.

**Cause — stale cache:**
`GET /compliance/posture` caches results in Redis for 300 s (configurable via
`COMPLIANCE_CACHE_TTL`). Changes to underlying controls (e.g. MFA enabled) will
not be reflected until the cache expires or is explicitly invalidated.

**Cause — broken WebSocket:**
The Portal's real-time score ring uses `WebSocket /compliance/ws`. If the
connection is dropped, the displayed score freezes.

**Fix:**
1. Force a recompute:
   ```bash
   curl -s -X POST https://api.shadow-warden-ai.com/compliance/posture/recalculate \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "X-Tenant-Tier: pro"
   ```
2. Reload the Portal page to re-establish the WebSocket connection.
3. Check Redis is running — if Redis is unavailable the cache layer is skipped
   and scores recompute on every request (slower, but still correct).

**See also:** [compliance-guide.md](compliance-guide.md)

---

## 5. Document scan returns 413 Request Entity Too Large

**Symptom:**
```
POST /document-intel/convert → 413 Request Entity Too Large
{"detail": "File too large: 67.3 MB > 50 MB limit"}
```

**Cause:**
The base64-encoded file exceeds `DOC_INTEL_MAX_BYTES` (default 50 MB).

**Fix:**
- Split the document and scan each part separately.
- For large PDFs, extract only the relevant pages before uploading.
- Increase the limit for your deployment (not recommended for shared tenants):
  ```bash
  # .env
  DOC_INTEL_MAX_BYTES=104857600   # 100 MB
  ```
- If the file is an audio recording, consider transcribing with a lighter tool
  first and filtering the transcript text.

**See also:** [api-reference.md — Document Intelligence](api-reference.md#document-intelligence-document-intel)

---

## 6. Sybil flag triggered — agent blocked

**Symptom:**
An AI agent receives `403 Forbidden` or its listings/purchases are silently
dropped. SOVA reports `sybil_risk: HIGH` in the Trust Graph.

**Cause:**
`SybilGuard` monitors agents for patterns associated with fake-identity abuse:
- Creating many low-value listings rapidly
- Purchasing own assets (wash trading)
- Reputation score manipulation (rapid self-rating cycles)

When Sybil risk exceeds the threshold, the agent is soft-blocked: existing
operations continue but new purchases and listings are rejected.

**Fix:**
1. Review the Trust Graph in Streamlit analytics → **Marketplace Admin** tab.
2. Check the agent's recent activity:
   ```bash
   curl "https://api.shadow-warden-ai.com/marketplace/agents/did:shadow:.../trust" \
     -H "X-API-Key: $WARDEN_API_KEY"
   ```
3. If the flag was triggered by legitimate bulk activity (e.g. batch asset
   upload), contact support to reset the Sybil counter manually.
4. Legitimate agents auto-recover after the sliding window (default 24 h)
   clears suspicious events.

**See also:** [security-model.md — Trust Graph & Sybil Guard](security-model.md)

---

## 7. DAO proposal expired

**Symptom:**
Voting on a governance proposal fails with:
```
{"detail": "Proposal PROP-001 is closed (expired at 2026-06-14T10:00:00Z)"}
```

**Cause:**
DAO governance proposals have a 72-hour voting window (configurable via
`GOVERNANCE_PROPOSAL_TTL_HOURS`). Once expired, no further votes are accepted
and the proposal status is set to `closed`.

**Fix:**
1. Create a new proposal:
   ```bash
   curl -s -X POST https://api.shadow-warden-ai.com/marketplace/governance/proposals \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "community_id": "comm_01JXYZ",
       "title":        "Increase monthly request quota",
       "description":  "...",
       "proposal_type": "PARAMETER_CHANGE",
       "proposed_value": {"monthly_requests": 20000}
     }'
   ```
2. If the proposal repeatedly fails to reach quorum before expiry, consider
   lowering `GOVERNANCE_QUORUM_PCT` (default 51%) or extending the TTL.

**See also:** [marketplace-guide.md — DAO Governance](marketplace-guide.md)

---

## 8. Auth errors — 401 / 403

| Error | Cause | Fix |
|-------|-------|-----|
| `401 Unauthorized` | Missing or invalid `X-API-Key` | Generate a key in Portal → Settings → API Keys |
| `403 Forbidden — tier too low` | Feature requires a higher plan | Upgrade plan or purchase the add-on |
| `402 Payment Required` | Feature requires a purchased add-on | Buy the add-on at Portal → Billing |
| `403 — ALLOW_UNAUTHENTICATED=false` | No key configured at all | Set `WARDEN_API_KEY` in `.env` or `ALLOW_UNAUTHENTICATED=true` for dev |

---

## 9. Evolution Engine not generating new rules

**Symptom:**
BLOCK events are logged but no new detection rules appear after 10+ minutes.

**Cause:**
- `ANTHROPIC_API_KEY` is empty → Evolution Engine runs in air-gapped mode (detection works, rule synthesis disabled).
- Claude API rate limit or quota exceeded.
- Evolution regex gate rejected the generated rule (ReDoS check failed).

**Fix:**
1. Confirm `ANTHROPIC_API_KEY` is set:
   ```bash
   kubectl exec -n shadow-warden deploy/shadow-warden-warden -- env | grep ANTHROPIC
   ```
2. Check evolution logs:
   ```bash
   kubectl logs -n shadow-warden deploy/shadow-warden-warden | grep -i "evolution\|opus"
   ```
3. If logs show `regex gate rejected`, the generated regex is unsafe. This is
   intentional — the gate prevents ReDoS. The engine will retry on the next BLOCK event.

---

## 10. Redis connection errors — rate limiting broken

**Symptom:**
All requests succeed regardless of rate limit, or Redis errors appear in logs:
`ConnectionError: Error 111 connecting to localhost:6379`.

**Cause:**
Redis is unavailable or `REDIS_URL` points to the wrong host.

**Fix:**
1. Docker Compose: `docker compose logs redis` — check for OOM or startup failure.
2. Kubernetes: `kubectl get pod -l app=redis -n shadow-warden`
3. Warden falls back to **in-process rate limiting** per worker when Redis is
   unavailable — limits are per-pod, not shared across replicas. This is
   intentional fail-open behaviour to avoid service interruption.
4. Set `REDIS_URL=memory://` in tests/local dev to skip Redis entirely.

---

## 11. Model not loading — MiniLM / ONNX startup failure

**Symptom:**
Warden starts but `/filter` returns 500 with `model not loaded` in logs.

**Cause:**
The MiniLM ONNX model has not been exported to the `warden-models` Docker volume.

**Fix:**
```bash
# Export ONNX model (runs once, writes to named volume)
docker run --rm \
  --name warden-onnx-export \
  -v warden-models:/warden/models \
  shadow-warden-ai-warden:latest \
  python3 warden/brain/export_onnx.py

# Then restart
docker compose restart warden
```

CI uses a pre-built cache at `/tmp/warden-model-cache` — see `.github/workflows/ci.yml`.

---

## Quick-reference: log locations

| Component | Log location |
|-----------|-------------|
| Filter events | `LOGS_PATH` (default `/warden/data/logs.json`) |
| Evolution Engine | stdout → Docker / pod logs |
| MinIO evidence | `warden-evidence/bundles/<session_id>.json` |
| MinIO filter logs | `warden-logs/logs/<date>/<request_id>.json` |
| STIX audit chain | SQLite `sep_stix_chain` table in `SEP_DB_PATH` |
| Prometheus metrics | `GET /metrics` (text format) |
| Jaeger traces | `http://your-host:16686` (requires `OTEL_ENABLED=true`) |
