#!/usr/bin/env bash
# scripts/canary_deploy.sh  (SC-05)
# ─────────────────────────────────────────────────────────────────────────────
# Zero-downtime canary deploy via Helm.
# Stages: 10% → 50% → 100% traffic weight.
# Rolls back automatically if error rate > 1% at any stage.
#
# Usage:
#   ./scripts/canary_deploy.sh <chart-version> [--namespace <ns>]
#
# Requirements: helm, kubectl, curl (for Prometheus query)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CHART_VERSION="${1:-}"
NAMESPACE="${NAMESPACE:-shadow-warden}"
RELEASE="shadow-warden"
CHART_PATH="charts/shadow-warden"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
ERROR_THRESHOLD="0.01"   # 1%
CANARY_WAIT="${CANARY_WAIT:-60}"  # seconds per stage

if [[ -z "$CHART_VERSION" ]]; then
  echo "Usage: $0 <chart-version>" >&2
  exit 1
fi

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

# ── Check error rate via Prometheus ───────────────────────────────────────────
check_error_rate() {
  local rate
  rate=$(curl -sf "${PROMETHEUS_URL}/api/v1/query" \
    --data-urlencode "query=rate(warden_http_errors_total[2m]) / rate(warden_http_requests_total[2m])" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['result'][0]['value'][1] if d['data']['result'] else '0')" 2>/dev/null || echo "0")
  log "Current error rate: ${rate}"
  python3 -c "import sys; sys.exit(0 if float('${rate}') <= ${ERROR_THRESHOLD} else 1)"
}

rollback() {
  log "Rolling back to previous release..."
  helm rollback "${RELEASE}" --namespace "${NAMESPACE}" --wait
  log "Rollback complete."
  exit 1
}

# ── Deploy canary (10%) ───────────────────────────────────────────────────────
log "Stage 1/3: Deploying canary at 10% weight (version ${CHART_VERSION})"
helm upgrade "${RELEASE}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --version "${CHART_VERSION}" \
  --set warden.replicas=1 \
  --set canary.enabled=true \
  --set canary.weight=10 \
  --wait --timeout 5m \
  || rollback

log "Waiting ${CANARY_WAIT}s to observe canary..."
sleep "${CANARY_WAIT}"
check_error_rate || { log "Error rate exceeded at 10% — rolling back"; rollback; }

# ── Scale to 50% ──────────────────────────────────────────────────────────────
log "Stage 2/3: Scaling canary to 50%"
helm upgrade "${RELEASE}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --version "${CHART_VERSION}" \
  --reuse-values \
  --set canary.weight=50 \
  --wait --timeout 5m \
  || rollback

sleep "${CANARY_WAIT}"
check_error_rate || { log "Error rate exceeded at 50% — rolling back"; rollback; }

# ── Full rollout (100%) ───────────────────────────────────────────────────────
log "Stage 3/3: Full rollout (100%)"
helm upgrade "${RELEASE}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --version "${CHART_VERSION}" \
  --reuse-values \
  --set canary.enabled=false \
  --set warden.replicas=3 \
  --atomic --timeout 10m \
  || rollback

log "Canary deploy complete. Version ${CHART_VERSION} is live."
