#!/usr/bin/env bash
# scripts/profile_under_load.sh
#
# Simultaneous k6 load test + py-spy flamegraph for Shadow Warden AI.
#
# Requirements (on the VPS):
#   pip install py-spy        (or: cargo install py-spy)
#   snap install k6  /  apt install k6
#   # Optional MinIO upload:
#   mc alias set warden http://localhost:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
#
# Usage:
#   # Basic (local, all scenarios from k6/load_test.js)
#   ./scripts/profile_under_load.sh
#
#   # Specific scenario + production target
#   WARDEN_URL=https://api.shadow-warden-ai.com \
#   WARDEN_API_KEY=your-key \
#   SCENARIO=baseline \
#   ./scripts/profile_under_load.sh
#
# Environment:
#   WARDEN_URL      Target URL          (default: http://localhost:8001)
#   WARDEN_API_KEY  API key             (default: empty — auth disabled)
#   SCENARIO        k6 scenario to run  (default: all | baseline | ramp | spike | soak)
#   PYSPY_RATE      py-spy sample rate  (default: 100 Hz)
#   RESULTS_DIR     Output directory    (default: results/)
#   MINIO_BUCKET    MinIO bucket        (default: warden-evidence)
#   MINIO_ALIAS     mc alias name       (default: warden)
#
# Output:
#   results/flamegraph_<timestamp>.svg          — py-spy SVG flamegraph
#   results/flamegraph_<timestamp>.speedscope   — Speedscope JSON
#   results/k6_<timestamp>.json                 — k6 NDJSON metrics
#   MinIO warden-evidence/profiles/<ts>/        — uploaded when mc is available

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────────
WARDEN_URL="${WARDEN_URL:-http://localhost:8001}"
WARDEN_API_KEY="${WARDEN_API_KEY:-}"
SCENARIO="${SCENARIO:-all}"          # all | baseline | ramp | spike | soak
PYSPY_RATE="${PYSPY_RATE:-100}"      # samples/sec
RESULTS_DIR="${RESULTS_DIR:-results}"
MINIO_BUCKET="${MINIO_BUCKET:-warden-evidence}"
MINIO_ALIAS="${MINIO_ALIAS:-warden}"

# Locate k6 script relative to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
K6_SCRIPT="${REPO_ROOT}/k6/load_test.js"

if [[ ! -f "${K6_SCRIPT}" ]]; then
    echo "ERROR: k6 script not found at ${K6_SCRIPT}"
    exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
FLAMEGRAPH_SVG="${RESULTS_DIR}/flamegraph_${TS}.svg"
FLAMEGRAPH_SS="${RESULTS_DIR}/flamegraph_${TS}.speedscope.json"
K6_OUT="${RESULTS_DIR}/k6_${TS}.json"
K6_SUMMARY="${RESULTS_DIR}/k6_${TS}_summary.json"

mkdir -p "${RESULTS_DIR}"

# ── Resolve warden PID (Docker or local) ───────────────────────────────────────
resolve_warden_pid() {
    local pid

    # Try Docker first (compose container name is <project>-warden-1 or warden-warden)
    if command -v docker &>/dev/null; then
        for cname in "shadow-warden-warden-1" "warden-warden"; do
            pid=$(docker inspect --format='{{.State.Pid}}' "${cname}" 2>/dev/null || true)
            if [[ -n "${pid}" && "${pid}" != "0" ]]; then
                echo "${pid}"
                return
            fi
        done
    fi

    # Fall back to local process lookup
    pid=$(pgrep -f "uvicorn warden.main" | head -1 || true)
    if [[ -n "${pid}" ]]; then
        echo "${pid}"
        return
    fi

    echo ""
}

WARDEN_PID=$(resolve_warden_pid)

if [[ -z "${WARDEN_PID}" ]]; then
    echo "ERROR: Could not find warden process (Docker or uvicorn). Is it running?"
    exit 1
fi

echo "=== Shadow Warden AI — Load Profile ==="
echo "  Warden PID : ${WARDEN_PID}"
echo "  Target URL : ${WARDEN_URL}"
echo "  Scenario   : ${SCENARIO}"
echo "  py-spy Hz  : ${PYSPY_RATE}"
echo "  Flamegraph : ${FLAMEGRAPH_SVG}"
echo "  k6 output  : ${K6_OUT}"
echo

# ── Start py-spy in the background ─────────────────────────────────────────────
echo "[1/4] Starting py-spy recorder (${PYSPY_RATE} Hz) ..."

py-spy record \
    --pid "${WARDEN_PID}" \
    --rate "${PYSPY_RATE}" \
    --format speedscope \
    --output "${FLAMEGRAPH_SS}" \
    --nonblocking \
    &
PYSPY_SS_PID=$!

py-spy record \
    --pid "${WARDEN_PID}" \
    --rate "${PYSPY_RATE}" \
    --format flamegraph \
    --output "${FLAMEGRAPH_SVG}" \
    --nonblocking \
    &
PYSPY_SVG_PID=$!

# ── Run k6 ─────────────────────────────────────────────────────────────────────
echo "[2/4] Running k6 (scenario=${SCENARIO}) ..."
K6_ARGS=(
    run
    "${K6_SCRIPT}"
    -e "BASE_URL=${WARDEN_URL}"
    -e "SCENARIO=${SCENARIO}"
    --out "json=${K6_OUT}"
    --summary-export="${K6_SUMMARY}"
)
if [[ -n "${WARDEN_API_KEY}" ]]; then
    K6_ARGS+=(-e "WARDEN_API_KEY=${WARDEN_API_KEY}")
fi

k6 "${K6_ARGS[@]}"

# ── Stop py-spy ─────────────────────────────────────────────────────────────────
echo "[3/4] Stopping profiler ..."
kill "${PYSPY_SS_PID}"  2>/dev/null || true
kill "${PYSPY_SVG_PID}" 2>/dev/null || true
wait "${PYSPY_SS_PID}"  2>/dev/null || true
wait "${PYSPY_SVG_PID}" 2>/dev/null || true

# ── Upload to MinIO ─────────────────────────────────────────────────────────────
echo "[4/4] Uploading results to MinIO ..."
if command -v mc &>/dev/null && mc alias ls "${MINIO_ALIAS}" &>/dev/null 2>&1; then
    MINIO_PREFIX="${MINIO_ALIAS}/${MINIO_BUCKET}/profiles/${TS}"
    mc cp "${FLAMEGRAPH_SVG}"  "${MINIO_PREFIX}/flamegraph.svg"  2>/dev/null && \
        echo "  Uploaded flamegraph.svg"        || echo "  WARNING: flamegraph upload failed"
    mc cp "${FLAMEGRAPH_SS}"   "${MINIO_PREFIX}/flamegraph.speedscope.json" 2>/dev/null && \
        echo "  Uploaded flamegraph.speedscope.json" || true
    mc cp "${K6_OUT}"          "${MINIO_PREFIX}/k6_metrics.json" 2>/dev/null && \
        echo "  Uploaded k6_metrics.json"        || echo "  WARNING: k6 metrics upload failed"
    mc cp "${K6_SUMMARY}"      "${MINIO_PREFIX}/k6_summary.json" 2>/dev/null && \
        echo "  Uploaded k6_summary.json"        || true
    echo "  MinIO path: ${MINIO_BUCKET}/profiles/${TS}/"
else
    echo "  mc not configured — skipping MinIO upload (set MINIO_ALIAS or run: mc alias set warden ...)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────────
echo
echo "=== Done ==="
[[ -f "${FLAMEGRAPH_SVG}" ]] && echo "  Flamegraph SVG : ${FLAMEGRAPH_SVG}"
[[ -f "${FLAMEGRAPH_SS}"  ]] && echo "  Speedscope     : ${FLAMEGRAPH_SS}"
[[ -f "${K6_OUT}"         ]] && echo "  k6 metrics     : ${K6_OUT}"
[[ -f "${K6_SUMMARY}"     ]] && echo "  k6 summary     : ${K6_SUMMARY}"
echo
echo "  View flamegraph : open ${FLAMEGRAPH_SVG}"
echo "  View speedscope : drag ${FLAMEGRAPH_SS} to https://www.speedscope.app"
echo
echo "  Extract P99 latency from k6 output:"
echo "    jq 'select(.type==\"Point\" and .metric==\"http_req_duration\")' ${K6_OUT} \\"
echo "      | jq -s '[.[].data.value] | sort | .[(length*0.99|floor)]'"
