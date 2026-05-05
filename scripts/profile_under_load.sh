#!/usr/bin/env bash
# scripts/profile_under_load.sh
#
# Simultaneous k6 load test + py-spy flamegraph for Shadow Warden AI.
#
# Requirements (on the VPS):
#   pip install py-spy        (or: cargo install py-spy)
#   snap install k6  /  apt install k6
#
# Usage:
#   # Basic (defaults: 60s warmup, 500 VU, local target)
#   ./scripts/profile_under_load.sh
#
#   # Point at production
#   WARDEN_URL=https://api.shadow-warden-ai.com \
#   API_KEY=your-key \
#   ./scripts/profile_under_load.sh
#
# Output:
#   results/flamegraph_<timestamp>.svg   — py-spy flamegraph
#   results/k6_<timestamp>.json          — k6 NDJSON metrics

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────────
WARDEN_URL="${WARDEN_URL:-http://localhost:8001}"
API_KEY="${API_KEY:-}"
DURATION="${DURATION:-5m}"
PEAK_VU="${PEAK_VU:-500}"
PYSPY_RATE="${PYSPY_RATE:-100}"      # samples/sec
RESULTS_DIR="${RESULTS_DIR:-results}"

TS=$(date +%Y%m%d_%H%M%S)
FLAMEGRAPH_OUT="${RESULTS_DIR}/flamegraph_${TS}.svg"
K6_OUT="${RESULTS_DIR}/k6_${TS}.json"

mkdir -p "${RESULTS_DIR}"

# ── Resolve warden PID (Docker or local) ───────────────────────────────────────
resolve_warden_pid() {
    local pid

    # Try Docker first
    if command -v docker &>/dev/null; then
        pid=$(docker inspect --format='{{.State.Pid}}' warden-warden 2>/dev/null || true)
        if [[ -n "${pid}" && "${pid}" != "0" ]]; then
            echo "${pid}"
            return
        fi
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
    echo "ERROR: Could not find warden process. Is it running?"
    exit 1
fi

echo "=== Shadow Warden AI — Load Profile ==="
echo "  Warden PID : ${WARDEN_PID}"
echo "  Target URL : ${WARDEN_URL}"
echo "  Duration   : ${DURATION}"
echo "  Peak VUs   : ${PEAK_VU}"
echo "  Flamegraph : ${FLAMEGRAPH_OUT}"
echo "  k6 output  : ${K6_OUT}"
echo

# ── Start py-spy in the background ─────────────────────────────────────────────
echo "[1/3] Starting py-spy recorder (${PYSPY_RATE} Hz) ..."
py-spy record \
    --pid "${WARDEN_PID}" \
    --rate "${PYSPY_RATE}" \
    --format speedscope \
    --output "${FLAMEGRAPH_OUT%.svg}.speedscope.json" \
    --nonblocking \
    &
PYSPY_PID=$!

# Also produce an SVG flamegraph in parallel
py-spy record \
    --pid "${WARDEN_PID}" \
    --rate "${PYSPY_RATE}" \
    --format flamegraph \
    --output "${FLAMEGRAPH_OUT}" \
    --nonblocking \
    &
PYSPY_SVG_PID=$!

# ── Run k6 ─────────────────────────────────────────────────────────────────────
echo "[2/3] Starting k6 load test ..."
K6_ARGS=(
    run
    tests/load/filter_bench.js
    -e "WARDEN_URL=${WARDEN_URL}"
    --out "json=${K6_OUT}"
    --vus "${PEAK_VU}"
    --duration "${DURATION}"
)
if [[ -n "${API_KEY}" ]]; then
    K6_ARGS+=(-e "API_KEY=${API_KEY}")
fi

k6 "${K6_ARGS[@]}"

# ── Stop py-spy ─────────────────────────────────────────────────────────────────
echo "[3/3] Stopping profiler ..."
kill "${PYSPY_PID}"    2>/dev/null || true
kill "${PYSPY_SVG_PID}" 2>/dev/null || true
wait "${PYSPY_PID}"    2>/dev/null || true
wait "${PYSPY_SVG_PID}" 2>/dev/null || true

# ── Summary ─────────────────────────────────────────────────────────────────────
echo
echo "=== Done ==="
if [[ -f "${FLAMEGRAPH_OUT}" ]]; then
    echo "  Flamegraph SVG : ${FLAMEGRAPH_OUT}"
    echo "  Open in browser: file://$(realpath "${FLAMEGRAPH_OUT}")"
fi
SPEEDSCOPE="${FLAMEGRAPH_OUT%.svg}.speedscope.json"
if [[ -f "${SPEEDSCOPE}" ]]; then
    echo "  Speedscope     : ${SPEEDSCOPE}"
    echo "  View online    : https://www.speedscope.app  (drag & drop the JSON)"
fi
echo "  k6 metrics     : ${K6_OUT}"
echo
echo "  To extract P99 from k6 output:"
echo "    jq 'select(.type==\"Point\" and .metric==\"http_req_duration\")' ${K6_OUT} \\"
echo "      | jq -s '[.[].data.value] | sort | .[(length*0.99|floor)]'"
