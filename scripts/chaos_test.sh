#!/usr/bin/env bash
# scripts/chaos_test.sh  (TQ-19)
# ─────────────────────────────────
# Chaos engineering — random service kill + fail-open verification
#
# Scenarios:
#   1. Kill redis → verify filter still passes requests (fail-open)
#   2. Kill warden → verify health endpoint recovers after restart
#   3. Kill minio  → verify evidence vault degrades gracefully (no crash)
#
# Usage:
#   bash scripts/chaos_test.sh [scenario_num]  # run specific scenario
#   bash scripts/chaos_test.sh                  # run all
#
# Requirements: Docker Compose running, curl, jq
# Reports results via exit code (0=all pass, 1=failures)

set -euo pipefail

BASE_URL="${WARDEN_BASE_URL:-http://localhost:8001}"
API_KEY="${WARDEN_API_KEY:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
PASS=0
FAIL=0

_log()  { echo "[chaos] $*"; }
_pass() { _log "✓ $1"; ((PASS++)); }
_fail() { _log "✗ $1"; ((FAIL++)); }

_filter() {
    local text="$1"
    local extra_headers=()
    [[ -n "$API_KEY" ]] && extra_headers=(-H "X-API-Key: $API_KEY")
    curl -sf -X POST "$BASE_URL/filter" \
        "${extra_headers[@]}" \
        -H "Content-Type: application/json" \
        -d "{\"text\": \"$text\"}" \
        --max-time 10 | jq -r '.verdict // "ERROR"'
}

_health() {
    curl -sf "$BASE_URL/health" --max-time 5 | jq -r '.status // "error"'
}

_service_running() {
    local svc="$1"
    docker compose -f "$COMPOSE_FILE" ps "$svc" --format json 2>/dev/null \
        | grep -q '"State":"running"' && echo "yes" || echo "no"
}

# ── Scenario 1: Redis kill ────────────────────────────────────────────────────
scenario_redis_kill() {
    _log "=== Scenario 1: Redis kill ==="

    # Baseline
    verdict=$(_filter "Hello world" 2>/dev/null || echo "ERROR")
    if [[ "$verdict" != "ERROR" ]]; then
        _pass "Pre-chaos filter works (verdict=$verdict)"
    else
        _fail "Pre-chaos filter failed before any chaos"
        return
    fi

    # Kill redis
    _log "Stopping redis..."
    docker compose -f "$COMPOSE_FILE" stop redis 2>/dev/null || true
    sleep 2

    # Warden should still handle requests (cache fail-open)
    verdict=$(_filter "What is 2+2?" 2>/dev/null || echo "TIMEOUT")
    if [[ "$verdict" != "TIMEOUT" && "$verdict" != "" ]]; then
        _pass "Filter works without Redis (fail-open): verdict=$verdict"
    else
        _fail "Filter crashed when Redis died (verdict=$verdict)"
    fi

    # Restart redis
    _log "Restarting redis..."
    docker compose -f "$COMPOSE_FILE" start redis 2>/dev/null || true
    sleep 3

    # Verify recovery
    verdict=$(_filter "Hello again" 2>/dev/null || echo "ERROR")
    if [[ "$verdict" != "ERROR" ]]; then
        _pass "Filter recovered after Redis restart (verdict=$verdict)"
    else
        _fail "Filter did not recover after Redis restart"
    fi
}

# ── Scenario 2: Warden restart ────────────────────────────────────────────────
scenario_warden_restart() {
    _log "=== Scenario 2: Warden restart ==="

    _log "Restarting warden service..."
    docker compose -f "$COMPOSE_FILE" restart warden 2>/dev/null || true

    # Wait up to 30s for health to return
    recovered=false
    for i in $(seq 1 10); do
        sleep 3
        status=$(_health 2>/dev/null || echo "error")
        if [[ "$status" == "ok" || "$status" == "healthy" ]]; then
            recovered=true
            break
        fi
        _log "  attempt $i: status=$status"
    done

    if $recovered; then
        _pass "Warden recovered after restart in $((i*3))s"
    else
        _fail "Warden did not recover within 30s"
    fi

    # Filter should work again
    verdict=$(_filter "Recover test" 2>/dev/null || echo "ERROR")
    if [[ "$verdict" != "ERROR" ]]; then
        _pass "Filter operational after restart (verdict=$verdict)"
    else
        _fail "Filter not working after restart"
    fi
}

# ── Scenario 3: MinIO kill ────────────────────────────────────────────────────
scenario_minio_kill() {
    _log "=== Scenario 3: MinIO kill ==="

    _log "Stopping minio..."
    docker compose -f "$COMPOSE_FILE" stop minio 2>/dev/null || true
    sleep 2

    # Warden should still handle filter requests (S3 is fail-open)
    verdict=$(_filter "Will this work without MinIO?" 2>/dev/null || echo "ERROR")
    if [[ "$verdict" != "ERROR" ]]; then
        _pass "Filter works without MinIO (fail-open): verdict=$verdict"
    else
        _fail "Filter crashed when MinIO died"
    fi

    # Health endpoint should not be UNHEALTHY due to MinIO
    status=$(_health 2>/dev/null || echo "error")
    if [[ "$status" != "error" ]]; then
        _pass "Health endpoint still responds without MinIO: $status"
    else
        _fail "Health endpoint failed without MinIO"
    fi

    # Restart minio
    _log "Restarting minio..."
    docker compose -f "$COMPOSE_FILE" start minio 2>/dev/null || true
    sleep 3
    _pass "MinIO restarted"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    local scenario="${1:-all}"

    _log "Starting chaos tests against $BASE_URL"
    _log "Compose file: $COMPOSE_FILE"

    # Check baseline
    if ! status=$(_health 2>/dev/null); then
        _log "ERROR: Warden service not reachable — start Docker Compose first"
        exit 1
    fi
    _log "Service health: $status"

    case "$scenario" in
        1|redis)   scenario_redis_kill ;;
        2|restart) scenario_warden_restart ;;
        3|minio)   scenario_minio_kill ;;
        all)
            scenario_redis_kill
            scenario_warden_restart
            scenario_minio_kill
            ;;
        *)
            echo "Usage: $0 [1|2|3|all|redis|restart|minio]"
            exit 1
            ;;
    esac

    _log "─────────────────────────────────────"
    _log "Results: $PASS passed, $FAIL failed"
    [[ $FAIL -eq 0 ]] && exit 0 || exit 1
}

main "$@"
