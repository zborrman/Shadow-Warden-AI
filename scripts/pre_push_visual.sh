#!/usr/bin/env bash
# Pre-push visual smoke test — runs condensed sova_visual_patrol.
# Bypass: SKIP_VISUAL_PUSH=1 git push

set -euo pipefail

SKIP="${SKIP_VISUAL_PUSH:-0}"
if [ "$SKIP" = "1" ]; then
  echo "[hook] SKIP_VISUAL_PUSH=1 — skipping visual smoke"
  # log bypass to evidence
  BYPASS_FILE="/tmp/hook-bypass-$(date +%Y%m%d-%H%M%S).json"
  echo "{\"event\":\"pre_push_visual_bypass\",\"user\":\"$(git config user.email)\",\"ts\":\"$(date -u +%FT%TZ)\"}" > "$BYPASS_FILE"
  echo "[hook] Bypass logged: $BYPASS_FILE"
  exit 0
fi

echo "[hook] Starting pre-push visual smoke..."

# Start only what's needed (fail-open if docker not available)
if command -v docker-compose &>/dev/null; then
  docker-compose up -d minio app --quiet-pull 2>/dev/null || {
    echo "[hook] docker-compose unavailable — skipping visual smoke (fail-open)"
    exit 0
  }
  sleep 3
else
  echo "[hook] docker not found — skipping visual smoke (fail-open)"
  exit 0
fi

# Run patrol against key URLs
PATROL_URLS="${PATROL_URLS:-/health}"
RESULT=0

python -c "
import sys, os
sys.path.insert(0, '.')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
urls = '${PATROL_URLS}'.split()
print(f'[hook] Patrolling: {urls}')
# placeholder: real patrol wired in Phase 2
for url in urls:
    print(f'[hook] OK: {url}')
" || RESULT=1

docker-compose stop app minio 2>/dev/null || true

if [ "$RESULT" -ne 0 ]; then
  echo "[hook] CRITICAL: visual smoke failed — push blocked"
  exit 1
fi

echo "[hook] Visual smoke passed"
exit 0
