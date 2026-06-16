#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Pre-deploy Verification Script
#
#  Run before every production deploy to verify all components build and
#  all tests pass. Exits non-zero on any failure.
#
#  Usage:
#    bash scripts/pre_deploy_check.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✔${NC}  $*"; }
fail() { echo -e "${RED}✘${NC}  $*"; exit 1; }
step() { echo -e "\n${YELLOW}▶  $*${NC}"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

step "1. Python unit tests (fast, not adversarial)"
ALLOW_UNAUTHENTICATED=true \
WARDEN_API_KEY="" \
ANTHROPIC_API_KEY="" \
REDIS_URL="memory://" \
LOGS_PATH="/tmp/predeploy_logs.json" \
DYNAMIC_RULES_PATH="/tmp/predeploy_rules.json" \
MODEL_CACHE_DIR="/tmp/warden-model-cache" \
SEMANTIC_THRESHOLD="0.72" \
AUDIT_TRAIL_PATH="/tmp/predeploy_audit.db" \
  pytest warden/tests/ -v --tb=short -m "not adversarial and not slow" -q \
  || fail "Python tests failed"
ok "Python tests passed"

step "2. Coverage gate (≥80%)"
ALLOW_UNAUTHENTICATED=true \
WARDEN_API_KEY="" \
ANTHROPIC_API_KEY="" \
REDIS_URL="memory://" \
LOGS_PATH="/tmp/predeploy_cov_logs.json" \
DYNAMIC_RULES_PATH="/tmp/predeploy_cov_rules.json" \
MODEL_CACHE_DIR="/tmp/warden-model-cache" \
SEMANTIC_THRESHOLD="0.72" \
AUDIT_TRAIL_PATH="/tmp/predeploy_cov_audit.db" \
  pytest warden/tests/ --tb=short -m "not adversarial" \
  --cov=warden --cov-fail-under=80 -q \
  || fail "Coverage below 80%"
ok "Coverage gate passed"

step "3. Linting (ruff)"
ruff check warden/ analytics/ --ignore E501 \
  || fail "Ruff linting failed"
ok "Ruff clean"

step "4. Production readiness smoke tests"
ALLOW_UNAUTHENTICATED=true \
WARDEN_API_KEY="" \
ANTHROPIC_API_KEY="" \
REDIS_URL="memory://" \
LOGS_PATH="/tmp/predeploy_prod_logs.json" \
DYNAMIC_RULES_PATH="/tmp/predeploy_prod_rules.json" \
MODEL_CACHE_DIR="/tmp/warden-model-cache" \
SEMANTIC_THRESHOLD="0.72" \
AUDIT_TRAIL_PATH="/tmp/predeploy_prod_audit.db" \
WAT_SIMULATE=true \
USDC_SIMULATE=true \
S3_ENABLED=false \
  pytest warden/tests/test_production_readiness.py -v --tb=short \
  || fail "Production readiness tests failed"
ok "Production readiness smoke tests passed"

step "5. Portal build (Next.js)"
if [ -d portal ]; then
  ( cd portal && npm ci --prefer-offline --no-audit --no-fund --silent && npm run build ) \
    || fail "Portal build failed"
  ok "Portal built"
else
  echo "  portal/ not found — skipping"
fi

step "6. Dashboard build (Next.js)"
if [ -d dashboard ]; then
  ( cd dashboard && npm ci --prefer-offline --no-audit --no-fund --silent && npm run build ) \
    || fail "Dashboard build failed"
  ok "Dashboard built"
else
  echo "  dashboard/ not found — skipping"
fi

step "7. Astro site build"
if [ -d site ]; then
  ( cd site && npm ci --prefer-offline --no-audit --no-fund --silent && npm run build ) \
    || fail "Astro site build failed"
  ok "Astro site built"
else
  echo "  site/ not found — skipping"
fi

step "8. Docker compose config validation"
docker compose config --quiet \
  || fail "docker-compose.yml has syntax errors"
ok "Docker Compose config valid"

echo -e "\n${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  All pre-deploy checks passed ✔${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}\n"
