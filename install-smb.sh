#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — Community Business Edition
# One-click installer for Linux / macOS / WSL
#
# Usage:
#   curl -sSL https://get.shadow-warden-ai.com/smb | bash
#   — or —
#   bash install-smb.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo -e "${BOLD}🛡️  Shadow Warden AI — Community Business Edition${NC}"
echo -e "    One-click security gateway for small & medium businesses"
echo -e "    Version 4.7  |  https://shadow-warden-ai.com"
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────────────

info "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Install from https://docs.docker.com/get-docker/"
fi

DOCKER_VERSION=$(docker --version | grep -oP '\d+\.\d+' | head -1)
info "Docker $DOCKER_VERSION found."

if ! docker compose version &>/dev/null 2>&1; then
    error "Docker Compose V2 not found. Update Docker Desktop or install docker-compose-plugin."
fi

success "All prerequisites met."

# ── Installation directory ────────────────────────────────────────────────────

INSTALL_DIR="${SHADOW_WARDEN_DIR:-$HOME/.shadow-warden-smb}"
info "Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# ── Generate secrets ──────────────────────────────────────────────────────────

gen_key() { python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null \
            || openssl rand -base64 32 | tr -d '=\n'; }

WARDEN_API_KEY=$(gen_key)
VAULT_MASTER_KEY=$(gen_key)
COMMUNITY_VAULT_KEY=$(gen_key)

# ── Write .env.smb ────────────────────────────────────────────────────────────

if [[ -f ".env.smb" ]]; then
    warn ".env.smb already exists — skipping key generation (keeping existing config)."
else
    info "Generating .env.smb with secure random keys..."
    cat > .env.smb <<EOF
# Shadow Warden AI — Community Business
# Auto-generated $(date -u +"%Y-%m-%d %H:%M UTC")
# DO NOT commit this file to version control.

WARDEN_API_KEY=${WARDEN_API_KEY}
VAULT_MASTER_KEY=${VAULT_MASTER_KEY}
COMMUNITY_VAULT_KEY=${COMMUNITY_VAULT_KEY}

WARDEN_TIER=community_business
TENANT_ID=my-business

# Optional: Anthropic key enables AI auto-evolution (leave blank for air-gapped mode)
ANTHROPIC_API_KEY=

# Optional: Slack webhook for HIGH/BLOCK alerts
SLACK_WEBHOOK_URL=

FILE_SCAN_ENABLED=true
FILE_SCAN_MAX_MB=10
SHADOW_AI_MONITOR=true
RETENTION_DAYS=180
EOF
    success ".env.smb created."
fi

# ── Download docker-compose.smb.yml if not present ────────────────────────────

if [[ ! -f "docker-compose.smb.yml" ]]; then
    info "Downloading docker-compose.smb.yml..."
    if command -v curl &>/dev/null; then
        curl -sSL "https://raw.githubusercontent.com/shadow-warden-ai/warden/main/docker-compose.smb.yml" \
             -o docker-compose.smb.yml 2>/dev/null \
        || cp "$(dirname "$0")/docker-compose.smb.yml" . 2>/dev/null \
        || error "Could not download docker-compose.smb.yml"
    else
        cp "$(dirname "$0")/docker-compose.smb.yml" . \
        || error "Could not find docker-compose.smb.yml"
    fi
    success "docker-compose.smb.yml ready."
fi

# ── Pull images ───────────────────────────────────────────────────────────────

info "Pulling Docker images (this may take 2-3 minutes on first run)..."
docker compose -f docker-compose.smb.yml pull --quiet 2>/dev/null || true

# ── Start services ────────────────────────────────────────────────────────────

info "Starting Shadow Warden AI (Community Business)..."
docker compose -f docker-compose.smb.yml up -d --remove-orphans

# ── Wait for health ───────────────────────────────────────────────────────────

info "Waiting for warden to be healthy..."
MAX_WAIT=60; elapsed=0
while [[ $elapsed -lt $MAX_WAIT ]]; do
    if curl -sf http://localhost:8001/health &>/dev/null; then
        break
    fi
    sleep 3; elapsed=$((elapsed + 3))
    echo -n "."
done
echo ""

if ! curl -sf http://localhost:8001/health &>/dev/null; then
    warn "Warden not responding yet — it may still be loading the AI model."
    warn "Check status: docker compose -f $INSTALL_DIR/docker-compose.smb.yml ps"
else
    success "Shadow Warden AI is running!"
fi

# ── Print summary ─────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅  Shadow Warden AI — Community Business ACTIVE${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}API Gateway:${NC}   http://localhost:8001"
echo -e "  ${BOLD}Dashboard:${NC}     http://localhost:8501"
echo -e "  ${BOLD}Health check:${NC}  http://localhost:8001/health"
echo -e "  ${BOLD}File Scanner:${NC}  POST http://localhost:8001/filter/file"
echo ""
echo -e "  ${BOLD}Your API Key:${NC}  ${YELLOW}$(grep WARDEN_API_KEY .env.smb | cut -d= -f2)${NC}"
echo -e "  ${BOLD}Config dir:${NC}    $INSTALL_DIR"
echo ""
echo -e "  ${BOLD}Quick test:${NC}"
echo -e "  curl -X POST http://localhost:8001/filter \\"
echo -e "       -H 'X-API-Key: \$(grep WARDEN_API_KEY $INSTALL_DIR/.env.smb | cut -d= -f2)' \\"
echo -e "       -H 'Content-Type: application/json' \\"
echo -e "       -d '{\"content\": \"Hello world\", \"tenant_id\": \"demo\"}'"
echo ""
echo -e "  ${BOLD}Manage:${NC}"
echo -e "  docker compose -f $INSTALL_DIR/docker-compose.smb.yml stop"
echo -e "  docker compose -f $INSTALL_DIR/docker-compose.smb.yml start"
echo -e "  docker compose -f $INSTALL_DIR/docker-compose.smb.yml logs -f warden"
echo ""
