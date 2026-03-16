#!/usr/bin/env bash
# deploy/hetzner.sh
# ─────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — One-Shot Hetzner Deployment
#
# Usage (run as root on a fresh Hetzner Ubuntu 22.04/24.04 VPS):
#
#   curl -fsSL https://raw.githubusercontent.com/your-org/shadow-warden-ai/main/deploy/hetzner.sh \
#     | bash -s -- --domain warden.example.com --email admin@example.com
#
# OR clone the repo first, then:
#   bash deploy/hetzner.sh --domain warden.example.com --email admin@example.com
#
# Flags:
#   --domain   FQDN for TLS (required for production; skip for IP-only deploy)
#   --email    Let's Encrypt contact email (required when --domain is set)
#   --repo     Git repo URL (default: current directory / already cloned)
#   --branch   Git branch (default: main)
#   --no-tls   Disable Let's Encrypt, serve on plain HTTP (dev/internal only)
#
# What this script does:
#   1. Install Docker + Docker Compose v2 if missing
#   2. Configure UFW firewall (22, 80, 443, 8001 + 8501 restricted by default)
#   3. Generate .env if it doesn't already exist
#   4. Issue Let's Encrypt TLS certificate via Certbot (unless --no-tls)
#   5. docker compose up --build -d
#   6. Enable systemd service for auto-restart on reboot
#   7. Print post-deploy status and URLs
#
# Exit codes: 0 success, 1 fatal error
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

# ── Defaults ──────────────────────────────────────────────────────────────────
DOMAIN=""
EMAIL=""
REPO_URL=""
BRANCH="main"
NO_TLS=0
DEPLOY_DIR="/opt/shadow-warden"
SYSTEMD_UNIT="shadow-warden"
COMPOSE_CMD=""       # resolved later

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[warden]${NC} $*"; }
ok()    { echo -e "${GREEN}[warden ✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warden !]${NC} $*"; }
fatal() { echo -e "${RED}[warden ✗]${NC} $*" >&2; exit 1; }

# ── Arg parser ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)  DOMAIN="$2";   shift 2 ;;
        --email)   EMAIL="$2";    shift 2 ;;
        --repo)    REPO_URL="$2"; shift 2 ;;
        --branch)  BRANCH="$2";   shift 2 ;;
        --no-tls)  NO_TLS=1;      shift   ;;
        *)         fatal "Unknown flag: $1" ;;
    esac
done

[[ "$NO_TLS" == 0 && -z "$DOMAIN" ]] && warn "No --domain specified — will deploy without TLS."
[[ "$NO_TLS" == 0 && -n "$DOMAIN" && -z "$EMAIL" ]] && fatal "--email is required when --domain is set (Let's Encrypt ToS)."

# ── Must run as root ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fatal "This script must be run as root (sudo bash deploy/hetzner.sh ...)."

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Docker
# ─────────────────────────────────────────────────────────────────────────────
info "Step 1/7 — Checking Docker …"

if ! command -v docker &>/dev/null; then
    info "Installing Docker CE …"
    apt-get update -qq
    apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    ok "Docker installed."
else
    ok "Docker $(docker --version | awk '{print $3}' | tr -d ',') already present."
fi

# Prefer `docker compose` (v2 plugin); fall back to `docker-compose` (v1)
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    fatal "Neither 'docker compose' nor 'docker-compose' found after install."
fi
ok "Compose command: $COMPOSE_CMD"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Firewall (UFW)
# ─────────────────────────────────────────────────────────────────────────────
info "Step 2/7 — Configuring UFW firewall …"

if command -v ufw &>/dev/null; then
    ufw --force reset          >/dev/null 2>&1 || true
    ufw default deny incoming  >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow 22/tcp    comment "SSH"
    ufw allow 80/tcp    comment "HTTP (redirect to HTTPS)"
    ufw allow 443/tcp   comment "HTTPS"
    # Internal ports — restrict to loopback; expose only via reverse-proxy
    # Uncomment the lines below if you need direct access from a trusted CIDR:
    # ufw allow from 10.0.0.0/8 to any port 8001 comment "Warden API (internal)"
    # ufw allow from 10.0.0.0/8 to any port 8501 comment "Dashboard (internal)"
    ufw --force enable >/dev/null 2>&1
    ok "UFW enabled: 22, 80, 443 open. Warden 8001/8501 restricted to loopback."
else
    warn "UFW not found — skipping firewall configuration."
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Clone / update repo
# ─────────────────────────────────────────────────────────────────────────────
info "Step 3/7 — Preparing source directory …"

if [[ -n "$REPO_URL" ]]; then
    if [[ -d "$DEPLOY_DIR/.git" ]]; then
        info "Pulling latest $BRANCH from $REPO_URL …"
        git -C "$DEPLOY_DIR" fetch origin
        git -C "$DEPLOY_DIR" checkout "$BRANCH"
        git -C "$DEPLOY_DIR" pull --ff-only origin "$BRANCH"
    else
        info "Cloning $REPO_URL → $DEPLOY_DIR …"
        git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$DEPLOY_DIR"
    fi
    ok "Source at $DEPLOY_DIR (branch: $BRANCH)."
elif [[ -f "$(pwd)/docker-compose.yml" ]]; then
    # Script is being run from inside the already-cloned repo
    DEPLOY_DIR="$(pwd)"
    ok "Using current directory as deploy root: $DEPLOY_DIR"
else
    fatal "No --repo specified and no docker-compose.yml in current directory."
fi

cd "$DEPLOY_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Generate .env
# ─────────────────────────────────────────────────────────────────────────────
info "Step 4/7 — Generating .env …"

ENV_FILE="$DEPLOY_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists — skipping generation (delete it to regenerate)."
else
    # Generate strong random secrets
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    WARDEN_API_KEY=$(python3 -c "import secrets; print('sw-' + secrets.token_hex(28))")
    GRAFANA_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
    DOCS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")

    cat > "$ENV_FILE" <<EOF
# Shadow Warden AI — Production .env
# Generated by deploy/hetzner.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# ────────────────────────────────────────────────────────────────
# KEEP THIS FILE SECRET — never commit to git.

# ── Environment ──────────────────────────────────────────────────
ENV=production

# ── Security ─────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}

# ── PostgreSQL ───────────────────────────────────────────────────
POSTGRES_USER=warden_user
DB_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=warden

# ── API Keys ─────────────────────────────────────────────────────
# Primary API key for /filter endpoint.
# Copy this to your client apps / MSP dashboard.
WARDEN_API_KEY=${WARDEN_API_KEY}

# ── Docs auth (HTTP Basic) ────────────────────────────────────────
DOCS_USERNAME=warden
DOCS_PASSWORD=${DOCS_PASSWORD}

# ── Grafana ───────────────────────────────────────────────────────
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}

# ── Evolution Engine (Claude Opus) ───────────────────────────────
# Obtain from https://console.anthropic.com/ — leave blank for air-gapped mode.
ANTHROPIC_API_KEY=

# ── OpenTelemetry + Jaeger ────────────────────────────────────────
OTEL_ENABLED=true
OTEL_SERVICE_NAME=shadow-warden
# Jaeger is started as a Docker service — internal DNS resolves automatically.
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
OTEL_SAMPLE_RATE=1.0

# ── Security features ─────────────────────────────────────────────
SESSION_GUARD_ENABLED=true
HONEY_MODE=true
HONEY_INJECT_SECRETS=true

# ── ML model cache ────────────────────────────────────────────────
MODEL_CACHE_DIR=/warden/models
SEMANTIC_THRESHOLD=0.72
STRICT_MODE=false

# ── ONNX Runtime ──────────────────────────────────────────────────
# Activated automatically after scripts/export_onnx.py runs (Step 5b below).
ONNX_MODEL_PATH=/warden/models/minilm-onnx
ONNX_THREADS=1
ONNX_INTRA_THREADS=4

# ── Rate limiting ─────────────────────────────────────────────────
RATE_LIMIT_PER_MINUTE=60
REDIS_URL=redis://redis:6379/0
CACHE_TTL_SECONDS=300

# ── Analytics / GDPR ─────────────────────────────────────────────
GDPR_LOG_RETENTION_DAYS=30

# ── Dashboard ─────────────────────────────────────────────────────
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD_HASH=
DASHBOARD_SESSION_MINUTES=60
DASHBOARD_MAX_ATTEMPTS=5
DASHBOARD_LOCKOUT_MINUTES=15

# ── Alerting (optional — fill in to enable) ───────────────────────
SLACK_WEBHOOK_URL=
PAGERDUTY_ROUTING_KEY=
ALERT_MIN_RISK_LEVEL=high

# ── SIEM (optional) ───────────────────────────────────────────────
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=
ELASTIC_URL=
ELASTIC_API_KEY=
ELASTIC_INDEX=shadow-warden-events

# ── LLM Proxy (optional) ──────────────────────────────────────────
OPENAI_UPSTREAM=https://api.openai.com
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=
EOF

    chmod 600 "$ENV_FILE"
    ok ".env created at $ENV_FILE (chmod 600)."
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  SAVE THESE — they won't be shown again:${NC}"
    echo -e "${YELLOW}  WARDEN_API_KEY  = ${WARDEN_API_KEY}${NC}"
    echo -e "${YELLOW}  DB_PASSWORD     = ${DB_PASSWORD}${NC}"
    echo -e "${YELLOW}  GRAFANA_PASSWORD= ${GRAFANA_PASSWORD}${NC}"
    echo -e "${YELLOW}  DOCS_PASSWORD   = ${DOCS_PASSWORD}${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — TLS (Let's Encrypt via Certbot)
# ─────────────────────────────────────────────────────────────────────────────
info "Step 5/7 — TLS certificate …"

if [[ -n "$DOMAIN" && "$NO_TLS" == 0 ]]; then
    if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        info "Issuing Let's Encrypt certificate for $DOMAIN …"
        apt-get install -y --no-install-recommends certbot >/dev/null 2>&1
        # Standalone mode — temporarily binds port 80
        certbot certonly --standalone \
            --non-interactive \
            --agree-tos \
            --email "$EMAIL" \
            -d "$DOMAIN"
        ok "Certificate issued: /etc/letsencrypt/live/$DOMAIN/"
    else
        ok "Certificate already present for $DOMAIN."
    fi

    # Symlink certs into nginx/tls directory expected by proxy service
    TLS_DIR="$DEPLOY_DIR/nginx/tls"
    mkdir -p "$TLS_DIR"
    ln -sf "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$TLS_DIR/cert.pem"
    ln -sf "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$TLS_DIR/key.pem"
    ok "TLS certs symlinked → $TLS_DIR"

    # Auto-renew cron (certbot --renew + compose reload)
    RENEW_HOOK="/etc/letsencrypt/renewal-hooks/deploy/warden-reload.sh"
    cat > "$RENEW_HOOK" <<HOOK
#!/bin/bash
# Auto-reload Warden proxy after certificate renewal
cd $DEPLOY_DIR
$COMPOSE_CMD exec -T proxy nginx -s reload
HOOK
    chmod +x "$RENEW_HOOK"
    ok "Certbot renewal hook installed at $RENEW_HOOK"

    # Add certbot renew to cron if not already present
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet") | crontab -
        ok "Certbot renewal cron registered (daily at 03:00 UTC)."
    fi
else
    warn "Skipping TLS — serving on HTTP only."
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5a — Generate Basic Auth credentials (.htpasswd)
# ─────────────────────────────────────────────────────────────────────────────
info "Step 5a/7 — Generating nginx Basic Auth credentials …"

HTPASSWD_FILE="$DEPLOY_DIR/nginx/auth/.htpasswd"

if [[ -f "$HTPASSWD_FILE" ]]; then
    ok ".htpasswd already exists — skipping (delete to regenerate)."
else
    mkdir -p "$DEPLOY_DIR/nginx/auth"
    chmod 750 "$DEPLOY_DIR/nginx/auth"

    # Generate a random admin password and write it immediately
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")

    if command -v htpasswd &>/dev/null; then
        htpasswd -cbB "$HTPASSWD_FILE" warden "$ADMIN_PASS"
    else
        apt-get install -y --no-install-recommends apache2-utils >/dev/null 2>&1
        htpasswd -cbB "$HTPASSWD_FILE" warden "$ADMIN_PASS"
    fi
    chmod 640 "$HTPASSWD_FILE"

    echo ""
    echo -e "${YELLOW}  BASIC AUTH (Jaeger + Dashboard + Admin UI):${NC}"
    echo -e "${YELLOW}  User    : warden${NC}"
    echo -e "${YELLOW}  Password: ${ADMIN_PASS}${NC}"
    echo -e "${YELLOW}  File    : ${HTPASSWD_FILE}${NC}"
    echo ""

    ok ".htpasswd created."
fi

# Symlink TLS certs into nginx/tls (certbot wrote them in Step 5)
mkdir -p "$DEPLOY_DIR/nginx/tls"
if [[ -n "$DOMAIN" && -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    ln -sf "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$DEPLOY_DIR/nginx/tls/cert.pem"
    ln -sf "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$DEPLOY_DIR/nginx/tls/key.pem"
    ok "TLS certs symlinked → $DEPLOY_DIR/nginx/tls/"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5b — Export MiniLM to ONNX (2-4× faster CPU inference)
# ─────────────────────────────────────────────────────────────────────────────
info "Step 5b/7 — Exporting MiniLM to ONNX …"

ONNX_OUT="$DEPLOY_DIR/warden/models/minilm-onnx"
mkdir -p "$ONNX_OUT"

if [[ -f "$ONNX_OUT/model.onnx" ]]; then
    ONNX_SIZE=$(du -m "$ONNX_OUT/model.onnx" | cut -f1)
    ok "ONNX model already present (${ONNX_SIZE} MB) — skipping export."
else
    # Install export deps into a temporary venv so we don't pollute system Python
    info "Installing export dependencies …"
    VENV_DIR="$(mktemp -d)/export-venv"
    python3 -m venv "$VENV_DIR" >/dev/null

    # CPU-only torch + sentence-transformers + optimum (preferred export path)
    "$VENV_DIR/bin/pip" install --quiet --no-cache-dir \
        torch --index-url https://download.pytorch.org/whl/cpu
    "$VENV_DIR/bin/pip" install --quiet --no-cache-dir \
        sentence-transformers transformers optimum[onnxruntime] onnxruntime

    info "Running export_onnx.py → $ONNX_OUT …"
    if "$VENV_DIR/bin/python" "$DEPLOY_DIR/scripts/export_onnx.py" \
            --output "$ONNX_OUT" 2>&1 | grep -v "^$"; then
        ONNX_SIZE=$(du -m "$ONNX_OUT/model.onnx" 2>/dev/null | cut -f1 || echo "?")
        ok "ONNX model exported: $ONNX_OUT/model.onnx (${ONNX_SIZE} MB)"
    else
        warn "ONNX export failed — falling back to PyTorch inference path."
        warn "Clearing ONNX_MODEL_PATH in .env so the container starts cleanly."
        sed -i 's|^ONNX_MODEL_PATH=.*|ONNX_MODEL_PATH=|' "$ENV_FILE"
    fi

    # Clean up the temporary venv (container has its own Python env)
    rm -rf "$VENV_DIR"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — docker compose up
# ─────────────────────────────────────────────────────────────────────────────
info "Step 6/7 — Building and starting services …"
info "This may take 5-10 minutes on first run (MiniLM model download ~80 MB) …"

$COMPOSE_CMD pull --quiet 2>/dev/null || true   # pull pre-built images if registry is set
$COMPOSE_CMD up --build -d --remove-orphans

ok "All services started."

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — systemd service (auto-restart on reboot)
# ─────────────────────────────────────────────────────────────────────────────
info "Step 7/7 — Installing systemd service …"

UNIT_FILE="/etc/systemd/system/${SYSTEMD_UNIT}.service"

cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=Shadow Warden AI
Documentation=https://github.com/your-org/shadow-warden-ai
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${DEPLOY_DIR}
ExecStart=${COMPOSE_CMD} up -d --remove-orphans
ExecStop=${COMPOSE_CMD} down
ExecReload=${COMPOSE_CMD} up -d --remove-orphans
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SYSTEMD_UNIT"
ok "systemd unit enabled: $SYSTEMD_UNIT.service (auto-start on reboot)."

# ─────────────────────────────────────────────────────────────────────────────
# DONE — Print status
# ─────────────────────────────────────────────────────────────────────────────

# Wait up to 30 s for warden health endpoint
info "Waiting for Warden health check …"
for i in $(seq 1 15); do
    if curl -sf http://localhost:8001/health >/dev/null 2>&1; then
        ok "Warden is healthy."
        break
    fi
    sleep 2
    [[ $i == 15 ]] && warn "Warden not yet healthy — check 'docker compose logs warden'."
done

SERVER_IP=$(curl -sf https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Shadow Warden AI — Deployment Complete ✓            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
if [[ -n "$DOMAIN" && "$NO_TLS" == 0 ]]; then
    echo -e "  Warden API   : ${CYAN}https://${DOMAIN}/filter${NC}"
    echo -e "  Dashboard    : ${CYAN}https://${DOMAIN}:8501${NC}  (or via tunnel)"
    echo -e "  Grafana      : ${CYAN}https://${DOMAIN}:3000${NC}  (or via tunnel)"
    echo -e "  Jaeger UI    : ${CYAN}https://${DOMAIN}:16686${NC} (internal only)"
else
    echo -e "  Warden API   : ${CYAN}http://${SERVER_IP}:8001/filter${NC}"
    echo -e "  Dashboard    : ${CYAN}http://${SERVER_IP}:8501${NC}"
    echo -e "  Grafana      : ${CYAN}http://${SERVER_IP}:3000${NC}"
    echo -e "  Jaeger UI    : ${CYAN}http://${SERVER_IP}:16686${NC}"
fi
echo ""
echo -e "  .env file    : ${CYAN}${ENV_FILE}${NC}"
echo -e "  Logs         : ${CYAN}$COMPOSE_CMD logs -f warden${NC}"
echo -e "  Restart      : ${CYAN}systemctl restart $SYSTEMD_UNIT${NC}"
echo -e "  Update       : ${CYAN}git pull && $COMPOSE_CMD up --build -d${NC}"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo -e "  1. Add ANTHROPIC_API_KEY to .env to enable the Evolution Engine"
echo -e "  2. Set SLACK_WEBHOOK_URL for real-time attack alerts"
echo -e "  3. Generate a dashboard password hash:"
echo -e "     ${CYAN}$COMPOSE_CMD exec warden python -m warden.analytics.auth${NC}"
echo ""
