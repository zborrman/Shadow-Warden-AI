#!/usr/bin/env bash
# scripts/setup_secrets.sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shadow Warden AI — Secrets Bootstrap Script
#
# Generates cryptographically strong secrets and distributes them to one
# of three backends:
#   • .env file       (Docker Compose / local dev)
#   • Kubernetes      (kubectl create secret — direct or dry-run YAML)
#   • Vault           (HashiCorp Vault KV v2)
#   • AWS             (AWS Secrets Manager via awscli)
#   • GCP             (GCP Secret Manager via gcloud)
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   bash scripts/setup_secrets.sh env              # write .env (interactive)
#   bash scripts/setup_secrets.sh env --non-interactive  # auto-generate all
#   bash scripts/setup_secrets.sh kube [namespace] # kubectl apply Secret
#   bash scripts/setup_secrets.sh kube-dry [ns]    # print YAML only
#   bash scripts/setup_secrets.sh vault [kv-path]  # write to Vault KV
#   bash scripts/setup_secrets.sh aws  [sm-path]   # write to AWS Secrets Mgr
#   bash scripts/setup_secrets.sh gcp  [project]   # write to GCP Secret Mgr
#   bash scripts/setup_secrets.sh check            # validate .env or env vars
#   bash scripts/setup_secrets.sh rotate-key       # rotate WARDEN_API_KEY only
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $*"; }
err()  { echo -e "  ${RED}✗${RESET} $*" >&2; }
info() { echo -e "  ${CYAN}→${RESET} $*"; }
hr()   { echo -e "  ${CYAN}$(printf '─%.0s' {1..60})${RESET}"; }

# ── Config ────────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-shadow-warden}"
KUBE_RELEASE="${KUBE_RELEASE:-shadow-warden}"

NON_INTERACTIVE=0
[[ "${2:-}" == "--non-interactive" || "${NON_INTERACTIVE:-0}" == "1" ]] && NON_INTERACTIVE=1

# ── Secret generation ─────────────────────────────────────────────────────────
#
# Uses OpenSSL (preferred) or Python as fallback.
# Each call generates a cryptographically random token of the requested length.

gen_hex() {
    local bytes="${1:-32}"   # output: 2×bytes hex chars
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$bytes"
    else
        python3 -c "import secrets; print(secrets.token_hex($bytes))"
    fi
}

gen_password() {
    # 24-char mixed alphanumeric (safe for psql / redis connection strings)
    local len="${1:-24}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$len"
        echo
    else
        python3 -c "import secrets,string; \
            print(''.join(secrets.choice(string.ascii_letters+string.digits) \
            for _ in range($len)))"
    fi
}

# ── Interactive prompt for a single secret value ──────────────────────────────
#
# Usage: ask_or_generate <VAR_NAME> <description> <generated_value>
# Prints: the value chosen (either typed or generated)

ask_or_generate() {
    local var="$1"
    local desc="$2"
    local generated="$3"

    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        echo "$generated"
        return
    fi

    echo ""
    echo -e "  ${BOLD}${var}${RESET} — ${desc}"
    echo -e "  Generated value: ${CYAN}${generated}${RESET}"
    echo -n "  Press ENTER to accept, or type your own value: "
    read -r input
    if [[ -z "$input" ]]; then
        echo "$generated"
    else
        echo "$input"
    fi
}

# ── Validate a single secret ──────────────────────────────────────────────────
validate_secret() {
    local name="$1"
    local value="$2"
    local required="${3:-1}"   # 1 = required, 0 = optional

    if [[ -z "$value" ]]; then
        if [[ $required -eq 1 ]]; then
            err "$name is not set (required)"
            return 1
        else
            warn "$name is not set (optional — feature disabled)"
            return 0
        fi
    fi

    # Length check for keys expected to be at least 32 hex chars
    case "$name" in
        WARDEN_API_KEY|SECRET_KEY)
            if [[ ${#value} -lt 32 ]]; then
                err "$name is too short (${#value} chars, minimum 32)"
                return 1
            fi ;;
        POSTGRES_PASS|REDIS_PASSWORD)
            if [[ ${#value} -lt 12 ]]; then
                err "$name is too short (${#value} chars, minimum 12)"
                return 1
            fi ;;
    esac

    # Detect obvious placeholder values
    local placeholders=("change-me" "changeme" "password" "secret" "admin" "test" "example")
    for placeholder in "${placeholders[@]}"; do
        if [[ "${value,,}" == *"$placeholder"* ]]; then
            err "$name contains placeholder value: '$value'"
            return 1
        fi
    done

    ok "$name  (${#value} chars)"
    return 0
}

# ── Check mode ────────────────────────────────────────────────────────────────
cmd_check() {
    echo -e "${BOLD}▶ Validating Shadow Warden secrets${RESET}"
    echo ""

    local errors=0

    # Source .env if it exists
    if [[ -f "$ENV_FILE" ]]; then
        info "Loading $ENV_FILE"
        # shellcheck disable=SC1090
        set -a; source "$ENV_FILE"; set +a
    else
        warn ".env not found — checking environment variables only"
    fi

    hr
    echo -e "  ${BOLD}Required secrets:${RESET}"
    hr

    validate_secret "WARDEN_API_KEY"  "${WARDEN_API_KEY:-}"  1 || ((errors++))
    validate_secret "POSTGRES_PASS"   "${POSTGRES_PASS:-}"   1 || ((errors++))
    validate_secret "SECRET_KEY"      "${SECRET_KEY:-}"      1 || ((errors++))

    hr
    echo -e "  ${BOLD}Optional secrets (features disabled if unset):${RESET}"
    hr

    validate_secret "ANTHROPIC_API_KEY"      "${ANTHROPIC_API_KEY:-}"      0
    validate_secret "REDIS_PASSWORD"         "${REDIS_PASSWORD:-}"         0
    validate_secret "SLACK_WEBHOOK_URL"      "${SLACK_WEBHOOK_URL:-}"      0
    validate_secret "PAGERDUTY_ROUTING_KEY"  "${PAGERDUTY_ROUTING_KEY:-}"  0
    validate_secret "GRAFANA_PASSWORD"       "${GRAFANA_PASSWORD:-}"       0
    validate_secret "SPLUNK_HEC_TOKEN"       "${SPLUNK_HEC_TOKEN:-}"       0
    validate_secret "ELASTIC_API_KEY"        "${ELASTIC_API_KEY:-}"        0
    validate_secret "LLM_API_KEY"            "${LLM_API_KEY:-}"            0

    echo ""
    if [[ $errors -gt 0 ]]; then
        echo -e "${RED}${BOLD}✗  $errors required secret(s) are missing or insecure.${RESET}"
        echo "   Run:  bash scripts/setup_secrets.sh env"
        return 1
    else
        echo -e "${GREEN}${BOLD}✅  All required secrets are set.${RESET}"
    fi
}

# ── .env backend ──────────────────────────────────────────────────────────────
cmd_env() {
    echo -e "${BOLD}▶ Shadow Warden AI — Secret Setup (.env)${RESET}"
    echo ""

    if [[ -f "$ENV_FILE" ]]; then
        if [[ $NON_INTERACTIVE -eq 0 ]]; then
            echo -e "  ${YELLOW}⚠${RESET}  .env already exists at $ENV_FILE"
            echo -n "     Overwrite? [y/N]: "
            read -r confirm
            [[ "${confirm,,}" == "y" ]] || { echo "  Aborted."; exit 0; }
        fi
        # Back up existing .env
        cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
        ok "Backed up existing .env"
    fi

    # Generate all secrets up-front
    local warden_api_key secret_key postgres_pass redis_password grafana_password

    warden_api_key=$(gen_hex 32)
    secret_key=$(gen_hex 32)
    postgres_pass=$(gen_password 24)
    redis_password=$(gen_password 20)
    grafana_password=$(gen_password 16)

    # Interactive prompts (ENTER to accept generated value)
    if [[ $NON_INTERACTIVE -eq 0 ]]; then
        echo ""
        echo -e "  ${BOLD}For each secret, press ENTER to accept the generated value${RESET}"
        echo -e "  ${BOLD}or type your own and press ENTER.${RESET}"
        echo ""
        echo -e "  ${YELLOW}Generated values are shown in cyan.${RESET}"
        echo -e "  ${YELLOW}Never commit .env to version control.${RESET}"
        echo ""

        warden_api_key=$(ask_or_generate WARDEN_API_KEY \
            "Main API key — clients send this in X-API-Key header" \
            "$warden_api_key")
        secret_key=$(ask_or_generate SECRET_KEY \
            "Flask/Streamlit session secret" \
            "$secret_key")
        postgres_pass=$(ask_or_generate POSTGRES_PASS \
            "PostgreSQL password for the warden database" \
            "$postgres_pass")
        redis_password=$(ask_or_generate REDIS_PASSWORD \
            "Redis AUTH password (leave empty for no auth)" \
            "$redis_password")
        grafana_password=$(ask_or_generate GRAFANA_PASSWORD \
            "Grafana admin UI password" \
            "$grafana_password")

        echo ""
        echo -e "  ${BOLD}Optional secrets (press ENTER to skip):${RESET}"

        local anthropic_api_key="" slack_webhook="" pagerduty_key=""
        local splunk_url="" splunk_token="" elastic_url="" elastic_key=""
        local llm_base_url="" llm_api_key=""

        echo ""
        echo -e "  ${BOLD}ANTHROPIC_API_KEY${RESET} — Evolution Engine (Claude Opus). Get from console.anthropic.com"
        echo -n "  Value (ENTER to skip): "; read -r anthropic_api_key

        echo ""
        echo -e "  ${BOLD}SLACK_WEBHOOK_URL${RESET} — Real-time HIGH/BLOCK alerts to Slack"
        echo -n "  Value (ENTER to skip): "; read -r slack_webhook

        echo ""
        echo -e "  ${BOLD}PAGERDUTY_ROUTING_KEY${RESET} — PagerDuty incident escalation"
        echo -n "  Value (ENTER to skip): "; read -r pagerduty_key

        echo ""
        echo -e "  ${BOLD}SPLUNK_HEC_URL / SPLUNK_HEC_TOKEN${RESET} — Splunk SIEM integration"
        echo -n "  SPLUNK_HEC_URL (ENTER to skip): "; read -r splunk_url
        if [[ -n "$splunk_url" ]]; then
            echo -n "  SPLUNK_HEC_TOKEN: "; read -r splunk_token
        fi

        echo ""
        echo -e "  ${BOLD}ELASTIC_URL / ELASTIC_API_KEY${RESET} — Elastic ECS SIEM integration"
        echo -n "  ELASTIC_URL (ENTER to skip): "; read -r elastic_url
        if [[ -n "$elastic_url" ]]; then
            echo -n "  ELASTIC_API_KEY: "; read -r elastic_key
        fi

        echo ""
        echo -e "  ${BOLD}LLM_BASE_URL / LLM_API_KEY${RESET} — Backend LLM for /ws/stream proxy"
        echo -n "  LLM_BASE_URL (ENTER to skip): "; read -r llm_base_url
        if [[ -n "$llm_base_url" ]]; then
            echo -n "  LLM_API_KEY: "; read -r llm_api_key
        fi
    fi

    # Write .env by patching .env.example values
    cp "$ENV_EXAMPLE" "$ENV_FILE"

    _set_env() {
        local key="$1" val="$2"
        # Replace key=... line (handles empty default values too)
        if grep -q "^${key}=" "$ENV_FILE"; then
            sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
        else
            echo "${key}=${val}" >> "$ENV_FILE"
        fi
    }

    _set_env ENV                    production
    _set_env SECRET_KEY             "$secret_key"
    _set_env POSTGRES_PASS          "$postgres_pass"
    _set_env WARDEN_API_KEY         "$warden_api_key"
    _set_env GRAFANA_PASSWORD       "$grafana_password"
    [[ -n "${redis_password:-}"   ]] && _set_env REDIS_PASSWORD    "$redis_password"
    [[ -n "${anthropic_api_key:-}"]] && _set_env ANTHROPIC_API_KEY "$anthropic_api_key"
    [[ -n "${slack_webhook:-}"    ]] && _set_env SLACK_WEBHOOK_URL  "$slack_webhook"
    [[ -n "${pagerduty_key:-}"    ]] && _set_env PAGERDUTY_ROUTING_KEY "$pagerduty_key"
    [[ -n "${splunk_url:-}"       ]] && _set_env SPLUNK_HEC_URL    "$splunk_url"
    [[ -n "${splunk_token:-}"     ]] && _set_env SPLUNK_HEC_TOKEN  "$splunk_token"
    [[ -n "${elastic_url:-}"      ]] && _set_env ELASTIC_URL       "$elastic_url"
    [[ -n "${elastic_key:-}"      ]] && _set_env ELASTIC_API_KEY   "$elastic_key"
    [[ -n "${llm_base_url:-}"     ]] && _set_env LLM_BASE_URL      "$llm_base_url"
    [[ -n "${llm_api_key:-}"      ]] && _set_env LLM_API_KEY       "$llm_api_key"

    chmod 600 "$ENV_FILE"

    echo ""
    ok ".env written to $ENV_FILE  (mode 600)"
    echo ""
    echo -e "${GREEN}${BOLD}✅  Secrets ready for Docker Compose.${RESET}"
    echo ""
    echo "  Next:"
    echo "    bash scripts/gen_certs.sh            # generate mTLS certs"
    echo "    docker compose up --build -d"
    echo ""
    echo -e "  ${YELLOW}Keep .env out of version control:${RESET}"
    echo "    echo .env >> .gitignore"
}

# ── Kubernetes Secret YAML ────────────────────────────────────────────────────
_kube_secret_yaml() {
    local ns="${1:-$KUBE_NAMESPACE}"

    # Collect values — from .env file or environment
    if [[ -f "$ENV_FILE" ]]; then
        set -a; source "$ENV_FILE"; set +a
    fi

    _b64() { printf '%s' "${1:-}" | base64 | tr -d '\n'; }

    cat << EOF
---
# Generated by scripts/setup_secrets.sh — do not commit
apiVersion: v1
kind: Secret
metadata:
  name: ${KUBE_RELEASE}-secrets
  namespace: $ns
  labels:
    app.kubernetes.io/name: shadow-warden
    app.kubernetes.io/managed-by: setup-secrets-sh
type: Opaque
data:
  WARDEN_API_KEY:         $(_b64 "${WARDEN_API_KEY:-}")
  SECRET_KEY:             $(_b64 "${SECRET_KEY:-}")
  ANTHROPIC_API_KEY:      $(_b64 "${ANTHROPIC_API_KEY:-}")
  POSTGRES_PASSWORD:      $(_b64 "${POSTGRES_PASS:-}")
  REDIS_PASSWORD:         $(_b64 "${REDIS_PASSWORD:-}")
  LLM_BASE_URL:           $(_b64 "${LLM_BASE_URL:-}")
  LLM_API_KEY:            $(_b64 "${LLM_API_KEY:-}")
  SLACK_WEBHOOK_URL:      $(_b64 "${SLACK_WEBHOOK_URL:-}")
  PAGERDUTY_ROUTING_KEY:  $(_b64 "${PAGERDUTY_ROUTING_KEY:-}")
  SPLUNK_HEC_URL:         $(_b64 "${SPLUNK_HEC_URL:-}")
  SPLUNK_HEC_TOKEN:       $(_b64 "${SPLUNK_HEC_TOKEN:-}")
  ELASTIC_URL:            $(_b64 "${ELASTIC_URL:-}")
  ELASTIC_API_KEY:        $(_b64 "${ELASTIC_API_KEY:-}")
  GRAFANA_PASSWORD:       $(_b64 "${GRAFANA_PASSWORD:-}")
EOF
}

# ── Kubernetes backend ────────────────────────────────────────────────────────
cmd_kube() {
    local ns="${2:-$KUBE_NAMESPACE}"
    echo -e "${BOLD}▶ Applying secrets to Kubernetes namespace: $ns${RESET}"

    command -v kubectl >/dev/null 2>&1 || { err "kubectl not found"; exit 1; }
    kubectl get namespace "$ns" >/dev/null 2>&1 || {
        warn "Namespace $ns not found — creating"
        kubectl create namespace "$ns"
    }

    _kube_secret_yaml "$ns" | kubectl apply -f -
    ok "Secret ${KUBE_RELEASE}-secrets applied"

    echo ""
    echo -e "${GREEN}${BOLD}✅  Kubernetes secrets ready.${RESET}"
    echo ""
    echo "  Verify:"
    echo "    kubectl get secret ${KUBE_RELEASE}-secrets -n $ns"
}

cmd_kube_dry() {
    local ns="${2:-$KUBE_NAMESPACE}"
    _kube_secret_yaml "$ns"
}

# ── Vault backend ─────────────────────────────────────────────────────────────
cmd_vault() {
    local path="${2:-secret/shadow-warden/prod}"
    command -v vault >/dev/null 2>&1 || { err "vault CLI not found"; exit 1; }

    echo -e "${BOLD}▶ Writing secrets to Vault: $path${RESET}"

    if [[ -f "$ENV_FILE" ]]; then
        set -a; source "$ENV_FILE"; set +a
    fi

    vault kv put "$path" \
        warden_api_key="${WARDEN_API_KEY:-}" \
        secret_key="${SECRET_KEY:-}" \
        anthropic_api_key="${ANTHROPIC_API_KEY:-}" \
        postgres_password="${POSTGRES_PASS:-}" \
        redis_password="${REDIS_PASSWORD:-}" \
        llm_api_key="${LLM_API_KEY:-}" \
        slack_webhook_url="${SLACK_WEBHOOK_URL:-}" \
        pagerduty_routing_key="${PAGERDUTY_ROUTING_KEY:-}" \
        splunk_hec_token="${SPLUNK_HEC_TOKEN:-}" \
        elastic_api_key="${ELASTIC_API_KEY:-}" \
        grafana_password="${GRAFANA_PASSWORD:-}"

    ok "Secrets written to Vault at $path"
    echo ""
    echo -e "${GREEN}${BOLD}✅  Vault secrets ready.${RESET}"
    echo ""
    echo "  Reference in Helm values:"
    echo "    Use External Secrets Operator with a VaultDynamicSecret"
    echo "    pointing to $path"
}

# ── AWS Secrets Manager backend ───────────────────────────────────────────────
cmd_aws() {
    local sm_path="${2:-shadow-warden/prod}"
    command -v aws >/dev/null 2>&1 || { err "AWS CLI not found"; exit 1; }

    echo -e "${BOLD}▶ Writing secrets to AWS Secrets Manager: $sm_path${RESET}"

    if [[ -f "$ENV_FILE" ]]; then
        set -a; source "$ENV_FILE"; set +a
    fi

    local payload
    payload=$(python3 -c "
import json, os
print(json.dumps({
    'warden_api_key':        os.environ.get('WARDEN_API_KEY',''),
    'secret_key':            os.environ.get('SECRET_KEY',''),
    'anthropic_api_key':     os.environ.get('ANTHROPIC_API_KEY',''),
    'postgres_password':     os.environ.get('POSTGRES_PASS',''),
    'redis_password':        os.environ.get('REDIS_PASSWORD',''),
    'llm_api_key':           os.environ.get('LLM_API_KEY',''),
    'slack_webhook_url':     os.environ.get('SLACK_WEBHOOK_URL',''),
    'pagerduty_routing_key': os.environ.get('PAGERDUTY_ROUTING_KEY',''),
    'splunk_hec_token':      os.environ.get('SPLUNK_HEC_TOKEN',''),
    'elastic_api_key':       os.environ.get('ELASTIC_API_KEY',''),
    'grafana_password':      os.environ.get('GRAFANA_PASSWORD',''),
}))")

    # Create or update
    if aws secretsmanager describe-secret --secret-id "$sm_path" >/dev/null 2>&1; then
        aws secretsmanager put-secret-value \
            --secret-id "$sm_path" \
            --secret-string "$payload" \
            --query VersionId --output text
        ok "Updated existing secret: $sm_path"
    else
        aws secretsmanager create-secret \
            --name "$sm_path" \
            --description "Shadow Warden AI production secrets" \
            --secret-string "$payload" \
            --query ARN --output text
        ok "Created new secret: $sm_path"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}✅  AWS Secrets Manager ready.${RESET}"
    echo ""
    echo "  Reference ARN in ExternalSecret:"
    echo "    remoteRef.key: $sm_path"
}

# ── GCP Secret Manager backend ────────────────────────────────────────────────
cmd_gcp() {
    local project="${2:-}"
    command -v gcloud >/dev/null 2>&1 || { err "gcloud CLI not found"; exit 1; }

    [[ -z "$project" ]] && project=$(gcloud config get-value project 2>/dev/null)
    [[ -z "$project" ]] && { err "GCP project not set. Pass as argument or set: gcloud config set project <id>"; exit 1; }

    echo -e "${BOLD}▶ Writing secrets to GCP Secret Manager (project: $project)${RESET}"

    if [[ -f "$ENV_FILE" ]]; then
        set -a; source "$ENV_FILE"; set +a
    fi

    _gcp_secret() {
        local name="$1" value="$2"
        local full="shadow-warden-${name//_/-}"

        # Create secret if it doesn't exist
        if ! gcloud secrets describe "$full" --project="$project" >/dev/null 2>&1; then
            gcloud secrets create "$full" \
                --project="$project" \
                --replication-policy="automatic" \
                --quiet
        fi

        # Add new version
        printf '%s' "$value" | \
            gcloud secrets versions add "$full" \
            --project="$project" \
            --data-file=- \
            --quiet

        ok "$full"
    }

    _gcp_secret warden-api-key       "${WARDEN_API_KEY:-}"
    _gcp_secret secret-key           "${SECRET_KEY:-}"
    _gcp_secret anthropic-api-key    "${ANTHROPIC_API_KEY:-}"
    _gcp_secret postgres-password    "${POSTGRES_PASS:-}"
    _gcp_secret redis-password       "${REDIS_PASSWORD:-}"
    _gcp_secret llm-api-key          "${LLM_API_KEY:-}"
    _gcp_secret slack-webhook-url    "${SLACK_WEBHOOK_URL:-}"
    _gcp_secret pagerduty-key        "${PAGERDUTY_ROUTING_KEY:-}"
    _gcp_secret splunk-hec-token     "${SPLUNK_HEC_TOKEN:-}"
    _gcp_secret elastic-api-key      "${ELASTIC_API_KEY:-}"
    _gcp_secret grafana-password     "${GRAFANA_PASSWORD:-}"

    echo ""
    echo -e "${GREEN}${BOLD}✅  GCP Secret Manager ready.${RESET}"
    echo ""
    echo "  Reference in ExternalSecret:"
    echo "    secretStoreRef.kind: ClusterSecretStore  (GCP provider)"
    echo "    remoteRef.key: shadow-warden-warden-api-key"
}

# ── Rotate WARDEN_API_KEY only ────────────────────────────────────────────────
cmd_rotate_key() {
    echo -e "${BOLD}▶ Rotating WARDEN_API_KEY${RESET}"

    local new_key
    new_key=$(gen_hex 32)

    if [[ -f "$ENV_FILE" ]]; then
        # Back up and rotate in .env
        cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
        sed -i "s|^WARDEN_API_KEY=.*|WARDEN_API_KEY=${new_key}|" "$ENV_FILE"
        ok ".env updated"
    fi

    echo ""
    echo -e "  ${BOLD}New WARDEN_API_KEY:${RESET}"
    echo -e "  ${CYAN}${new_key}${RESET}"
    echo ""
    echo -e "${YELLOW}⚠  Remember to update:${RESET}"
    echo "   • All client applications sending X-API-Key"
    echo "   • Kubernetes Secret (run: bash scripts/setup_secrets.sh kube)"
    echo "   • Vault / AWS SM / GCP SM (run the relevant backend command)"
    echo ""
    echo "  Restart warden after updating the Secret:"
    echo "    kubectl rollout restart deploy/${KUBE_RELEASE}-warden -n ${KUBE_NAMESPACE}"
}

# ── Argument dispatch ─────────────────────────────────────────────────────────
CMD="${1:-env}"

case "$CMD" in
    env)          cmd_env ;;
    check)        cmd_check ;;
    kube)         cmd_kube "$@" ;;
    kube-dry)     cmd_kube_dry "$@" ;;
    vault)        cmd_vault "$@" ;;
    aws)          cmd_aws "$@" ;;
    gcp)          cmd_gcp "$@" ;;
    rotate-key)   cmd_rotate_key ;;
    help|--help|-h)
        sed -n '/^# Usage/,/^# ━/p' "$0" | grep -v "^# ━"
        ;;
    *)
        err "Unknown command: $CMD"
        echo "  Valid commands: env | check | kube [ns] | kube-dry [ns]"
        echo "                  vault [path] | aws [path] | gcp [project]"
        echo "                  rotate-key | help"
        exit 1
        ;;
esac
