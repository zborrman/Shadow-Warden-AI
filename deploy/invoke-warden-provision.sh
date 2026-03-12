#!/usr/bin/env bash
# deploy/invoke-warden-provision.sh
# Shadow Warden AI — Zero-Touch Endpoint Provisioning (macOS / Linux)
#
# Usage:
#   GATEWAY_URL=https://ai.acme-msp.com \
#   MSP_API_KEY=$MSP_WARDEN_KEY \
#   COMPANY_NAME="Riverside Dental" \
#   CONTACT_EMAIL="it@riverside-dental.com" \
#   bash invoke-warden-provision.sh
#
# Optional env vars:
#   PLAN              (starter | professional | enterprise — default: starter)
#   EXTENSION_ID      Chrome Web Store ID
#   OLLAMA_URL        Local Ollama endpoint (default: http://localhost:11434)
#   DRY_RUN=1         Print what would happen; do not write config
#   FORCE=1           Re-provision even if already provisioned
#
# Exit codes:
#   0 — success
#   1 — error
#   2 — already provisioned (use FORCE=1 to override)
#
# macOS: writes Chrome/Edge JSON policy to /Library/Managed Preferences/
# Linux: writes to /etc/opt/chrome/policies/managed/  and
#                   /etc/opt/microsoft/edge/policies/managed/

set -euo pipefail

# ── Parameters ────────────────────────────────────────────────────────────────

GATEWAY_URL="${GATEWAY_URL:?GATEWAY_URL is required}"
MSP_API_KEY="${MSP_API_KEY:?MSP_API_KEY is required}"
COMPANY_NAME="${COMPANY_NAME:?COMPANY_NAME is required}"
CONTACT_EMAIL="${CONTACT_EMAIL:?CONTACT_EMAIL is required}"
PLAN="${PLAN:-starter}"
EXTENSION_ID="${EXTENSION_ID:-WARDEN_EXTENSION_ID_PLACEHOLDER}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
DRY_RUN="${DRY_RUN:-0}"
FORCE="${FORCE:-0}"
PROVISION_MARKER="/var/lib/shadow-warden/provision.json"

GATEWAY_BASE="${GATEWAY_URL%/}"

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "[Warden] $*" >&2; }
ok()   { printf '{"status":"ok","tenant_id":"%s","company":"%s","gateway_url":"%s","message":"%s"}\n' \
              "$TENANT_ID" "$COMPANY_NAME" "$GATEWAY_BASE" \
              "Extension will auto-install on next Chrome/Edge launch."; }
fail() { printf '{"status":"error","message":"%s"}\n' "$1"; exit 1; }

write_file() {
    local path="$1"
    local content="$2"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "[DryRun] Would write: $path"
        log "$content"
        return
    fi
    mkdir -p "$(dirname "$path")"
    echo "$content" > "$path"
    log "Written: $path"
}

# ── Check already provisioned ─────────────────────────────────────────────────

if [[ "$FORCE" != "1" && -f "$PROVISION_MARKER" ]]; then
    TID=$(python3 -c "import json,sys; d=json.load(open('$PROVISION_MARKER')); print(d.get('tenant_id',''))" 2>/dev/null || true)
    if [[ -n "$TID" ]]; then
        printf '{"status":"already_provisioned","tenant_id":"%s","message":"Use FORCE=1 to re-provision."}\n' "$TID"
        exit 2
    fi
fi

# ── Step 1: POST /onboard ─────────────────────────────────────────────────────

ONBOARD_URL="${GATEWAY_BASE}/onboard"
log "Calling $ONBOARD_URL ..."

if [[ "$DRY_RUN" == "1" ]]; then
    TENANT_ID="dryrun-$(head -c 4 /dev/urandom | xxd -p)"
    API_KEY="sw-dryrun-key-000000"
    log "[DryRun] Would POST to $ONBOARD_URL"
else
    RESPONSE=$(curl -s -w '\n%{http_code}' \
        -X POST "$ONBOARD_URL" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $MSP_API_KEY" \
        --max-time 30 \
        -d "{\"company_name\":\"$COMPANY_NAME\",\"contact_email\":\"$CONTACT_EMAIL\",\"plan\":\"$PLAN\"}")

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -1)

    if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
        fail "POST /onboard returned HTTP $HTTP_CODE: $BODY"
    fi

    TENANT_ID=$(echo "$BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['tenant_id'])" 2>/dev/null)
    API_KEY=$(echo "$BODY"   | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['api_key'])"   2>/dev/null)

    if [[ -z "$TENANT_ID" || -z "$API_KEY" ]]; then
        fail "Response missing tenant_id or api_key: $BODY"
    fi
fi

log "Tenant: $TENANT_ID"

# ── Step 2: Write browser policy ──────────────────────────────────────────────

POLICY_JSON=$(cat <<EOF
{
  "ExtensionInstallForcelist": [
    "${EXTENSION_ID};https://clients2.google.com/service/update2/crx"
  ],
  "3rdparty": {
    "extensions": {
      "${EXTENSION_ID}": {
        "policy": {
          "gatewayUrl":  "$GATEWAY_BASE",
          "apiKey":      "$API_KEY",
          "tenantId":    "$TENANT_ID",
          "ollamaUrl":   "$OLLAMA_URL",
          "enabled":     true,
          "managed":     true
        }
      }
    }
  }
}
EOF
)

if [[ "$(uname)" == "Darwin" ]]; then
    # macOS — Chrome Enterprise managed preferences
    CHROME_POLICY_DIR="/Library/Managed Preferences/com.google.Chrome"
    EDGE_POLICY_DIR="/Library/Managed Preferences/com.microsoft.Edge"

    write_file "${CHROME_POLICY_DIR}/shadow_warden.json" "$POLICY_JSON"
    write_file "${EDGE_POLICY_DIR}/shadow_warden.json"   "$POLICY_JSON"
else
    # Linux — Chrome/Chromium and Edge JSON policy
    write_file "/etc/opt/chrome/policies/managed/shadow_warden.json"          "$POLICY_JSON"
    write_file "/etc/chromium/policies/managed/shadow_warden.json"             "$POLICY_JSON"
    write_file "/etc/opt/microsoft/edge/policies/managed/shadow_warden.json"   "$POLICY_JSON"
fi

# ── Step 3: Write provision marker ────────────────────────────────────────────

if [[ "$DRY_RUN" != "1" ]]; then
    write_file "$PROVISION_MARKER" \
        "{\"tenant_id\":\"$TENANT_ID\",\"company\":\"$COMPANY_NAME\",\"gateway_url\":\"$GATEWAY_BASE\",\"provisioned_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

if [[ "$DRY_RUN" == "1" ]]; then
    printf '{"status":"dry_run","tenant_id":"%s","company":"%s","message":"Dry run — no files written."}\n' \
        "$TENANT_ID" "$COMPANY_NAME"
else
    ok
fi

exit 0
