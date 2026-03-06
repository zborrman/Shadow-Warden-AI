#!/usr/bin/env bash
# scripts/gen_certs.sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shadow Warden AI — mTLS Certificate Management Script
#
# Generates a self-signed CA hierarchy + per-service leaf certificates.
# Supports CRL generation, revocation, rotation, expiry checks,
# and Kubernetes Secret output for Enterprise key management.
#
# ── Output layout (certs/ is git-ignored) ──────────────────────────────────
#   certs/ca.{key,crt}                — Root CA       (10-year validity)
#   certs/ca.crl                      — CRL           (30-day validity)
#   certs/ca.cnf                      — OpenSSL CA config
#   certs/warden.{key,crt}            — Warden server cert  (90-day)
#   certs/analytics.{key,crt}         — Analytics server cert
#   certs/proxy-client.{key,crt}      — nginx → warden client cert
#   certs/analytics-client.{key,crt}  — analytics → warden client cert
#   certs/admin-client.{key,crt}      — admin → warden client cert
#   certs/app-client.{key,crt}        — app service → warden client cert
#   certs/issued/                     — OpenSSL CA archive (auto-managed)
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   bash scripts/gen_certs.sh                        # generate all certs
#   bash scripts/gen_certs.sh generate               # same as above
#   RENEW=1 bash scripts/gen_certs.sh                # force-regenerate all
#   bash scripts/gen_certs.sh check                  # show expiry for all certs
#   bash scripts/gen_certs.sh revoke <name>          # revoke + refresh CRL
#   bash scripts/gen_certs.sh rotate <name>          # revoke + re-issue + CRL
#   bash scripts/gen_certs.sh kube-secret            # print Kubernetes Secret YAML
#   bash scripts/gen_certs.sh kube-apply [namespace] # kubectl apply the Secret
#
# ── Kubernetes SANs ─────────────────────────────────────────────────────────
#   The warden server cert includes SANs for both Docker Compose
#   (dns:warden) and Kubernetes (dns:shadow-warden-warden.<ns>.svc.cluster.local)
#   Set KUBE_RELEASE and KUBE_NAMESPACE before generating to customise.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

# ── Configuration ────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DIR="${CERTS_DIR:-$ROOT_DIR/certs}"

DAYS_CA=3650        # 10 years  — rotate CA manually
DAYS_LEAF="${DAYS_LEAF:-90}"   # 90 days   — rotate quarterly
DAYS_CRL=30         # 30 days   — refresh CRL monthly
WARN_DAYS=14        # warn when cert expires in < 14 days

# Kubernetes service names (used to build SANs)
KUBE_RELEASE="${KUBE_RELEASE:-shadow-warden}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-shadow-warden}"
KUBE_CLUSTER_DOMAIN="${KUBE_CLUSTER_DOMAIN:-cluster.local}"
KUBE_SVC="${KUBE_RELEASE}-warden"

# ── Prerequisites check ───────────────────────────────────────────────────────
check_deps() {
    for cmd in openssl base64; do
        command -v "$cmd" >/dev/null 2>&1 || {
            err "Required tool not found: $cmd"
            exit 1
        }
    done
}

# ── OpenSSL CA config ─────────────────────────────────────────────────────────
write_ca_cnf() {
    if [[ "${RENEW:-0}" == "1" ]]; then
        rm -f "$CERTS_DIR/ca.db" "$CERTS_DIR/ca.db.attr" "$CERTS_DIR/ca.crl.srl"
    fi

    cat > "$CERTS_DIR/ca.cnf" << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database         = $CERTS_DIR/ca.db
new_certs_dir    = $CERTS_DIR/issued
certificate      = $CERTS_DIR/ca.crt
private_key      = $CERTS_DIR/ca.key
crl              = $CERTS_DIR/ca.crl
crlnumber        = $CERTS_DIR/ca.crl.srl
default_crl_days = $DAYS_CRL
default_md       = sha256
preserve         = no
policy           = policy_anything
unique_subject   = no

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

    [[ -f "$CERTS_DIR/ca.db"      ]] || touch "$CERTS_DIR/ca.db"
    [[ -f "$CERTS_DIR/ca.db.attr" ]] || touch "$CERTS_DIR/ca.db.attr"
    [[ -f "$CERTS_DIR/ca.crl.srl" ]] || printf "01\n" > "$CERTS_DIR/ca.crl.srl"
}

# ── Issue a leaf cert ─────────────────────────────────────────────────────────
# Usage: issue_cert <filename-prefix> <CommonName> <subjectAltName-string>
issue_cert() {
    local name="$1"
    local cn="$2"
    local san="$3"

    if [[ -f "$CERTS_DIR/$name.crt" && "${RENEW:-0}" != "1" ]]; then
        warn "$name cert already exists — skipping  (RENEW=1 to regenerate)"
        return
    fi

    openssl genrsa -out "$CERTS_DIR/$name.key" 2048 2>/dev/null

    openssl req -new \
        -key  "$CERTS_DIR/$name.key" \
        -out  "$CERTS_DIR/$name.csr" \
        -subj "/CN=$cn/O=ShadowWarden/C=US" 2>/dev/null

    # Per-cert extension file
    local ext_file="$CERTS_DIR/$name.ext"
    cat > "$ext_file" << EOF
[cert_ext]
subjectAltName        = $san
basicConstraints      = CA:FALSE
keyUsage              = critical,digitalSignature,keyEncipherment
extendedKeyUsage      = serverAuth,clientAuth
subjectKeyIdentifier  = hash
authorityKeyIdentifier= keyid:always
EOF

    openssl ca -config "$CERTS_DIR/ca.cnf" \
        -in         "$CERTS_DIR/$name.csr" \
        -out        "$CERTS_DIR/$name.crt" \
        -days       "$DAYS_LEAF" \
        -batch \
        -extfile    "$ext_file" \
        -extensions cert_ext \
        2>/dev/null

    rm -f "$CERTS_DIR/$name.csr" "$ext_file"
    ok "$name  (CN=$cn, ${DAYS_LEAF}d)"
}

# ── CRL ───────────────────────────────────────────────────────────────────────
gen_crl() {
    openssl ca -config "$CERTS_DIR/ca.cnf" \
        -gencrl \
        -out "$CERTS_DIR/ca.crl" \
        2>/dev/null
    chmod 644 "$CERTS_DIR/ca.crl"

    local revoked
    revoked=$(grep -c "^R" "$CERTS_DIR/ca.db" 2>/dev/null || true)
    revoked="${revoked:-0}"
    ok "CRL  (${DAYS_CRL}-day validity, ${revoked} revoked entr$([ "$revoked" = 1 ] && echo y || echo ies))"
}

# ── Revoke ────────────────────────────────────────────────────────────────────
revoke_cert() {
    local name="$1"
    local cert="$CERTS_DIR/$name.crt"
    [[ -f "$cert" ]] || { err "$cert not found"; exit 1; }

    echo -e "${BOLD}▶ Revoking $name...${RESET}"
    write_ca_cnf

    # Extract CN from the cert before revoking (used to patch MTLS_ALLOWED_CNS)
    local cn
    cn=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null \
         | sed 's/.*CN\s*=\s*//;s/,.*//')

    openssl ca -config "$CERTS_DIR/ca.cnf" \
        -revoke "$cert" 2>/dev/null \
        && ok "Revoked $name  (CN=$cn)" \
        || warn "$name may already be revoked"

    gen_crl

    # ── Kubernetes: push updated CRL + patch CN allowlist ─────────────────────
    if command -v kubectl >/dev/null 2>&1; then
        echo ""
        info "Pushing updated CRL to Kubernetes namespace '$KUBE_NAMESPACE' …"
        kube_apply "$KUBE_NAMESPACE"

        # Remove the revoked CN from MTLS_ALLOWED_CNS via helm upgrade.
        # This is the enforcement layer for Mode B (uvicorn direct TLS) and
        # provides defence-in-depth for Mode A (nginx TLS termination).
        if command -v helm >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
            local current_cns new_cns
            current_cns=$(helm get values "$KUBE_RELEASE" \
                --namespace "$KUBE_NAMESPACE" --all --output json 2>/dev/null \
                | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('warden', {}).get('mtls', {}).get('allowedCNs', ''))
" 2>/dev/null || echo "")

            if [[ -n "$current_cns" && "$current_cns" == *"$cn"* ]]; then
                new_cns=$(echo "$current_cns" \
                    | tr ',' '\n' \
                    | grep -v "^${cn}$" \
                    | paste -sd ',' -)
                info "Patching MTLS_ALLOWED_CNS:  $current_cns  →  ${new_cns:-<empty>}"
                helm upgrade "$KUBE_RELEASE" \
                    "$(cd "$(dirname "$0")/.." && pwd)/helm/shadow-warden" \
                    --namespace "$KUBE_NAMESPACE" \
                    --reuse-values \
                    --set "warden.mtls.allowedCNs=${new_cns}" \
                    2>/dev/null \
                    && ok "Helm release updated  (allowedCNs=${new_cns:-<empty>})" \
                    || warn "helm upgrade failed — patch allowedCNs manually"
            else
                info "CN '$cn' not in current allowedCNs ('$current_cns') — no Helm patch needed."
            fi
        fi

        # Restart warden to mount the refreshed CRL secret and pick up the
        # updated MTLS_ALLOWED_CNS env var in one rollout.
        echo ""
        info "Restarting warden deployment …"
        kubectl rollout restart \
            "deployment/${KUBE_RELEASE}-warden" \
            --namespace "$KUBE_NAMESPACE" \
            && kubectl rollout status \
                "deployment/${KUBE_RELEASE}-warden" \
                --namespace "$KUBE_NAMESPACE" \
                --timeout=120s \
            && ok "Warden pods restarted — revocation is now live"
    else
        # kubectl not available: print manual steps
        echo ""
        echo "    kubectl not found. To enforce revocation, run:"
        echo "      bash scripts/gen_certs.sh kube-apply ${KUBE_NAMESPACE}"
        echo "      helm upgrade $KUBE_RELEASE helm/shadow-warden \\"
        echo "        --namespace $KUBE_NAMESPACE --reuse-values \\"
        echo "        --set warden.mtls.allowedCNs=\"<list without $cn>\""
        echo "      kubectl rollout restart deploy/${KUBE_RELEASE}-warden -n ${KUBE_NAMESPACE}"
    fi

    echo ""
    echo "    Docker Compose — reload nginx to enforce the new CRL immediately:"
    echo "      docker exec warden-proxy nginx -s reload"
    echo ""
    echo -e "${GREEN}${BOLD}✅  Revocation complete for $name (CN=$cn).${RESET}"
}

# ── Rotate (revoke + re-issue) ────────────────────────────────────────────────
rotate_cert() {
    local name="$1"
    echo -e "${BOLD}▶ Rotating $name...${RESET}"
    write_ca_cnf

    # Find CN and SAN from the existing cert
    local cn san
    cn=$(openssl x509 -in "$CERTS_DIR/$name.crt" -noout -subject 2>/dev/null \
         | sed 's/.*CN\s*=\s*//;s/,.*//')

    # Revoke old cert
    openssl ca -config "$CERTS_DIR/ca.cnf" \
        -revoke "$CERTS_DIR/$name.crt" 2>/dev/null || true

    # Remove old cert so issue_cert regenerates
    rm -f "$CERTS_DIR/$name.crt" "$CERTS_DIR/$name.key"
    RENEW=1

    # Re-issue with same CN (SAN must be passed externally; use lookup table)
    case "$name" in
        warden)
            _issue_warden_cert ;;
        analytics)
            issue_cert analytics analytics \
                "DNS:analytics,DNS:localhost,IP:127.0.0.1" ;;
        proxy-client)
            issue_cert proxy-client proxy "DNS:proxy" ;;
        analytics-client)
            issue_cert analytics-client analytics \
                "DNS:analytics,DNS:${KUBE_RELEASE}-analytics.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}" ;;
        admin-client)
            issue_cert admin-client admin \
                "DNS:admin,DNS:${KUBE_RELEASE}-admin.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}" ;;
        app-client)
            issue_cert app-client app "DNS:app" ;;
        *)
            err "Unknown cert name '$name'. Cannot determine SAN for rotation."
            err "Valid names: warden analytics proxy-client analytics-client admin-client app-client"
            exit 1 ;;
    esac

    gen_crl

    echo ""
    echo -e "${GREEN}${BOLD}✅  Rotation complete for $name.${RESET}"
    echo "    Reload affected services and (for k8s) update the Secret:"
    echo "      bash scripts/gen_certs.sh kube-apply ${KUBE_NAMESPACE}"
}

# ── Warden server cert (Kubernetes + Docker SANs) ─────────────────────────────
_issue_warden_cert() {
    # SAN covers Docker service name, Kubernetes short + FQDN, and localhost
    local san
    san="DNS:warden"
    san+=",DNS:${KUBE_SVC}"
    san+=",DNS:${KUBE_SVC}.${KUBE_NAMESPACE}"
    san+=",DNS:${KUBE_SVC}.${KUBE_NAMESPACE}.svc"
    san+=",DNS:${KUBE_SVC}.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}"
    san+=",DNS:localhost"
    san+=",IP:127.0.0.1"

    issue_cert warden warden "$san"
}

# ── Expiry check ──────────────────────────────────────────────────────────────
check_expiry() {
    echo -e "${BOLD}▶ Certificate expiry status${RESET}"
    echo ""

    local now
    now=$(date +%s)
    local any_warn=0

    for cert in "$CERTS_DIR"/*.crt; do
        [[ -f "$cert" ]] || continue
        local name
        name=$(basename "$cert" .crt)

        local end_date cn days_left
        end_date=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null \
                   | cut -d= -f2)
        cn=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null \
             | sed 's/.*CN\s*=\s*//;s/,.*//')

        # Convert to epoch (portable: works on Linux and macOS)
        if date --version >/dev/null 2>&1; then
            # GNU date (Linux)
            end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
        else
            # BSD date (macOS)
            end_epoch=$(date -j -f "%b %d %T %Y %Z" "$end_date" +%s 2>/dev/null || echo 0)
        fi

        days_left=$(( (end_epoch - now) / 86400 ))

        local icon color
        if   [[ $days_left -lt 0 ]];         then icon="✗"; color="$RED";    any_warn=1
        elif [[ $days_left -lt $WARN_DAYS ]]; then icon="⚠"; color="$YELLOW"; any_warn=1
        else                                      icon="✓"; color="$GREEN"
        fi

        printf "  ${color}%s${RESET}  %-22s  CN=%-20s  expires %s  (%d days)\n" \
            "$icon" "$name" "$cn" "$end_date" "$days_left"
    done

    # CRL expiry
    if [[ -f "$CERTS_DIR/ca.crl" ]]; then
        local crl_end crl_epoch crl_days
        crl_end=$(openssl crl -in "$CERTS_DIR/ca.crl" -noout -nextupdate 2>/dev/null \
                  | cut -d= -f2)
        if date --version >/dev/null 2>&1; then
            crl_epoch=$(date -d "$crl_end" +%s 2>/dev/null || echo 0)
        else
            crl_epoch=$(date -j -f "%b %d %T %Y %Z" "$crl_end" +%s 2>/dev/null || echo 0)
        fi
        crl_days=$(( (crl_epoch - now) / 86400 ))

        local icon color
        if   [[ $crl_days -lt 0 ]];         then icon="✗"; color="$RED";    any_warn=1
        elif [[ $crl_days -lt $WARN_DAYS ]]; then icon="⚠"; color="$YELLOW"; any_warn=1
        else                                      icon="✓"; color="$GREEN"
        fi
        printf "  ${color}%s${RESET}  %-22s  %-26s  next update %s  (%d days)\n" \
            "$icon" "ca.crl" "(CRL)" "$crl_end" "$crl_days"
    fi

    echo ""
    if [[ $any_warn -eq 1 ]]; then
        echo -e "${YELLOW}⚠  One or more certs are expiring soon or have expired.${RESET}"
        echo "   Rotate with:  bash scripts/gen_certs.sh rotate <name>"
        return 1
    else
        echo -e "${GREEN}✅  All certificates are valid.${RESET}"
    fi
}

# ── Kubernetes Secret YAML ────────────────────────────────────────────────────
kube_secret_yaml() {
    local ns="${1:-$KUBE_NAMESPACE}"

    echo "---"
    echo "# Generated by scripts/gen_certs.sh — do not commit to git"
    echo "apiVersion: v1"
    echo "kind: Secret"
    echo "metadata:"
    echo "  name: ${KUBE_RELEASE}-mtls-certs"
    echo "  namespace: $ns"
    echo "  labels:"
    echo "    app.kubernetes.io/name: shadow-warden"
    echo "    app.kubernetes.io/component: mtls"
    echo "type: Opaque"
    echo "data:"

    for name in ca warden analytics proxy-client analytics-client admin-client app-client; do
        for ext in crt key; do
            local file="$CERTS_DIR/$name.$ext"
            [[ -f "$file" ]] || continue
            local key="${name//-/_}_${ext}"   # e.g. proxy-client.crt → proxy_client_crt
            printf "  %s: %s\n" "$key" "$(base64 < "$file" | tr -d '\n')"
        done
    done

    # CRL
    if [[ -f "$CERTS_DIR/ca.crl" ]]; then
        printf "  ca_crl: %s\n" "$(base64 < "$CERTS_DIR/ca.crl" | tr -d '\n')"
    fi
}

# ── kubectl apply ─────────────────────────────────────────────────────────────
kube_apply() {
    local ns="${1:-$KUBE_NAMESPACE}"
    command -v kubectl >/dev/null 2>&1 || { err "kubectl not found"; exit 1; }

    echo -e "${BOLD}▶ Applying mTLS Secret to namespace: $ns${RESET}"
    kube_secret_yaml "$ns" | kubectl apply -f -
    ok "Secret ${KUBE_RELEASE}-mtls-certs applied to $ns"

    echo ""
    echo "    Restart warden to mount the new certs:"
    echo "      kubectl rollout restart deploy/${KUBE_RELEASE}-warden -n $ns"
}

# ── Full generation ───────────────────────────────────────────────────────────
generate_all() {
    check_deps
    mkdir -p "$CERTS_DIR/issued"

    echo -e "${BOLD}▶ Shadow Warden AI — mTLS Certificate Generation${RESET}"
    echo "  Output: $CERTS_DIR"
    echo "  Leaf validity: ${DAYS_LEAF} days"
    echo "  Kubernetes service: ${KUBE_SVC}.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}"
    echo ""

    # ── 1. Root CA ────────────────────────────────────────────────────────────
    if [[ -f "$CERTS_DIR/ca.crt" && "${RENEW:-0}" != "1" ]]; then
        warn "CA already exists — skipping  (RENEW=1 to regenerate)"
    else
        openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null
        openssl req -new -x509 \
            -key  "$CERTS_DIR/ca.key" \
            -out  "$CERTS_DIR/ca.crt" \
            -days $DAYS_CA \
            -subj "/CN=ShadowWardenCA/O=ShadowWarden/C=US" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            2>/dev/null
        ok "Root CA  (${DAYS_CA}-day, 4096-bit RSA)"
    fi

    # ── 2. OpenSSL CA database ────────────────────────────────────────────────
    write_ca_cnf

    # ── 3. Server certs ───────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}Server certificates:${RESET}"
    _issue_warden_cert
    issue_cert analytics analytics \
        "DNS:analytics,DNS:localhost,IP:127.0.0.1"

    # ── 4. Client certs ───────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}Client certificates:${RESET}"

    # nginx proxy → warden
    issue_cert proxy-client proxy \
        "DNS:proxy,DNS:${KUBE_RELEASE}-proxy.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}"

    # analytics service → warden (for internal calls)
    issue_cert analytics-client analytics \
        "DNS:analytics,DNS:${KUBE_RELEASE}-analytics.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}"

    # admin UI → warden
    issue_cert admin-client admin \
        "DNS:admin,DNS:${KUBE_RELEASE}-admin.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}"

    # app service → warden
    issue_cert app-client app \
        "DNS:app,DNS:${KUBE_RELEASE}-app.${KUBE_NAMESPACE}.svc.${KUBE_CLUSTER_DOMAIN}"

    # ── 5. CRL ────────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}Certificate Revocation List:${RESET}"
    gen_crl

    # ── 6. Permissions ────────────────────────────────────────────────────────
    chmod 600 "$CERTS_DIR"/*.key
    chmod 644 "$CERTS_DIR"/*.crt "$CERTS_DIR"/*.crl 2>/dev/null || true

    echo ""
    echo -e "${GREEN}${BOLD}✅  All certificates generated successfully.${RESET}"
    echo ""
    echo "  ── Next steps ──────────────────────────────────────────────────────"
    echo ""
    echo "  Docker Compose:"
    echo "    Set MTLS_ENABLED=true in .env, then:"
    echo "    docker compose up -d"
    echo ""
    echo "  Kubernetes:"
    echo "    bash scripts/gen_certs.sh kube-apply ${KUBE_NAMESPACE}"
    echo "    # Then enable in Helm values:"
    echo "    # warden.mtls.enabled: true"
    echo "    # warden.mtls.allowedCNs: \"proxy,analytics,admin,app\""
    echo ""
    echo "  Revoke a compromised cert:"
    echo "    bash scripts/gen_certs.sh revoke <name>"
    echo ""
    echo "  Rotate (revoke + re-issue) a cert:"
    echo "    bash scripts/gen_certs.sh rotate <name>"
    echo ""
    echo "  Check expiry status:"
    echo "    bash scripts/gen_certs.sh check"
}

# ── Argument dispatch ─────────────────────────────────────────────────────────
CMD="${1:-generate}"

case "$CMD" in
    generate)
        generate_all
        ;;

    check)
        check_expiry
        ;;

    revoke)
        [[ -z "${2:-}" ]] && {
            err "Usage: $0 revoke <cert-name>"
            err "Valid names: warden analytics proxy-client analytics-client admin-client app-client"
            exit 1
        }
        revoke_cert "$2"
        ;;

    rotate)
        [[ -z "${2:-}" ]] && {
            err "Usage: $0 rotate <cert-name>"
            err "Valid names: warden analytics proxy-client analytics-client admin-client app-client"
            exit 1
        }
        write_ca_cnf
        rotate_cert "$2"
        ;;

    kube-secret)
        kube_secret_yaml "${2:-$KUBE_NAMESPACE}"
        ;;

    kube-apply)
        kube_apply "${2:-$KUBE_NAMESPACE}"
        ;;

    help|--help|-h)
        sed -n '/^# Usage/,/^# ── /p' "$0" | head -20 | grep -v "^#\s*──"
        ;;

    *)
        err "Unknown command: $CMD"
        echo "  Valid commands: generate | check | revoke <name> | rotate <name>"
        echo "                  kube-secret [ns] | kube-apply [ns] | help"
        exit 1
        ;;
esac
