#!/usr/bin/env bash
# scripts/gen_htpasswd.sh
# ─────────────────────────────────────────────────────────────────────────────
# Generate nginx Basic Auth credentials for the admin virtual host.
#
# Protects:
#   /jaeger/    — Jaeger tracing UI
#   /dashboard/ — Streamlit analytics
#   /admin/     — MSP admin panel
#
# Usage:
#   bash scripts/gen_htpasswd.sh                      # prompts for password
#   bash scripts/gen_htpasswd.sh --user ops --pass s3cr3t
#
# Output: nginx/auth/.htpasswd  (bcrypt hash, created with mode 640)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

AUTH_DIR="$(cd "$(dirname "$0")/.." && pwd)/nginx/auth"
HTPASSWD_FILE="$AUTH_DIR/.htpasswd"
USERNAME="${WARDEN_ADMIN_USER:-}"
PASSWORD="${WARDEN_ADMIN_PASS:-}"

# ── Arg parser ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) USERNAME="$2"; shift 2 ;;
        --pass) PASSWORD="$2"; shift 2 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$USERNAME" ]] && read -rp "Admin username [warden]: " USERNAME
USERNAME="${USERNAME:-warden}"

[[ -z "$PASSWORD" ]] && read -rsp "Admin password: " PASSWORD && echo ""
[[ -z "$PASSWORD" ]] && echo "ERROR: password cannot be empty." >&2 && exit 1

mkdir -p "$AUTH_DIR"
chmod 750 "$AUTH_DIR"

# ── Generate bcrypt hash ──────────────────────────────────────────────────────
# Prefer apache2-utils (htpasswd), fall back to Python passlib/bcrypt.
if command -v htpasswd &>/dev/null; then
    htpasswd -cbB "$HTPASSWD_FILE" "$USERNAME" "$PASSWORD"
elif python3 -c "import passlib" 2>/dev/null; then
    python3 - <<PYEOF
from passlib.apache import HtpasswdFile
ht = HtpasswdFile("$HTPASSWD_FILE", new=True)
ht.set_password("$USERNAME", "$PASSWORD")
ht.save()
PYEOF
elif python3 -c "import bcrypt" 2>/dev/null; then
    python3 - <<PYEOF
import bcrypt, pathlib
h = bcrypt.hashpw("$PASSWORD".encode(), bcrypt.gensalt(rounds=12)).decode()
pathlib.Path("$HTPASSWD_FILE").write_text(f"$USERNAME:{h}\n")
PYEOF
else
    echo "ERROR: install apache2-utils (htpasswd) or pip install passlib[bcrypt]" >&2
    exit 1
fi

chmod 640 "$HTPASSWD_FILE"

echo ""
echo "✓ .htpasswd written to: $HTPASSWD_FILE"
echo "  User: $USERNAME"
echo "  Protected paths:"
echo "    https://admin.shadow-warden-ai.com/jaeger/"
echo "    https://admin.shadow-warden-ai.com/        (dashboard)"
echo "    https://admin.shadow-warden-ai.com/admin/"
echo ""
echo "Restart nginx to apply:"
echo "  docker compose restart proxy"
