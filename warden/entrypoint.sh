#!/usr/bin/env bash
# warden/entrypoint.sh
# ─────────────────────────────────────────────────────────────────────────────
# Starts uvicorn with or without mTLS depending on MTLS_ENABLED and cert
# presence.  This lets Docker Compose and CI both use the same image.
#
# Mode B — uvicorn owns the TLS socket (certs required):
#   MTLS_ENABLED=true  +  /certs/warden.crt present  →  HTTPS + CERT_REQUIRED
#
# Mode A / plaintext — nginx terminates and forwards CN header:
#   MTLS_ENABLED=false (default)  →  plain HTTP on 8001
# ─────────────────────────────────────────────────────────────────────────────
set -e

WORKERS="${UVICORN_WORKERS:-2}"
PORT="${PORT:-8001}"

if [ "${MTLS_ENABLED:-false}" = "true" ] && [ -f /certs/warden.crt ]; then
    echo "[entrypoint] mTLS enabled — starting uvicorn with TLS (CERT_REQUIRED)"
    exec uvicorn warden.main:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --workers "$WORKERS" \
        --ssl-certfile /certs/warden.crt \
        --ssl-keyfile  /certs/warden.key \
        --ssl-ca-certs /certs/ca.crt \
        --ssl-cert-reqs 2
else
    echo "[entrypoint] mTLS disabled — starting uvicorn plain HTTP"
    exec uvicorn warden.main:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --workers "$WORKERS"
fi
