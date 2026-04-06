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
#
# WHY this runs as root before dropping to wardenuser via gosu:
#   Docker bind-mounts (./warden/models:/warden/models) arrive owned by
#   whatever user created the host directory — often root from a prior
#   `docker compose up` or git checkout. The Dockerfile chown in the image
#   layer is completely overridden by the bind-mount at runtime. Running as
#   root here lets us fix ownership once at startup, then exec as wardenuser
#   via gosu — the same pattern used by the official postgres / redis images.
# ─────────────────────────────────────────────────────────────────────────────
set -e

WORKERS="${UVICORN_WORKERS:-2}"
PORT="${PORT:-8001}"

# ── Fix model cache & data directory ownership ────────────────────────────────
echo "[entrypoint] fixing /warden/models and /warden/data ownership → wardenuser"
mkdir -p /warden/models /warden/data
chown -R wardenuser:warden /warden/models /warden/data
chmod -R 755 /warden/models /warden/data

# ── Database migrations (run once per startup, idempotent) ───────────────────
if [ -n "${DATABASE_URL:-}" ]; then
    echo "[entrypoint] running alembic migrations..."
    cd /warden
    alembic -c warden/alembic.ini upgrade head && echo "[entrypoint] migrations complete" \
        || echo "[entrypoint] WARNING: migrations failed (continuing anyway)"
fi

# ── ARQ worker mode (set ARQ_MODE=1 in docker-compose to run background tasks) ─
if [ "${ARQ_MODE:-0}" = "1" ]; then
    echo "[entrypoint] ARQ_MODE=1 — starting arq worker"
    exec gosu wardenuser arq warden.workers.settings.WorkerSettings
fi

# ── Start uvicorn as wardenuser via gosu ──────────────────────────────────────
if [ "${MTLS_ENABLED:-false}" = "true" ] && [ -f /certs/warden.crt ]; then
    echo "[entrypoint] mTLS enabled — starting uvicorn with TLS (CERT_REQUIRED)"
    exec gosu wardenuser uvicorn warden.main:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --workers "$WORKERS" \
        --ssl-certfile /certs/warden.crt \
        --ssl-keyfile  /certs/warden.key \
        --ssl-ca-certs /certs/ca.crt \
        --ssl-cert-reqs 2
else
    echo "[entrypoint] mTLS disabled — starting uvicorn plain HTTP"
    exec gosu wardenuser uvicorn warden.main:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --workers "$WORKERS"
fi
