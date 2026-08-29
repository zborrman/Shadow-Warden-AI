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

# ── Prometheus multiprocess registry ─────────────────────────────────────────
# uvicorn runs $WORKERS forked processes and each keeps its OWN prometheus_client
# registry. Without a shared directory, /metrics is answered by whichever worker
# the kernel hands the connection to, so a single counter reads a different
# value on consecutive scrapes — measured on production as
# http_requests_total returning 51, then 0, then 1. Prometheus reads each drop
# as a counter reset, which makes rate() over any warden counter meaningless
# and every rate-based alert noise.
#
# prometheus_fastapi_instrumentator's .expose() builds a MultiProcessCollector
# registry when this variable is set, so setting it is what makes /metrics
# aggregate across all workers.
#
# The directory MUST be emptied before the workers fork: files are keyed by pid
# and survive a restart, so stale files from dead workers would be summed into
# every future scrape and inflate counters forever. Cleaning here (once, in the
# parent) rather than in the FastAPI lifespan (which runs per worker, after the
# fork, and would delete the siblings' live files) is the only correct place.
if [ -n "${PROMETHEUS_MULTIPROC_DIR:-}" ]; then
    echo "[entrypoint] prometheus multiprocess dir: ${PROMETHEUS_MULTIPROC_DIR} (clearing stale pid files)"
    mkdir -p "${PROMETHEUS_MULTIPROC_DIR}"
    rm -f "${PROMETHEUS_MULTIPROC_DIR}"/*.db 2>/dev/null || true
    chown -R wardenuser:warden "${PROMETHEUS_MULTIPROC_DIR}"
elif [ "${WORKERS}" -gt 1 ]; then
    echo "[entrypoint] WARNING: ${WORKERS} uvicorn workers but PROMETHEUS_MULTIPROC_DIR is unset —"          "/metrics will report a single arbitrary worker's registry"
fi

# ── Pass-through: if a command was given (e.g. docker run ... python3 foo.py),
#    run it as wardenuser after fixing ownership — do NOT start uvicorn.
if [ $# -gt 0 ]; then
    exec gosu wardenuser "$@"
fi

# ── Database migrations: NOT here. ───────────────────────────────────────────
# `warden/db/migrate.py::upgrade_to_head()` runs the Alembic tree from the
# FastAPI lifespan, under a Postgres advisory lock (D-1). This file used to run
# it too, and got it wrong for four months: `cd /warden` then
# `alembic -c warden/alembic.ini` resolves to /warden/warden/alembic.ini, but
# WORKDIR *is* /warden and the file is /warden/alembic.ini — so every boot
# printed "No 'script_location' key found in configuration" and swallowed it
# with `|| echo "WARNING: migrations failed (continuing anyway)"`.
#
# That fail-open is why the D-1 audit concluded "alembic upgrade head appears
# nowhere": something did invoke it, on every single boot, and had been failing
# silently since the block was added in b3d02377 (2026-04-06). Do not restore
# it. A second migrator would also run in ARQ_MODE, where no lifespan exists
# and no schema authority belongs.

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
