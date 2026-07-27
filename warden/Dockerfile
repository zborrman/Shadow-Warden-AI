# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Warden Gateway  (slim build)
#
#  Base: python:3.11-slim  (~130 MB vs ~1.8 GB playwright/python MCR image)
#
#  BuildKit required (DOCKER_BUILDKIT=1 or Docker Desktop ≥4.x default).
#  Cache mounts keep pip/apt caches across rebuilds → code-only change: ~30s.
#
#  Browser sandbox (warden/tools/browser.py) is DEFERRED.
#  To re-enable when server disk allows:
#    1. Switch FROM back to: mcr.microsoft.com/playwright/python:v1.49.0-noble
#    2. Add after pip installs: RUN playwright install chromium
#    3. Set BROWSER_ENABLED=true in docker-compose.yml
# ─────────────────────────────────────────────────────────────────────────────
# syntax=docker/dockerfile:1.7

# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 1 — builder  (P-3a)
#
#  Everything that needs a compiler happens here and is then thrown away. The
#  single-stage image shipped gcc, g++, cmake, ninja-build, libssl-dev and
#  astyle into the *running gateway* — ~466 MB of apt, and a full C/C++
#  toolchain inside a security container, which turns a file-write primitive
#  into a code-execution primitive.
#
#  It also, for the entire life of the PQC feature, never produced a working
#  liboqs. `pip install liboqs-python` installs the *Python bindings only*; the
#  native library is a separate CMake build the Dockerfile never ran. The step
#  was `|| echo "⚠ ..."` fail-open, so the build always "succeeded" and nobody
#  was told. Verified 2026-07-27 against production: no liboqs.so anywhere on
#  disk, and `pqc_status()` returning {'available': False}. PQC is sold on the
#  Enterprise tier; it was silently degrading to classical Ed25519. This stage
#  builds liboqs for real.
# ═════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

# Build-only toolchain. None of this reaches the runtime image.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ cmake ninja-build libssl-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── liboqs (the C library) ───────────────────────────────────────────────────
#  Version must match liboqs-python: `oqs.py` sets OQS_VERSION from its own
#  package version and, when it cannot load a library, tries to download and
#  build that exact tag at *import time*. Pinning both to 0.16.0 and shipping a
#  prebuilt library means the runtime never attempts that (which would need
#  network + cmake in the running container — precisely what this stage removes).
ARG LIBOQS_VERSION=0.16.0
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" \
        https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
 && cmake --build /tmp/liboqs/build --parallel \
 && cmake --install /tmp/liboqs/build \
 && rm -rf /tmp/liboqs

# ── Python deps (three-step: liboqs → torch CPU-only → everything else) ─────
#
#  DETERMINISM (P-0): requirements.txt states *intent* (floors, `>=`), while
#  constraints.txt is the lockfile that decides the actual resolved version of
#  every package. CI has installed with `-c constraints.txt` for a while; this
#  image did not, so the two drifted — on 2026-07-26 that drift put
#  prometheus-fastapi-instrumentator 8.1.0 into production while CI had tested
#  8.0.2, and its changed `_get_route_name` arity 502'd the whole API. A
#  measurement taken the next day found 48 packages differing between the
#  CI-tested set and the running production image.
#
#  Rule: every pip install on this image's critical path is version-decided —
#  either an explicit `==` here, or via `-c constraints.txt`. Enforced by
#  warden/tests/test_deps_pinned.py.
COPY requirements.txt constraints.txt ./

# Installed into the builder's REAL site-packages, not a `--prefix=/install`
# staging tree — deliberately.
#
#  `pip install --prefix=/install` does not put /install on sys.path, so step 3
#  cannot see the CPU-only torch that step 2 just installed. sentence-transformers
#  depends on torch, so pip resolved it again from the DEFAULT index and pulled
#  the CUDA build: +2.7 GB of nvidia-* wheels and +691 MB of triton, taking the
#  image from 3.6 GB to 7.35 GB and silently violating the repo's CPU-only-torch
#  constraint. Caught by inspecting the layer sizes before shipping.
#
#  Installing normally keeps the exact sequential resolution semantics of the
#  proven single-stage build — step 3 sees torch already satisfied and leaves it
#  alone — and the runtime stage simply takes the finished site-packages.

# Step 1 — liboqs-python: the Python *bindings*. The native library it binds to
#   was built above; this no longer needs to succeed by luck.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "liboqs-python==0.16.0"

# Step 2 — torch from the CPU-only wheel index (~800 MB wheel, cached after first pull).
#   Pinned explicitly rather than via constraints.txt: the `+cpu` local version
#   only exists on the PyTorch CPU index, so it cannot be resolved from PyPI and
#   is deliberately excluded from the constraints file (see its header).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "torch==2.13.0+cpu" --index-url https://download.pytorch.org/whl/cpu

# Step 3 — everything else from PyPI, version-decided by the lockfile.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt -c constraints.txt

# Assert the CPU-only invariant held. A CUDA torch is not a size regression to
# be noticed later — it is a different artifact, on hardware that has no GPU.
RUN python -c "\
import importlib.util, torch; \
assert torch.__version__.endswith('+cpu'), 'torch is not the CPU build: ' + torch.__version__; \
assert importlib.util.find_spec('nvidia') is None, 'CUDA nvidia-* wheels pulled into a CPU-only image'; \
assert importlib.util.find_spec('triton') is None, 'triton (GPU compiler) pulled into a CPU-only image'; \
print('torch CPU-only OK', torch.__version__)"


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 2 — runtime
#
#  Runtime libraries only. No gcc, no g++, no cmake, no ninja, no astyle.
# ═════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim

WORKDIR /warden

# Runtime-only system deps.
#   libgomp1         — OpenMP, needed by torch / scikit-learn at import
#   gosu             — entrypoint drops root -> wardenuser
#   curl             — container healthcheck
#   git              — GitPython (a streamlit dependency) shells out to it
#   postgresql-client (R1 backups): the base image's own repo ships v17, which is
#     newer than the timescale/timescaledb:latest-pg16 server — pg_dump/pg_restore
#     support dumping from an older major server than the client, so no PGDG repo
#     is needed. (Do NOT pin postgresql-client-16 via PGDG: on this base image's
#     codename, PGDG's libpq5 conflicts with the system libldap, and apt fails.)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 curl gosu git ca-certificates \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Python site-packages + console scripts, built above. Both stages derive from
# the same python:3.11-slim, so /usr/local/bin is identical apart from the
# entry points the installs added.
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# The native liboqs. OQS_INSTALL_PATH is how oqs.py finds it (it looks in
# $OQS_INSTALL_PATH/lib and /lib64); ldconfig additionally puts it on the
# default search path so ctypes.util.find_library("oqs") resolves too.
COPY --from=builder /opt/liboqs /opt/liboqs
ENV OQS_INSTALL_PATH=/opt/liboqs
RUN echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf \
 && echo "/opt/liboqs/lib64" >> /etc/ld.so.conf.d/liboqs.conf \
 && ldconfig

# PQC must not be able to fail silently again. This is a build-time assertion:
# if liboqs cannot be loaded, the image does not get built. The old behaviour
# was `|| echo "⚠ ..."`, which is why a non-working PQC shipped for months.
RUN python -c "import oqs; assert oqs.is_sig_enabled('ML-DSA-65'), 'ML-DSA-65 missing'; assert oqs.is_kem_enabled('ML-KEM-768'), 'ML-KEM-768 missing'; print('liboqs OK', oqs.oqs_version())"

# ── Non-root runtime user ─────────────────────────────────────────────────────
RUN addgroup --system --gid 10001 warden \
    && adduser --system --uid 10001 --gid 10001 --no-create-home wardenuser

# ── Application source ────────────────────────────────────────────────────────
ARG GIT_SHA=dev
COPY --chown=wardenuser:warden . .

RUN mkdir -p /warden/models /warden/data \
    && chown -R wardenuser:warden /warden/models /warden/data \
    && chmod -R 755 /warden/models /warden/data

# ── Runtime environment ───────────────────────────────────────────────────────
ENV MODEL_CACHE_DIR=/warden/models
ENV HF_HOME=/warden/models
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/
ENV BROWSER_ENABLED=false

# NOTE: We do NOT set USER here. The entrypoint runs as root so it can fix
# bind-mount directory ownership (Docker volumes arrive owned by root when
# the host directory was created outside the container). After fixing perms
# it execs uvicorn as wardenuser via gosu — same pattern as postgres/redis.

EXPOSE 8001

ENTRYPOINT ["/bin/bash", "/warden/entrypoint.sh"]
