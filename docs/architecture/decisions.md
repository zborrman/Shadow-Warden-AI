# Architecture Decision Records

---

## ADR-001 — CPU-only PyTorch

**Status:** Accepted  
**Date:** 2024-01

**Context:** MiniLM model needs to run in CI and on standard dev machines.
GPU is not guaranteed.

**Decision:** Install PyTorch from the CPU-only index URL
(`--index-url https://download.pytorch.org/whl/cpu`) in the Dockerfile.
This prevents the 4 GB CUDA wheel from being pulled.

**Consequences:** ~10x slower than GPU inference for large batches.
Acceptable because filter latency is dominated by I/O, not model inference,
and P99 < 50ms is met on standard hardware.

---

## ADR-002 — SQLite for Community / SEP / Healer

**Status:** Accepted  
**Date:** 2024-03

**Context:** Lightweight persistent storage for community posts, SEP audit
chains, healer metrics, and pentest findings. PostgreSQL is already deployed
but adds network overhead and schema migration complexity for these datasets.

**Decision:** Use SQLite with `COMMUNITY_DB_PATH`, `SEP_DB_PATH`,
`HEALER_METRICS_DB` environment variables (default `/tmp/...`).
Production deployments mount a persistent volume at the configured path.

**Consequences:** No concurrent write bottleneck for expected load
(< 100 posts/day per tenant). Not suitable for multi-node deployments —
use the PostgreSQL-backed models for those.

---

## ADR-003 — Fail-open Pattern for External Dependencies

**Status:** Accepted  
**Date:** 2024-02

**Context:** NIM, Slack, MinIO, and Redis are optional or may be unavailable
in development.

**Decision:** Every external call is wrapped in `try/except` with
`log.warning(...)` and a safe default. No external dependency is allowed to
crash the primary filter pipeline.

**Consequences:** In degraded mode the system loses features (moderation
verdicts, alerts, evidence storage) but never loses the core security function.

---

## ADR-004 — HMAC-SHA256 for Admin Tokens

**Status:** Accepted  
**Date:** 2024-04

**Context:** Admin endpoints (`DELETE /community/posts`, `POST /soc/heal`,
MasterAgent task tokens) need tamper-evident auth without a full OAuth stack.

**Decision:** HMAC-SHA256 over `(key_material:timestamp)` using
`hmac.compare_digest()` for constant-time comparison. Admin keys stored in
env vars, never in logs.

**Consequences:** No rotation mechanism out of the box. Operators must
rotate `ADMIN_KEY` manually via env var update + container restart.

---

## ADR-005 — Playwright MCR Base Image

**Status:** Accepted  
**Date:** 2024-03

**Context:** Visual patrol and visual_assert_page require Chromium with OS
dependencies (libnss3, libatk, etc.) that are not present in `python:slim`.

**Decision:** Use `mcr.microsoft.com/playwright/python:v1.49.0-noble` as the
base image. Non-root user UID/GID 10001 (not 1001 which is taken by noble).

**Consequences:** Larger base image (~1.2 GB). Acceptable for the warden
service; other services use slim images.

---

## ADR-006 — Atomic Writes for JSON State Files

**Status:** Accepted  
**Date:** 2024-01

**Context:** `logs.json`, `dynamic_rules.json`, `cve_report.json`, and
`security_posture.json` are written by background workers and read by the
API concurrently.

**Decision:** All writes use `tempfile.mkstemp()` + `os.replace()`.
`os.replace()` is atomic on POSIX and Windows (same filesystem).

**Consequences:** A crash mid-write leaves a `.tmp` orphan file.
A cleanup cron or restart is needed to remove them in long-running deployments.
