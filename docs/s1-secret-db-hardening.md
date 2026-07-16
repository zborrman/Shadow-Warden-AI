# S1 — Secret-bearing SQLite DBs off `/tmp`

**Risk (ranked #1 HIGH in `docs/modernization-plan-v8.md` §6c).** Every per-module
SQLite DB resolves its default location under `data_dir()` (Phase 6,
`WARDEN_DATA_DIR`). That default is `/tmp` for backward compatibility. Several of
those DBs hold PII / secret material — secrets-governance inventory
(`warden_secrets.db`), the ACP token vault (`warden_acp.db`), staff economics,
the marketplace ledger, SEP transfers. `/tmp` is ephemeral **and** frequently
world-readable, so a prod deploy that never sets `WARDEN_DATA_DIR` is leaking
credential-bearing DBs into a shared directory.

## What S1 changes (code — inert until opted into)

Two guardrails on the single `data_dir()` seam in `warden/config.py`:

1. **mode-0700 base dir.** When `WARDEN_DATA_DIR` is set to anything other than
   the legacy `/tmp`, `data_path()` creates it with `mode=0o700` and best-effort
   `chmod(0o700)` (tightens a pre-existing loose dir too). `/tmp` itself is never
   chmod-ed — its sticky-bit permissions belong to the OS. Both operations are
   suppressed on failure (not owner, or a filesystem that ignores POSIX modes
   such as Windows), so they never crash a boot.

2. **Prod boot assertion.** `Settings.validate()` flags a production deploy
   (`WARDEN_ENV` ∈ {`prod`, `production`}) whose `data_dir()` still resolves under
   `/tmp`. It surfaces as a config problem — logged at startup, and with
   `CONFIG_FAILCLOSED=true` it crash-loops the boot instead of serving secrets
   from `/tmp`.

Both are **no-ops on an unset environment**: default `WARDEN_ENV=dev`, default
`WARDEN_DATA_DIR=/tmp` → the `base != /tmp` branch never runs and nothing is
chmod-ed. Current prod behaviour is unchanged until the operator opts in below.

## Prod rollout (operational — not auto-applied)

On the VPS `.env`:

```bash
WARDEN_ENV=production
WARDEN_DATA_DIR=/var/lib/warden      # a DEDICATED, persisted volume — see caveat
CONFIG_FAILCLOSED=true               # optional: fail the boot on the /tmp warning
```

Mount `/var/lib/warden` into every warden-image service that writes module DBs —
today that is `warden` **and** `arq-worker` (both build from `warden/Dockerfile`,
both run as UID/GID 10001). They must share the **same** `WARDEN_DATA_DIR`, or a
DB written by the ARQ worker (e.g. staff economics) and read by the gateway would
split across two `/tmp` copies.

### ⚠️ Caveat: do NOT point `WARDEN_DATA_DIR` at the shared `./data` bind mount

`./data` is also mounted **read-only into the `admin` (Streamlit) service** at
`/data`, and `admin` builds from a different image whose UID may not be 10001.
The 0700 chmod is owned by the writer (UID 10001); a different-UID reader loses
access and the dashboard breaks. Use a **dedicated** volume for
`WARDEN_DATA_DIR` (mounted only into the UID-10001 warden services), and keep the
existing `/warden/data` bind mount for the handful of DBs already pinned there by
explicit `*_DB_PATH` env (`GSAM_DB_PATH`, `SEMANTIC_DB_PATH`, `AUDIT_TRAIL_PATH`,
`LOGS_PATH`, …), which the admin dashboard reads. Explicit per-module
`*_DB_PATH` overrides always win over `WARDEN_DATA_DIR`.

## Tests

`warden/tests/test_data_dir_hardening.py` — `is_prod` matrix, the prod-`/tmp`
`validate()` assertion (exact + subdir), dev back-compat, `validate_or_raise`,
and the POSIX 0700 creation/tighten checks (skipped on non-POSIX hosts).
