# Production Secret & Config Hardening Runbook

**Created:** 2026-07-21 · **Target:** `/opt/shadow-warden` on VPS `91.98.234.160` · **Trigger:** pre-production audit found 3 `change-me` secrets + secret DBs on `/tmp` in prod.

> Run these **at the keyboard on the VPS** — every step mutates prod. Do them in order; Step 1 must precede Step 3 or the S1 guard will crash-loop the app (by design). Estimated disruption: portal users re-login (JWT rotation); a ~30 s warden restart window (in-flight requests drain, `stop_grace_period: 30s`).

## Findings this fixes

| # | Finding | Severity | Why it matters |
|---|---|---|---|
| 1 | `PORTAL_JWT_SECRET=change-me` | **P0** | Portal is internet-facing and signs session JWTs with this. Known secret ⇒ **forgeable sessions**. |
| 2 | `DB_PASSWORD=change-me` | **P0** | Postgres role `warden_user` password is the default placeholder. (Postgres is internal-network-only, limiting blast radius, but it's a known credential.) |
| 3 | `SECRET_KEY=change-me` | **P0** | App secret is a placeholder. |
| 4 | `WARDEN_ENV` unset + `WARDEN_DATA_DIR` unset | **P0** | App runs in `dev` mode → S1 fail-closed guard never fires; module SQLite DBs (PII/secret material) default to `/tmp` — **wiped on reboot**, world-readable, and invisible to the nightly backup (isolated per-container `/tmp`). The compose change in this PR persists the data dir by default; the prod-posture flip stays operator opt-in. |

Not a problem: `ALLOW_UNAUTHENTICATED` unset is safe (auth is fail-closed while `WARDEN_API_KEY` is set); `VAULT_MASTER_KEY`, `OFFSITE_S3_*`, `CORS_ORIGINS` all correct.

---

## Pre-flight

```bash
ssh root@91.98.234.160
cd /opt/shadow-warden
cp .env ".env.bak.$(date +%Y%m%dT%H%M%S)"    # rollback point
```

## How env vars actually reach the containers (read this first)

Verified 2026-07-21 on the box: **no service uses `env_file: .env`.** `.env` reaches a container **only** where `docker-compose.yml` explicitly interpolates `${VAR}` inside that service's `environment:` block. And `docker-compose.yml` is **pulled from `main`** on every deploy (`git reset --hard origin/main`), so any var that isn't already wired must be added in the compose file **via git**, not by editing the file on the box (a local edit is wiped on the next deploy).

Consequences:
- `SECRET_KEY`, `PORTAL_JWT_SECRET` — already wired (`${SECRET_KEY:-…}` in warden; `${PORTAL_JWT_SECRET:-}` in warden + portal) → rotatable by an `.env` value change + `docker compose up -d`.
- `DB_PASSWORD` — reaches warden **and** arq-worker indirectly, interpolated into `DATABASE_URL=postgresql+asyncpg://warden_user:${DB_PASSWORD:-change-me}@postgres:5432/warden`. Rotating it means: `ALTER ROLE` + `.env` value change + recreate **warden, arq-worker, postgres-exporter**.
- `WARDEN_DATA_DIR`, `WARDEN_ENV`, `CONFIG_FAILCLOSED` — were wired **nowhere**. Now wired into warden + arq-worker by the compose change that ships with this runbook (defaults `/warden/data` / `dev` / `false`). Once that lands on `main` and deploys, the data dir **persists by default** and the prod flags become opt-in via `.env`.

> Note on container user: the app runs **non-root as `wardenuser` (UID 10001)** — verified: uvicorn PID 1 and its workers are `wardenuser`. The Dockerfile deliberately has no `USER` directive (starts as root) and drops privileges via `gosu` in `entrypoint.sh`, so a `docker compose exec … id` returns `root` (exec uses the image's default user, not the running process's) — that is **not** a regression. The `/warden/data` bind mount is owned `wardenuser:warden`, so the `0700` chmod there is owned by the app user.

## Step 1 — Persist the data dir (handled by the compose change in this PR)

The `WARDEN_DATA_DIR=${WARDEN_DATA_DIR:-/warden/data}` wiring in this PR makes module SQLite DBs land on the persisted `./data` bind mount **by default** on the next deploy — no `.env` edit needed. This also fixes a latent backup gap: arq-worker's nightly backup scans `data_dir()`, which was its own isolated `/tmp`, so it saw **none** of the module DBs warden wrote to warden's separate `/tmp`; now both share `/warden/data`.

After the deploy, confirm it took effect:
```bash
docker compose exec -T warden python3 -c "from warden.config import data_dir; print(data_dir())"   # want /warden/data
docker compose exec -T warden sh -c 'ls /warden/data/warden_*.db 2>/dev/null | head'                # DBs now here
chmod 700 /opt/shadow-warden/data                                                                    # tighten the host mount
```
Nothing to migrate: the old `/tmp` DBs are ephemeral, so there is no prod data to move.

## Step 2 — Rotate the three `change-me` secrets

```bash
NEW_SECRET_KEY=$(openssl rand -hex 32)
NEW_PORTAL_JWT=$(openssl rand -hex 32)
NEW_DB_PASS=$(openssl rand -hex 24)      # hex only — safe inside a DATABASE_URL

# 2a. SECRET_KEY + PORTAL_JWT_SECRET are plain .env swaps
sed -i "s#^SECRET_KEY=.*#SECRET_KEY=${NEW_SECRET_KEY}#" .env
sed -i "s#^PORTAL_JWT_SECRET=.*#PORTAL_JWT_SECRET=${NEW_PORTAL_JWT}#" .env    # ⚠ logs out existing portal sessions

# 2b. DB_PASSWORD needs Postgres and .env changed together.
#     The role can rotate its own password using the OLD one (still 'change-me' until this runs).
docker compose exec -T postgres psql -U warden_user -d warden \
  -c "ALTER ROLE warden_user WITH PASSWORD '${NEW_DB_PASS}';"
sed -i "s#^DB_PASSWORD=.*#DB_PASSWORD=${NEW_DB_PASS}#" .env
# If a full DATABASE_URL is also present in .env, update its password field too:
grep -q '^DATABASE_URL=' .env && sed -i -E "s#(postgres(ql)?://warden_user:)[^@]*@#\1${NEW_DB_PASS}@#" .env || true
```

Confirm no placeholders remain:
```bash
grep -c 'change-me' .env    # want 0
```

## Step 3 — Flip to production posture (only AFTER Step 1)

```bash
for kv in 'WARDEN_ENV=production' 'CONFIG_FAILCLOSED=true' 'ALLOW_UNAUTHENTICATED=false'; do
  k=${kv%%=*}; grep -q "^${k}=" .env && sed -i "s#^${k}=.*#${kv}#" .env || echo "$kv" >> .env
done
```
These flags are wired into compose (this PR) with safe `dev`/`false` defaults, so they take effect the moment they're set in `.env` + a recreate. **Only flip these after confirming Step 1** — i.e. `data_dir()` reports `/warden/data`, not `/tmp`. With `CONFIG_FAILCLOSED=true`, a data dir still resolving under `/tmp` crashes the app on boot by design (that is the S1 guard doing its job).

## Step 4 — Apply and verify

```bash
# recreate only the services whose config changed
docker compose up -d warden arq-worker portal admin analytics

# health
docker compose exec -T warden curl -sf http://localhost:8001/health >/dev/null && echo "health OK" || echo "HEALTH FAIL"

# no config crash-loop
docker compose logs --tail 50 warden | grep -iE 'CONFIG_FAILCLOSED|/tmp|Traceback' || echo "no config errors in log tail"

# module DBs now land on the persisted mount
docker compose exec -T warden sh -c 'ls -la /warden/data/warden_*.db 2>/dev/null | head' || echo "(none yet — created on first use)"

# portal issues a fresh session (old ones are invalid by design)
curl -s -o /dev/null -w '%{http_code}\n' https://app.shadow-warden-ai.com/

# backup still ships with the new VAULT/creds — trigger or wait for 03:30 UTC cron
```

## Rollback

```bash
cp .env.bak.<timestamp> .env
# if Step 2b already ran, either keep NEW_DB_PASS (recommended) or revert the role:
#   docker compose exec -T postgres psql -U warden_user -d warden -c "ALTER ROLE warden_user WITH PASSWORD 'change-me';"
docker compose up -d warden arq-worker portal admin analytics
```

## Post-change

- Store `NEW_DB_PASS` / `NEW_PORTAL_JWT` / `NEW_SECRET_KEY` in the team secret manager — the `.env` on the box is the only copy otherwise.
- Delete the `.env.bak.*` files once verified (they contain the old — and any interim — secrets).
- Re-run the live smoke from the pre-production plan (`docs/pre-production-plan.md`) to confirm `/filter` verdicts once rate limits settle.
