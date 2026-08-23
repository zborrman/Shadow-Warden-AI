#!/usr/bin/env bash
#
# Reload Grafana when its provisioning changed — idempotent, safe to run twice.
#
# Why this exists as a script rather than a step
# ──────────────────────────────────────────────
# Grafana reads `grafana/provisioning/**` at startup only. The files are
# bind-mounted, so changing one alters neither the image nor the compose config
# and `docker compose up` correctly does nothing — the container goes on
# evaluating whatever it loaded. Production paged critical on a rule whose fix
# had already shipped, for weeks, because of exactly that.
#
# The deploy job learned to restart Grafana on a change. That only covers code
# that arrives through the deploy job. Code reaches this server other ways —
# someone pulling by hand, an agent session over ssh — and those pulls left the
# container on stale rules with nothing recording it. So the logic lives here,
# where the deploy and a human can both call it, and the deploy step is one line.
#
# Usage (from the repo root on the server, or anywhere):
#     bash scripts/reload_grafana_if_changed.sh
#
# Exit codes: 0 = up to date or reloaded successfully; 1 = reload failed (the
# stamp is deliberately left unwritten, so the next run retries).
set -euo pipefail

cd "$(dirname "$0")/.."

PROV_DIR="grafana/provisioning"
STAMP=".deploy-grafana-prov.sha"
CONTAINER="warden-grafana"
HEALTH_TRIES=30
HEALTH_SLEEP=4

if [ ! -d "$PROV_DIR" ]; then
  echo "reload-grafana: no $PROV_DIR here — nothing to do"
  exit 0
fi

# Keyed to a stamp of the tree, NOT to a git diff. A per-run diff is consumable
# state: a deploy that pulls and then fails spends the window exactly once,
# silently, in the direction that leaves production on stale rules. That is not
# hypothetical — it is how the first version of this check lost its own change.
PROV_SHA=$(find "$PROV_DIR" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d" " -f1)

if [ "$PROV_SHA" = "$(cat "$STAMP" 2>/dev/null || true)" ]; then
  echo "reload-grafana: provisioning unchanged — no restart"
  exit 0
fi

echo "reload-grafana: provisioning changed — restarting $CONTAINER"
if ! docker compose restart grafana; then
  echo "reload-grafana: restart command failed — rules on disk are NOT loaded" >&2
  exit 1
fi

# The stamp is written only after Grafana comes back HEALTHY, never on the exit
# code of `restart`. Malformed provisioning does not fail the restart — it
# crash-loops the container afterwards, which this repository has caused twice
# (a pinned datasource uid, then secure_settings). Stamping on exit code alone
# would record a crash-looping Grafana as "rules loaded" and never retry.
for _ in $(seq 1 "$HEALTH_TRIES"); do
  STATE=$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "missing")
  case "$STATE" in
    healthy)
      echo "$PROV_SHA" > "$STAMP"
      echo "reload-grafana: $CONTAINER healthy — provisioning loaded"
      exit 0
      ;;
    missing)
      echo "reload-grafana: $CONTAINER not found — cannot confirm the rules loaded" >&2
      exit 1
      ;;
  esac
  sleep "$HEALTH_SLEEP"
done

echo "reload-grafana: $CONTAINER did not become healthy — rules on disk are NOT loaded." >&2
echo "reload-grafana: stamp left unwritten so the next run retries. Last log lines:" >&2
docker compose logs --tail 30 grafana 2>&1 | tail -30 >&2 || true
exit 1
