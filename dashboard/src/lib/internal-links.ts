/**
 * Links to services the browser may not be able to reach.
 *
 * Grafana, Jaeger, Prometheus and MinIO are all bound to 127.0.0.1 on the host
 * (OB-7): they hold every datasource credential and the whole alerting config,
 * and a request straight to the origin IP bypasses Cloudflare's WAF entirely.
 * That is the correct posture. What was not correct is that this dashboard went
 * on rendering `<a href="http://grafana:3000">` — a Docker-internal hostname no
 * browser can resolve — as a normal clickable link.
 *
 * Measured 2026-09-01: every internal link on the SOC pages was dead, in three
 * separate flavours. `NEXT_PUBLIC_GRAFANA_URL` had four different values across
 * four files (`grafana:3000` in compose, `91.98.234.160:3000` and
 * `localhost:3000` as code fallbacks, `127.0.0.1:3001` in CLAUDE.md), and none
 * of them resolves for a user. Ports 3000 and 3001 both answer nothing from
 * outside the host, which is by design.
 *
 * So there is no default here. An unset variable means "not published", and an
 * unpublished service renders as its tunnel command instead of as a link that
 * will not work. A dead link is worse than an honest absence: it costs the
 * reader a click, a wait and a browser error before telling them the same
 * thing.
 *
 * When the Caddy vhost behind Cloudflare Access exists (see docker/Caddyfile),
 * set the variable to that URL and the link returns on its own — no code
 * change. Note these are `NEXT_PUBLIC_*`, so they are inlined into the bundle
 * at BUILD time; editing the host `.env` afterwards changes nothing.
 */

export type InternalLink =
  | { readonly kind: "link"; readonly href: string }
  | { readonly kind: "tunnel"; readonly command: string };

/** Loopback ports as bound in docker-compose.yml, for the tunnel hint. */
const LOOPBACK_PORT: Record<string, number> = {
  Grafana: 3001,
  Jaeger: 16686,
  Prometheus: 9090,
  MinIO: 9001,
};

/**
 * The tunnel line is a TEMPLATE, not a runnable command — `<host>` is left for
 * the reader to substitute. The alternative was another environment variable
 * nobody would set, whose unset state would produce a command that looks
 * runnable and is not. Callers render it as a template, never as copy-paste.
 */
const SSH_HOST = "root@<host>";

/** Hosts a visitor's browser can never reach, whatever the variable says. */
const UNREACHABLE = new Set([
  "grafana", "jaeger", "prometheus", "loki", "minio", "warden", "analytics",
  "localhost", "127.0.0.1", "0.0.0.0", "::1",
]);

function isPublished(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  if (parsed.hostname === "") return false;
  return !UNREACHABLE.has(parsed.hostname.toLowerCase());
}

export function internalLink(service: string, url: string | undefined): InternalLink {
  // A non-empty value is not the same as a reachable one. Without this check
  // the fix would be one `GRAFANA_PUBLIC_URL=http://grafana:3000` away from
  // reinstating the exact defect it removes — and the CI guard cannot see it,
  // because it reads source files, not the value someone puts in a .env.
  const trimmed = (url ?? "").trim();
  if (trimmed !== "" && isPublished(trimmed)) {
    return { kind: "link", href: trimmed };
  }
  const port = LOOPBACK_PORT[service] ?? 0;
  return {
    kind: "tunnel",
    command: `ssh -L ${port}:127.0.0.1:${port} ${SSH_HOST}`,
  };
}

export const GRAFANA_URL = process.env.NEXT_PUBLIC_GRAFANA_URL ?? "";
export const JAEGER_URL = process.env.NEXT_PUBLIC_JAEGER_URL ?? "";
export const PROMETHEUS_URL = process.env.NEXT_PUBLIC_PROMETHEUS_URL ?? "";
export const MINIO_URL = process.env.NEXT_PUBLIC_MINIO_URL ?? "";

/**
 * uid of the provisioned dashboard the metrics page deep-links into.
 *
 * The page used to point at `/d/shadow-warden/shadow-warden`. No dashboard has
 * ever had that uid — `grafana/dashboards/warden_overview.json` declares
 * `shadow-warden-overview` — so even from inside the network the link 404'd.
 * `warden/tests/test_dashboard_links_resolve.py` now pins this against the
 * provisioning, so the two cannot drift apart again.
 */
export const OVERVIEW_UID = "shadow-warden-overview";

export function grafanaPanelHref(panelId: number): string {
  return `${GRAFANA_URL}/d/${OVERVIEW_UID}/?panelId=${panelId}&viewPanel=${panelId}&orgId=1`;
}

export function grafanaDashboardHref(): string {
  return `${GRAFANA_URL}/d/${OVERVIEW_UID}/?orgId=1`;
}
