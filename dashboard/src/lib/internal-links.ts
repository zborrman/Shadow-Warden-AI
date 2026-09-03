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

/**
 * Named hosts a visitor's browser can never reach, whatever the variable says.
 *
 * Kept for legibility — the single-label rule below already covers every one of
 * them, since a Docker service name has no dot. Both exist because this list
 * says *why* out loud, and the rule catches the ones nobody thought to list.
 */
const UNREACHABLE = new Set([
  "grafana", "jaeger", "prometheus", "loki", "minio", "warden", "analytics",
  "localhost", "127.0.0.1", "0.0.0.0", "::1",
]);

/** Loopback, private, link-local and metadata literals, v4 and v6. */
function isNonPublicAddress(host: string): boolean {
  // `new URL("http://[::1]:3000").hostname` is "[::1]" — WITH the brackets. A
  // set membership test against "::1" therefore never matched, which is how
  // IPv6 loopback slipped through the first version of this check.
  const bare = host.startsWith("[") && host.endsWith("]")
    ? host.slice(1, -1).toLowerCase()
    : host.toLowerCase();

  if (bare.includes(":")) {
    // IPv6: ::1 loopback, fe80::/10 link-local, fc00::/7 unique-local, ::
    return (
      bare === "::1" ||
      bare === "::" ||
      bare.startsWith("fe8") || bare.startsWith("fe9") ||
      bare.startsWith("fea") || bare.startsWith("feb") ||
      bare.startsWith("fc") || bare.startsWith("fd")
    );
  }

  const octets = bare.split(".");
  if (octets.length !== 4 || !octets.every(o => /^\d{1,3}$/.test(o))) return false;
  const [a, b] = octets.map(Number);
  if (octets.map(Number).some(n => n > 255)) return true;   // malformed -> closed
  if (a === 127 || a === 0) return true;                    // loopback, unspecified
  if (a === 10) return true;                                // private
  if (a === 172 && b >= 16 && b <= 31) return true;         // private
  if (a === 192 && b === 168) return true;                  // private
  if (a === 169 && b === 254) return true;                  // link-local + metadata
  return false;
}

/**
 * Fail closed: anything not positively recognised as a public host is treated
 * as unpublished, and the tunnel line is shown instead. Being wrong in that
 * direction costs a reader one extra step; being wrong the other way puts back
 * the dead link this whole change removes.
 */
function isPublished(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;

  const host = parsed.hostname;
  if (host === "") return false;
  if (UNREACHABLE.has(host.toLowerCase())) return false;
  if (isNonPublicAddress(host)) return false;

  // A single-label host — `grafana`, `jaeger`, `my-box` — resolves only inside
  // the Docker network or someone's search domain, never from a browser on the
  // internet. A published service has a dotted name.
  if (!host.includes(".") && !host.startsWith("[")) return false;

  return true;
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
