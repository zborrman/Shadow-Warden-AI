// Content negotiation for `Accept: text/markdown` (https://acceptmarkdown.com).
//
// Pure functions, no imports: the middleware bundles this, and `node --test`
// exercises it directly (edge/negotiate.test.mjs). Everything that decides
// *which* representation to serve lives here so it can be tested without a
// deployment.
//
// The four conformance rules the spec states:
//   1. serve markdown for `Accept: text/markdown`
//   2. set `Vary: Accept`                     — the middleware does this on both branches
//   3. reject unsupported types with `406`
//   4. honour q-values
//
// Negotiation happens on the same URL that serves HTML. The `.md` files are
// also fetchable directly, which is a convenience, not the contract.

/**
 * Page route → markdown representation. A route absent from this map has no
 * markdown representation; a client that will accept nothing else gets a 406.
 */
export const MARKDOWN_ROUTES = Object.freeze({
  "/": "/index.md",
  "/pricing": "/pricing.md",
  "/price": "/pricing.md",
  "/doc": "/doc.md",
  "/sdk": "/sdk.md",
  "/agentic": "/agentic.md",
  "/trust": "/trust.md",
});

/** Served when the requested path does not exist at all. */
export const NOT_FOUND_MARKDOWN = "/404.md";

const MARKDOWN_TYPES = ["text/markdown", "text/x-markdown"];
const HTML_TYPES = ["text/html", "application/xhtml+xml"];

/**
 * Parse an Accept header into ranges. Malformed parameters are ignored rather
 * than throwing: a bad Accept header must never fail the request.
 *
 * @returns {{type: string, subtype: string, q: number}[]}
 */
export function parseAccept(header) {
  if (!header) return [];
  const ranges = [];
  for (const part of String(header).split(",")) {
    const [rawType, ...params] = part.split(";");
    const token = rawType.trim().toLowerCase();
    if (!token) continue;
    const slash = token.indexOf("/");
    const type = slash === -1 ? token : token.slice(0, slash);
    const subtype = slash === -1 ? "*" : token.slice(slash + 1);
    let q = 1;
    for (const param of params) {
      const eq = param.indexOf("=");
      if (eq === -1) continue;
      if (param.slice(0, eq).trim().toLowerCase() !== "q") continue;
      const parsed = Number.parseFloat(param.slice(eq + 1).trim());
      if (Number.isFinite(parsed)) q = Math.min(Math.max(parsed, 0), 1);
    }
    ranges.push({ type, subtype, q });
  }
  return ranges;
}

/**
 * Best {q, specificity} a set of media types scores against an Accept header.
 * Specificity follows RFC 9110 §12.5.1: `type/subtype` beats `type/*` beats
 * `*​/*`, and only breaks a tie between equal q-values.
 */
function score(ranges, mediaTypes) {
  let best = { q: 0, specificity: -1 };
  for (const media of mediaTypes) {
    const [type, subtype] = media.split("/");
    for (const range of ranges) {
      let specificity;
      if (range.type === type && range.subtype === subtype) specificity = 2;
      else if (range.type === type && range.subtype === "*") specificity = 1;
      else if (range.type === "*" && range.subtype === "*") specificity = 0;
      else continue;
      if (range.q > best.q || (range.q === best.q && specificity > best.specificity)) {
        best = { q: range.q, specificity };
      }
    }
  }
  return best;
}

/**
 * Which representation this client wants.
 *
 * `"html"`     — serve the page as it is today (the default for browsers, for
 *                `*​/*` clients such as curl, and for a missing Accept header)
 * `"markdown"` — the client asked for markdown, and asked for it more strongly
 *                than for HTML
 * `"none"`     — the client accepts neither, so the answer is 406
 *
 * @returns {"html"|"markdown"|"none"}
 */
export function chooseVariant(acceptHeader) {
  const ranges = parseAccept(acceptHeader);
  if (ranges.length === 0) return "html";

  const markdown = score(ranges, MARKDOWN_TYPES);
  const html = score(ranges, HTML_TYPES);

  if (markdown.q === 0 && html.q === 0) return "none";
  if (markdown.q > html.q) return "markdown";
  if (markdown.q < html.q) return "html";
  // Equal q: the more specific range wins. `*​/*` ties resolve to HTML, which
  // keeps every existing */* client (curl, most crawlers) on today's behaviour.
  return markdown.specificity > html.specificity ? "markdown" : "html";
}

/** Trailing slashes and casing are not meaningful for these routes. */
export function normalizePath(pathname) {
  if (!pathname) return "/";
  let path = pathname.toLowerCase();
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  return path || "/";
}

/** The markdown file for a page route, or `null` if it has no markdown form. */
export function markdownPathFor(pathname) {
  return MARKDOWN_ROUTES[normalizePath(pathname)] ?? null;
}

/** Body returned with a 406, itself markdown so the client can read the way out. */
export function notAcceptableBody() {
  const routes = [...new Set(Object.values(MARKDOWN_ROUTES))].sort();
  return [
    "# 406 Not Acceptable",
    "",
    "This URL can be served as `text/html` or `text/markdown`. Your `Accept`",
    "header asked for neither, or this page has no markdown representation.",
    "",
    "Markdown is available at:",
    "",
    ...routes.map((route) => `- https://shadow-warden-ai.com${route}`),
    "",
    "Site index for machines: https://shadow-warden-ai.com/llms.txt",
    "Agent instructions: https://shadow-warden-ai.com/.well-known/agent-instructions.md",
    "",
  ].join("\n");
}

// ── Request planning ─────────────────────────────────────────────────────────
// The middleware (middleware.ts) and the local preview harness
// (edge/preview-server.mjs) both drive these, so what CI exercises and what
// Vercel runs cannot drift apart.

/** Header set on the internal existence probe so it cannot recurse. */
export const PROBE_HEADER = "x-swa-md-probe";

/**
 * What to do with a request, before knowing whether the path exists.
 *
 * @returns one of
 *   {action:"pass"}                     serve normally, no negotiation
 *   {action:"html"}                     serve HTML, add `Vary: Accept`
 *   {action:"markdown", file}           serve this markdown file with 200
 *   {action:"not-acceptable"}           406
 *   {action:"probe"}                    ask whether the path exists, then call
 *                                       planAfterProbe()
 */
export function planRequest({ method = "GET", pathname = "/", accept = null, isProbe = false } = {}) {
  if (isProbe) return { action: "pass" };
  if (method !== "GET" && method !== "HEAD") return { action: "pass" };
  if (pathname === "/api" || pathname.startsWith("/api/")) return { action: "pass" };

  const variant = chooseVariant(accept);
  if (variant === "none") return { action: "not-acceptable" };
  if (variant === "html") return { action: "html" };

  const file = markdownPathFor(pathname);
  if (file) return { action: "markdown", file };
  return { action: "probe" };
}

/**
 * What to do once the probe has answered. A path that does not exist earns a
 * markdown 404 body; a path that exists but has no markdown form falls back to
 * HTML, or to 406 for a client that will not take HTML.
 */
export function planAfterProbe({ accept = null, status = 200 } = {}) {
  if (status === 404) return { action: "markdown", file: NOT_FOUND_MARKDOWN, status: 404 };
  return chooseVariant(accept) === "none"
    ? { action: "not-acceptable" }
    : { action: "html" };
}
