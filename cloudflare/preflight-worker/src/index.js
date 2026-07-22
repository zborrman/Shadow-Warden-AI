/**
 * Shadow Warden AI — Cloudflare Preflight Worker
 *
 * Runs at the edge (api.shadow-warden-ai.com/*) before requests reach the
 * warden backend. Enforces:
 *   1. Payload size gate — reject POST/PUT bodies > 1 MB (413)
 *   2. Content-Type enforcement on /filter + /mcp routes (415)
 *   3. Header forwarding — CF-Ray → X-CF-Ray for distributed tracing
 *   4. Pass-through with rate-limit bypass header for health probes
 *
 * Fail-open: any unexpected error falls through to the origin unchanged.
 */

const MAX_BODY_BYTES = 1_048_576; // 1 MB

// Routes that MUST have Content-Type: application/json
const JSON_REQUIRED_PREFIXES = ["/filter", "/mcp", "/agent/", "/staff/"];

// Health + readiness probes — always pass through
const PASSTHROUGH_PATHS = new Set(["/_preflight", "/health", "/health/pipeline"]);

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Always pass through health probes
      if (PASSTHROUGH_PATHS.has(path)) {
        return fetch(request);
      }

      const isBodyMethod = request.method === "POST" || request.method === "PUT";
      const requiresJson =
        isBodyMethod &&
        JSON_REQUIRED_PREFIXES.some((prefix) => path.startsWith(prefix));

      // ── 1. Payload size gate ────────────────────────────────────────────────
      // Content-Length is client-supplied and absent entirely on a chunked
      // (Transfer-Encoding: chunked) upload — trusting it alone lets an attacker
      // stream an unbounded body straight past this gate. A declared length is
      // checked here; an undeclared one is rejected outright on the guarded API
      // routes, where every legitimate client sends a buffered JSON body.
      if (isBodyMethod) {
        const rawLength = request.headers.get("content-length");
        const contentLength = parseInt(rawLength || "0", 10);

        if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
          return jsonError(413, "payload_too_large", {
            max_bytes: MAX_BODY_BYTES,
            received_bytes: contentLength,
          });
        }

        if (requiresJson && (rawLength === null || !Number.isFinite(contentLength))) {
          return jsonError(411, "length_required", {
            detail: "Content-Length is required; chunked bodies are not accepted",
          });
        }
      }

      // ── 2. Content-Type enforcement ─────────────────────────────────────────
      if (requiresJson) {
        const ct = request.headers.get("content-type") || "";
        if (!ct.includes("application/json") && !ct.includes("multipart/form-data")) {
          return jsonError(415, "unsupported_media_type", {
            required: "application/json",
            received: ct || "(none)",
          });
        }
      }

      // ── 3. Forward CF-Ray for distributed tracing ───────────────────────────
      const headers = new Headers(request.headers);
      const cfRay = request.headers.get("cf-ray") || "";
      if (cfRay) {
        headers.set("X-CF-Ray", cfRay);
      }

      // Forward real client IP so warden can use it for ERS / shadow ban.
      // Only CF-Connecting-IP is authoritative here — Cloudflare overwrites it
      // at the edge on every request. X-Forwarded-For is client-supplied and
      // must never be promoted into an identity header.
      const clientIp = request.headers.get("cf-connecting-ip") || "";
      if (clientIp) {
        headers.set("X-Real-IP", clientIp);
      } else {
        headers.delete("X-Real-IP");
      }

      return fetch(new Request(request, { headers }));
    } catch (err) {
      // Fail-open: unexpected errors never block traffic
      console.error("preflight error (fail-open):", err);
      return fetch(request);
    }
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function jsonError(status, code, detail = {}) {
  return new Response(
    JSON.stringify({ error: code, ...detail }),
    {
      status,
      headers: {
        "Content-Type": "application/json",
        "X-Preflight-Rejected": "true",
      },
    },
  );
}
