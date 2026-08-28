// Local stand-in for Vercel's edge + static routing, so the negotiation the
// site will actually perform can be exercised without a deployment.
//
// It serves `site/dist` the way vercel.json asks for it (cleanUrls,
// trailingSlash: false, 404.html for unknown paths) and drives the same
// planner the middleware drives (edge/negotiate.mjs), which is the point: an
// end-to-end assertion here is an assertion about the deployed behaviour, not
// about a second implementation of it.
//
// Not deployed. Used by edge/negotiate.e2e.test.mjs and available for manual
// checks:  node edge/preview-server.mjs [port] [distDir]

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

import { PROBE_HEADER, notAcceptableBody, planAfterProbe, planRequest } from "./negotiate.mjs";

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

async function readIfFile(path) {
  try {
    const info = await stat(path);
    if (!info.isFile()) return null;
    return await readFile(path);
  } catch {
    return null;
  }
}

/** vercel.json: cleanUrls + trailingSlash:false over a static Astro build. */
async function resolveStatic(dist, pathname) {
  const decoded = decodeURIComponent(pathname);
  if (decoded.includes("..")) return null;
  const safe = normalize(decoded);
  const candidates = extname(safe)
    ? [join(dist, safe)]
    : [join(dist, safe, "index.html"), join(dist, `${safe}.html`)];
  for (const candidate of candidates) {
    const body = await readIfFile(candidate);
    if (body) return { body, path: candidate };
  }
  return null;
}

export function createPreviewServer(dist) {
  return createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const accept = req.headers.accept ?? null;

    const send = (status, body, headers) => {
      res.writeHead(status, headers);
      res.end(req.method === "HEAD" ? undefined : body);
    };

    const sendStatic = async (pathname, status, extraHeaders = {}) => {
      const hit = await resolveStatic(dist, pathname);
      if (!hit) return send(404, "not found", { "content-type": "text/plain" });
      return send(status, hit.body, {
        "content-type": CONTENT_TYPES[extname(hit.path)] ?? "application/octet-stream",
        ...extraHeaders,
      });
    };

    const sendMarkdown = async (file, status) => {
      const hit = await resolveStatic(dist, file);
      if (!hit) return send(status, `# ${status}\n`, { "content-type": "text/markdown; charset=utf-8", vary: "Accept" });
      return send(status, hit.body, { "content-type": "text/markdown; charset=utf-8", vary: "Accept" });
    };

    const notAcceptable = () =>
      send(406, notAcceptableBody(), { "content-type": "text/markdown; charset=utf-8", vary: "Accept" });

    // Static files with an extension bypass middleware, exactly as the matcher does.
    if (extname(url.pathname)) return sendStatic(url.pathname, 200);

    const plan = planRequest({
      method: req.method,
      pathname: url.pathname,
      accept,
      isProbe: req.headers[PROBE_HEADER] !== undefined,
    });

    switch (plan.action) {
      case "not-acceptable":
        return notAcceptable();
      case "markdown":
        return sendMarkdown(plan.file, plan.status ?? 200);
      case "probe":
      case "html":
      case "pass":
      default: {
        const hit = await resolveStatic(dist, url.pathname);
        if (plan.action === "probe") {
          const after = planAfterProbe({ accept, status: hit ? 200 : 404 });
          if (after.action === "markdown") return sendMarkdown(after.file, after.status ?? 200);
          if (after.action === "not-acceptable") return notAcceptable();
        }
        if (!hit) return sendStatic("/404.html", 404, { vary: "Accept" });
        return send(200, hit.body, {
          "content-type": CONTENT_TYPES[extname(hit.path)] ?? "text/html; charset=utf-8",
          ...(plan.action === "pass" ? {} : { vary: "Accept" }),
        });
      }
    }
  });
}

if (process.argv[1] && import.meta.url.endsWith("preview-server.mjs") && process.argv[1].endsWith("preview-server.mjs")) {
  const port = Number(process.argv[2] ?? 4321);
  const dist = process.argv[3] ?? fileURLToPath(new URL("../site/dist", import.meta.url));
  createPreviewServer(dist).listen(port, () => console.log(`preview: http://localhost:${port} (${dist})`));
}
