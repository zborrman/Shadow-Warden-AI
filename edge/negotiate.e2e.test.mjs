// node --test edge/negotiate.e2e.test.mjs
//
// End-to-end over the real built site (site/dist), through the same planner the
// Vercel middleware runs. This is the check that would have caught the audit
// finding: `Accept: text/markdown` returning `text/html` with no `Vary`.
//
// Skips when site/dist has not been built.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { createPreviewServer } from "./preview-server.mjs";

const DIST = fileURLToPath(new URL("../site/dist", import.meta.url));
const built = existsSync(DIST);

describe("agent readiness over the built site", { skip: built ? false : "site/dist not built" }, () => {
  let server;
  let base;

  before(async () => {
    server = createPreviewServer(DIST);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => server?.close());

  const get = (path, accept) =>
    fetch(`${base}${path}`, accept === undefined ? undefined : { headers: { accept } });

  test("the homepage serves markdown to a markdown client, with Vary", async () => {
    const response = await get("/", "text/markdown");
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "text/markdown; charset=utf-8");
    assert.equal(response.headers.get("vary"), "Accept");
    const body = await response.text();
    assert.match(body, /^# Shadow Warden AI/);
  });

  test("the homepage still serves HTML to a browser, with Vary", async () => {
    const response = await get(
      "/",
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    );
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /text\/html/);
    assert.equal(response.headers.get("vary"), "Accept");
    assert.match(await response.text(), /<!DOCTYPE html>/i);
  });

  test("curl's default */* is not a markdown request", async () => {
    const response = await get("/", "*/*");
    assert.match(response.headers.get("content-type"), /text\/html/);
  });

  test("every negotiated route has a markdown representation", async () => {
    const { MARKDOWN_ROUTES } = await import("./negotiate.mjs");
    for (const route of Object.keys(MARKDOWN_ROUTES)) {
      const response = await get(route, "text/markdown");
      assert.equal(response.status, 200, `${route} did not serve markdown`);
      assert.equal(response.headers.get("content-type"), "text/markdown; charset=utf-8", route);
      assert.ok((await response.text()).startsWith("#"), `${route} markdown has no heading`);
    }
  });

  test("an unknown path is a real 404 with a markdown recovery body", async () => {
    const response = await get("/no-such-path-xyz", "text/markdown");
    assert.equal(response.status, 404);
    assert.equal(response.headers.get("content-type"), "text/markdown; charset=utf-8");
    const body = await response.text();
    assert.match(body, /llms\.txt/);
    assert.match(body, /sitemap-index\.xml/);
  });

  test("an unknown path is a real 404 for a browser too, and points somewhere", async () => {
    const response = await get("/no-such-path-xyz", "text/html");
    assert.equal(response.status, 404);
    const body = await response.text();
    assert.match(body, /llms\.txt/);
    assert.match(body, /sitemap-index\.xml/);
    assert.match(body, /agent-instructions\.md/);
  });

  test("a client that accepts neither representation gets 406", async () => {
    const response = await get("/", "application/pdf");
    assert.equal(response.status, 406);
    assert.equal(response.headers.get("content-type"), "text/markdown; charset=utf-8");
    assert.match(await response.text(), /406 Not Acceptable/);
  });

  test("a page with no markdown form falls back to HTML rather than failing", async () => {
    const response = await get("/status", "text/markdown, text/html;q=0.5");
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /text\/html/);
  });

  test("machine-readable files are served and typed", async () => {
    for (const [path, type] of [
      ["/llms.txt", /text\/plain/],
      ["/index.md", /text\/markdown/],
      ["/.well-known/agent-instructions.md", /text\/markdown/],
      ["/.well-known/did.json", /application\/json/],
      ["/openapi.json", /application\/json/],
      ["/sitemap-index.xml", /xml/],
      ["/robots.txt", /text\/plain/],
    ]) {
      const response = await get(path, "*/*");
      assert.equal(response.status, 200, `${path} is missing`);
      assert.match(response.headers.get("content-type"), type, path);
    }
  });

  test("llms.txt tells an agent when to use this", async () => {
    const body = await (await get("/llms.txt", "*/*")).text();
    assert.match(body, /## When to use this/);
    assert.match(body, /agent-instructions\.md/);
  });

  test("the agent instructions name best-fit jobs and when not to use it", async () => {
    const body = await (await get("/.well-known/agent-instructions.md", "*/*")).text();
    assert.match(body, /## When to use this/);
    assert.match(body, /## When not to use this/);
    assert.match(body, /warden filter/);
  });
});
