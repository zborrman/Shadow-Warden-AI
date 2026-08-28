// node --test edge/
//
// The negotiation rules from https://acceptmarkdown.com, pinned. These run
// without a deployment, which is the point: the only other way to find out that
// `*/*` started resolving to markdown is for a browser to download the homepage.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MARKDOWN_ROUTES,
  chooseVariant,
  markdownPathFor,
  normalizePath,
  notAcceptableBody,
  parseAccept,
} from "./negotiate.mjs";

test("an explicit markdown request gets markdown", () => {
  assert.equal(chooseVariant("text/markdown"), "markdown");
  assert.equal(chooseVariant("text/x-markdown"), "markdown");
  assert.equal(chooseVariant("text/markdown; charset=utf-8"), "markdown");
});

test("browsers keep getting HTML", () => {
  const chrome =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
  assert.equal(chooseVariant(chrome), "html");
  assert.equal(chooseVariant("text/html"), "html");
});

test("a wildcard is not a request for markdown", () => {
  // curl, most crawlers, and every client that never thought about it.
  assert.equal(chooseVariant("*/*"), "html");
  assert.equal(chooseVariant("text/*"), "html");
  assert.equal(chooseVariant(null), "html");
  assert.equal(chooseVariant(""), "html");
});

test("q-values decide when both are named", () => {
  assert.equal(chooseVariant("text/markdown;q=0.1, text/html;q=0.9"), "html");
  assert.equal(chooseVariant("text/markdown;q=0.9, text/html;q=0.1"), "markdown");
  assert.equal(chooseVariant("text/html;q=0, text/markdown"), "markdown");
});

test("markdown named explicitly beats HTML matched by a wildcard", () => {
  assert.equal(chooseVariant("text/markdown, */*"), "markdown");
});

test("equal q and equal specificity resolves to HTML", () => {
  assert.equal(chooseVariant("text/markdown, text/html"), "html");
});

test("a client that accepts neither gets 406", () => {
  assert.equal(chooseVariant("application/pdf"), "none");
  assert.equal(chooseVariant("image/png, image/jpeg"), "none");
  assert.equal(chooseVariant("text/html;q=0, text/markdown;q=0"), "none");
});

test("q=0 on a wildcard rejects everything it covers", () => {
  assert.equal(chooseVariant("*/*;q=0"), "none");
});

test("a malformed Accept header never throws and never blocks", () => {
  for (const header of [";;;", "text/", "/html", "text/html;q=banana", ",,,"]) {
    assert.doesNotThrow(() => chooseVariant(header));
    assert.notEqual(chooseVariant(header), "markdown");
  }
  // q=banana is unparseable, so the range keeps the default q=1.
  assert.equal(chooseVariant("text/html;q=banana"), "html");
});

test("q-values are clamped to the 0..1 range", () => {
  assert.deepEqual(parseAccept("text/html;q=5"), [{ type: "text", subtype: "html", q: 1 }]);
  assert.deepEqual(parseAccept("text/html;q=-2"), [{ type: "text", subtype: "html", q: 0 }]);
});

test("routes resolve regardless of trailing slash or case", () => {
  assert.equal(markdownPathFor("/"), "/index.md");
  assert.equal(markdownPathFor("/pricing"), "/pricing.md");
  assert.equal(markdownPathFor("/pricing/"), "/pricing.md");
  assert.equal(markdownPathFor("/Pricing"), "/pricing.md");
  assert.equal(markdownPathFor("/price"), "/pricing.md");
  assert.equal(normalizePath(""), "/");
});

test("an unmapped route has no markdown representation", () => {
  assert.equal(markdownPathFor("/community"), null);
  assert.equal(markdownPathFor("/nope"), null);
});

test("every mapped route points at a .md path", () => {
  for (const [route, file] of Object.entries(MARKDOWN_ROUTES)) {
    assert.ok(route.startsWith("/"), `${route} is not absolute`);
    assert.ok(file.endsWith(".md"), `${file} is not markdown`);
  }
});

test("the 406 body is itself markdown and names a way out", () => {
  const body = notAcceptableBody();
  assert.match(body, /^# 406 Not Acceptable/);
  assert.match(body, /llms\.txt/);
  assert.match(body, /agent-instructions\.md/);
});
