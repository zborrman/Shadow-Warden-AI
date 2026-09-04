/**
 * Behavioural test for src/lib/internal-links.ts — run in CI, not by hand.
 *
 * The Python guard beside this (warden/tests/test_dashboard_links_resolve.py)
 * asserts that the validation *exists* by matching source text. That is worth
 * something and it is not enough: it passes just as happily if `isPublished()`
 * starts returning true for everything, as long as the markers stay in the
 * file. A check that reads source and calls it a verification is the same
 * defect this whole change set is about, one level up — so the table below
 * actually calls the function.
 *
 * Every case here was a real bypass at some point in review:
 *
 *   [::ffff:127.0.0.1]   `URL` canonicalises the hostname to `[::ffff:7f00:1]`,
 *                        which matched none of the v6 prefixes the original
 *                        deny-list checked.
 *   localhost.           the fully-qualified form: absent from the deny-list,
 *                        and dotted, so it passed the DNS-name test too.
 *   0x7f.1 / 2130706433  `URL` canonicalises both to 127.0.0.1.
 *
 * Run: npm run test:links
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const OUT = resolve(process.cwd(), ".tmp-links");
mkdirSync(OUT, { recursive: true });
// Emitted .js is ESM; without this node reparses it and warns on every run.
writeFileSync(resolve(OUT, "package.json"), '{"type":"module"}\n');

const { internalLink } = await import(
  pathToFileURL(resolve(OUT, "internal-links.js")).href
);

/** [input, expected kind] */
const CASES = [
  // unset and unparseable
  [undefined, "tunnel"],
  ["", "tunnel"],
  ["   ", "tunnel"],
  ["not a url", "tunnel"],
  // wrong scheme
  ["ftp://grafana.example.com", "tunnel"],
  ["javascript:alert(1)", "tunnel"],
  ["file:///etc/passwd", "tunnel"],
  // docker-internal single-label hosts
  ["http://grafana:3000", "tunnel"],
  ["http://jaeger:16686", "tunnel"],
  ["http://localhost:3000", "tunnel"],
  // trailing-dot forms of the same
  ["http://localhost.:3000", "tunnel"],
  ["http://grafana.:3000", "tunnel"],
  // loopback, every spelling URL accepts
  ["http://127.0.0.1:3001", "tunnel"],
  ["http://0x7f.1:3000", "tunnel"],
  ["http://2130706433:3000", "tunnel"],
  ["http://[::1]:3000", "tunnel"],
  ["http://[::ffff:127.0.0.1]:3000", "tunnel"],
  ["http://[::ffff:7f00:1]:3000", "tunnel"],
  // private, link-local, metadata
  ["http://10.0.0.5:3000", "tunnel"],
  ["http://192.168.1.10:3000", "tunnel"],
  ["http://172.20.0.3:3000", "tunnel"],
  ["http://169.254.169.254/latest/meta-data", "tunnel"],
  // any other address literal, public included — deliberate, see the module
  ["http://91.98.234.161:3000", "tunnel"],
  ["http://[2001:db8::1]:3000", "tunnel"],
  // what a published service actually looks like
  ["https://grafana.shadow-warden-ai.com", "link"],
  ["https://grafana.shadow-warden-ai.com.", "link"],
  ["https://grafana.shadow-warden-ai.com/d/x?orgId=1", "link"],
  ["http://jaeger.internal.example.org:8080", "link"],
];

let failed = 0;
for (const [input, want] of CASES) {
  const got = internalLink("Grafana", input).kind;
  if (got !== want) {
    failed++;
    console.error(`FAIL  want=${want}  got=${got}  input=${JSON.stringify(input)}`);
  }
}

if (failed > 0) {
  console.error(
    `\n${failed}/${CASES.length} internal-link cases failed.\n` +
      "A `tunnel` expectation that came back `link` means a host the visitor " +
      "cannot reach would render as a working link — the exact defect OB-F21 " +
      "removed. A `link` expectation that came back `tunnel` means a real " +
      "published vhost stopped being clickable."
  );
  process.exit(1);
}

console.log(`internal-links: ${CASES.length}/${CASES.length} cases pass`);
