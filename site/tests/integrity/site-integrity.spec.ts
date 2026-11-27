// Site integrity sweep: every static Astro route is opened in a browser and must
// answer < 400, make no failing same-origin request, log no console error, throw
// no uncaught exception, and leave no secret in `window` or Web Storage.
//
// Kept apart from tests/e2e (the 37-assertion suite CI ratchets with
// E2E_MIN_TESTS): run it with its own config, against a local build or a deploy:
//   PLAYWRIGHT_BASE_URL=http://localhost:4321 npx playwright test -c playwright.integrity.config.ts
// Routes come from src/pages, so a new page is covered without editing this file;
// dynamic routes ([slug]) need an entry in EXTRA_ROUTES.
import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const BASE_URL = (process.env.PLAYWRIGHT_BASE_URL || process.env.BASE_URL || 'http://localhost:4321').replace(/\/$/, '');
const PAGES = path.join(process.cwd(), 'src', 'pages');
const EXTRA_ROUTES: string[] = [];

// Console noise that is not a defect of the page, each with its reason. Keep it short.
const ALLOWED_CONSOLE: [RegExp, string][] = [
  // A local build calls the production API, which (correctly) does not allow
  // a localhost origin. On the deployed site the same request is same-site.
  [/blocked by CORS policy|Failed to load resource: net::ERR_FAILED/i, 'cross-origin API call from a local origin'],
];

function discoverRoutes(): string[] {
  const routes = new Set<string>();
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      const rel = path.relative(PAGES, full).split(path.sep).join('/');
      const m = rel.match(/^(.*)\.astro$/);
      if (!m || rel.includes('[') || m[1].split('/').some(s => s.startsWith('_'))) continue;
      const route = m[1] === 'index' ? '/' : `/${m[1].replace(/\/index$/, '')}`;
      routes.add(route);
    }
  };
  walk(PAGES);
  EXTRA_ROUTES.forEach(r => routes.add(r));
  return [...routes].sort();
}

const ROUTES = discoverRoutes();

test.describe('Site integrity: status, requests, console, secrets', () => {
  test('route discovery found the site', () => {
    expect(ROUTES.length, 'no routes discovered under src/pages').toBeGreaterThan(20);
  });

  for (const route of ROUTES) {
    test(`route ${route}`, async ({ page }) => {
      const consoleErrors: string[] = [];
      const pageErrors: string[] = [];
      const failed: string[] = [];

      page.on('console', msg => {
        if (msg.type() !== 'error') return;
        const text = msg.text();
        if (!ALLOWED_CONSOLE.some(([re]) => re.test(text))) consoleErrors.push(text.slice(0, 300));
      });
      page.on('pageerror', err => pageErrors.push(err.message.slice(0, 300)));
      page.on('response', res => {
        if (res.url().startsWith(BASE_URL) && res.status() >= 400) failed.push(`${res.status()} ${res.url()}`);
      });

      const response = await page.goto(`${BASE_URL}${route}`, { waitUntil: 'networkidle', timeout: 45_000 });
      expect(response, `no response from ${route}`).not.toBeNull();
      expect(response!.status(), `HTTP status of ${route}`).toBeLessThan(400);

      const leaks = await page.evaluate(() => {
        const findings: string[] = [];
        const patterns: [string, RegExp][] = [
          ['OpenAI key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/],
          ['Anthropic key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
          ['AWS key', /\bAKIA[0-9A-Z]{16}\b/],
          ['Stripe live secret', /\bsk_live_[0-9a-zA-Z]{24,}\b/],
          ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
          ['DB URI with credentials', /(?:postgres(?:ql)?|mongodb|mysql|redis):\/\/[^:\s/]+:[^@\s]+@/i],
          ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
        ];
        const suspiciousKey = /(?:SECRET|PRIVATE_KEY|DB_PASSWORD|SERVICE_ROLE|API_KEY)/i;
        const scan = (v: unknown, where: string, depth = 0, seen = new WeakSet<object>()) => {
          if (depth > 4 || v == null) return;
          if (typeof v === 'string') { for (const [n, re] of patterns) if (re.test(v)) findings.push(`${n} in ${where}`); return; }
          if (typeof v !== 'object' || seen.has(v as object)) return;
          seen.add(v as object);
          for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
            if (suspiciousKey.test(k) && typeof x === 'string' && x.length > 0) findings.push(`suspicious key "${k}" in ${where}`);
            scan(x, `${where}.${k}`, depth + 1, seen);
          }
        };
        const builtin = new Set(Object.getOwnPropertyNames(Window.prototype));
        const blank = document.createElement('iframe');
        blank.style.display = 'none';
        document.body.appendChild(blank);
        const pristine = new Set(Object.keys(blank.contentWindow as Window));
        blank.remove();
        for (const key of Object.keys(window)) {
          if (builtin.has(key) || pristine.has(key)) continue;
          try {
            if (suspiciousKey.test(key)) findings.push(`suspicious global window.${key}`);
            scan((window as unknown as Record<string, unknown>)[key], `window.${key}`);
          } catch { /* cross-origin frame or throwing getter */ }
        }
        for (const [name, store] of [['localStorage', localStorage], ['sessionStorage', sessionStorage]] as const) {
          for (let i = 0; i < store.length; i++) {
            const k = store.key(i);
            if (!k) continue;
            const val = store.getItem(k) || '';
            for (const [n, re] of patterns) if (re.test(val)) findings.push(`${n} in ${name}["${k}"]`);
          }
        }
        return [...new Set(findings)];
      });

      expect(failed, `failing same-origin requests on ${route}`).toEqual([]);
      expect(consoleErrors, `console errors on ${route}`).toEqual([]);
      expect(pageErrors, `uncaught exceptions on ${route}`).toEqual([]);
      expect(leaks, `secrets exposed in the browser on ${route}`).toEqual([]);
    });
  }
});
