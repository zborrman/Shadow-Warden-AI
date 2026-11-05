// Lighthouse floors for the public storefront (M2M plan, stage M6).
//
// Runs Lighthouse against the catalog and one product page of the built portal
// (served from e2e/mock-gateway.mjs fixtures) and fails below the floors.
// Performance is printed, not asserted: a shared CI runner's timing is noise,
// and no performance figure is published anywhere.
//
//   PORTAL_URL=http://127.0.0.1:3017 node e2e/lighthouse.mjs
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'

const BASE = (process.env.PORTAL_URL || 'http://127.0.0.1:3017').replace(/\/$/, '')
const LIGHTHOUSE = 'lighthouse@12.8.2'
const FLOORS = { accessibility: 0.95, 'best-practices': 0.9, seo: 0.95 }

const fx = JSON.parse(readFileSync(new URL('./fixtures/storefront.json', import.meta.url), 'utf8'))
const pages = {
  catalog: `${BASE}/s/${fx.slug}/`,
  product: `${BASE}/s/${fx.slug}/p/${fx.feed.products[0].id}/`,
}

const failures = []
for (const [name, url] of Object.entries(pages)) {
  const out = execFileSync('npx', [
    '-y', LIGHTHOUSE, url,
    `--chrome-path=${chromium.executablePath()}`,
    '--chrome-flags=--headless=new --no-sandbox',
    '--only-categories=performance,accessibility,best-practices,seo',
    '--output=json', '--output-path=stdout', '--quiet',
  ], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, shell: process.platform === 'win32' })
  const report = JSON.parse(out)
  const scores = Object.fromEntries(Object.entries(report.categories).map(([k, v]) => [k, v.score]))
  console.log(name, JSON.stringify(scores))
  for (const [cat, floor] of Object.entries(FLOORS)) {
    if ((scores[cat] ?? 0) >= floor) continue
    const misses = report.categories[cat].auditRefs
      .filter(r => r.weight > 0 && report.audits[r.id].score !== null && report.audits[r.id].score < 1)
      .map(r => r.id)
    failures.push(`${name}: ${cat} ${scores[cat]} < ${floor} (${misses.join(', ')})`)
  }
}

if (failures.length) {
  console.error(`\nLighthouse below floor:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log('\nLighthouse: accessibility, best practices and SEO at or above their floors')
