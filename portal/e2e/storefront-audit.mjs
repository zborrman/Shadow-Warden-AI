// Storefront accessibility and machine-readability audit (M2M plan, stage M6).
//
// Drives the built portal against e2e/mock-gateway.mjs through a buyer's whole
// path, in a desktop and a phone viewport, and fails on:
//   - any axe-core violation of WCAG 2.1 A/AA rules with serious or critical impact;
//   - a page wider than the viewport (horizontal scroll);
//   - missing or malformed schema.org JSON-LD on the catalog and product pages;
//   - a sitemap or robots.txt that lists private pages or omits public ones.
//
//   PORTAL_URL=http://127.0.0.1:3017 node e2e/storefront-audit.mjs
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'
import AxeBuilder from '@axe-core/playwright'

const BASE = (process.env.PORTAL_URL || 'http://127.0.0.1:3017').replace(/\/$/, '')
const fx = JSON.parse(readFileSync(new URL('./fixtures/storefront.json', import.meta.url), 'utf8'))
const SLUG = fx.slug
const product = fx.feed.products[0]
const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

const failures = []
const fail = (where, msg) => failures.push(`${where}: ${msg}`)

async function axe(page, where) {
  const { violations } = await new AxeBuilder({ page }).withTags(WCAG).analyze()
  for (const v of violations.filter(v => v.impact === 'serious' || v.impact === 'critical')) {
    fail(where, `axe ${v.id} (${v.impact}) — ${v.help}; ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`)
  }
  console.log(`  axe ${where}: ${violations.length} violation(s), all impacts`)
}

async function noHorizontalScroll(page, where) {
  const wide = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)
  if (wide) fail(where, 'page is wider than the viewport')
}

async function jsonLd(page, where, type) {
  const blocks = await page.locator('script[type="application/ld+json"]').allTextContents()
  const parsed = []
  for (const b of blocks) {
    try { parsed.push(JSON.parse(b)) } catch { fail(where, 'JSON-LD block does not parse') }
  }
  const hit = parsed.find(d => d['@type'] === type)
  if (!hit) return fail(where, `no ${type} JSON-LD`)
  if (type === 'Product') {
    if (!Array.isArray(hit.offers) || hit.offers.length !== product.prices.length) fail(where, 'one Offer per price expected')
    if (hit.aggregateRating || hit.review) fail(where, 'ratings or reviews emitted: nothing measures them')
    for (const o of hit.offers ?? []) {
      if (!/^\d+(\.\d+)?$/.test(String(o.price))) fail(where, `offer price ${o.price} is not a decimal`)
    }
  }
}

const VIEWPORTS_DESKTOP = { width: 1280, height: 900 }

async function run(viewport, label) {
  const browser = await chromium.launch()
  const ctx = await browser.newContext({ viewport, locale: 'en-US' })
  const page = await ctx.newPage()
  const at = name => `${label} ${name}`

  await page.goto(`${BASE}/s/${SLUG}/`)
  await page.getByRole('heading', { level: 1 }).first().waitFor()
  await axe(page, at('catalog'))
  await noHorizontalScroll(page, at('catalog'))
  await jsonLd(page, at('catalog'), 'OnlineStore')

  await page.goto(`${BASE}/s/${SLUG}/p/${product.id}/`)
  await page.getByRole('heading', { level: 1 }).first().waitFor()
  await axe(page, at('product'))
  await noHorizontalScroll(page, at('product'))
  await jsonLd(page, at('product'), 'Product')
  await page.getByRole('button', { name: /add to cart/i }).click()

  await page.goto(`${BASE}/s/${SLUG}/cart/`)
  await page.getByLabel(/destination country/i).fill('DE')
  await page.getByRole('button', { name: /calculate shipping/i }).click()
  await page.getByLabel(/full name/i).waitFor()
  await axe(page, at('cart with checkout form'))
  await noHorizontalScroll(page, at('cart'))

  await page.getByLabel(/full name/i).fill('Audit Buyer')
  await page.getByLabel(/^email/i).fill('audit@example.org')
  await page.getByLabel(/^address$/i).fill('1 Audit Street')
  await page.getByLabel(/^city/i).fill('Berlin')
  await page.getByRole('button', { name: /send order request/i }).click()
  await page.waitForURL(/\/order\/.+#t=/)
  await page.getByRole('heading', { name: /order request/i }).waitFor()
  await axe(page, at('order request'))
  await noHorizontalScroll(page, at('order request'))

  // The same page once the seller has accepted and attached their payment link.
  const PAY_URL = 'https://buy.stripe.com/audit'
  await page.route(/\/order-requests\/[^/]+$/, async route => {
    const res = await route.fetch()
    await route.fulfill({ response: res, json: { ...(await res.json()), status: 'ACCEPTED', payment_url: PAY_URL } })
  })
  await page.reload()
  const pay = page.getByRole('link', { name: /go to payment/i })
  await pay.waitFor()
  if ((await pay.getAttribute('href')) !== PAY_URL) fail(at('payment link'), 'wrong href')
  if (!/noopener/.test((await pay.getAttribute('rel')) ?? '')) fail(at('payment link'), 'no rel=noopener')
  await axe(page, at('order with payment link'))
  await noHorizontalScroll(page, at('order with payment link'))
  await page.unroute(/\/order-requests\/[^/]+$/)

  // German, to catch a translation that overflows or loses a label.
  await ctx.addCookies([{ name: 'sf_lang', value: 'de', url: `${BASE}/s/` }])
  await page.goto(`${BASE}/s/${SLUG}/`)
  await page.getByRole('heading', { level: 1 }).first().waitFor()
  await axe(page, at('catalog (de)'))
  await noHorizontalScroll(page, at('catalog (de)'))

  await browser.close()
}

// A visitor who asks for less motion gets it through the accessibility widget, and
// everyone else keeps the animation.
async function reducedMotion() {
  const browser = await chromium.launch()
  const probe = async reducedMotion => {
    const ctx = await browser.newContext({ viewport: VIEWPORTS_DESKTOP, locale: 'en-US', reducedMotion })
    const page = await ctx.newPage()
    await page.goto(`${BASE}/s/${SLUG}/`)
    await page.waitForLoadState('networkidle')
    await page.locator('aside').first().waitFor()
    // public/accessibility-widget.js applies the preference once it has loaded.
    if (reducedMotion === 'reduce') {
      await page.waitForFunction(() => /-reduce-motion\b/.test(document.body.className))
    }
    const out = await page.evaluate(() => {
      const spinner = document.createElement('div')
      spinner.className = 'animate-spin'
      document.body.append(spinner)
      const s = getComputedStyle(spinner)
      return {
        sidebar: parseFloat(getComputedStyle(document.querySelector('aside')).transitionDuration),
        scroll: getComputedStyle(document.documentElement).scrollBehavior,
        spinIterations: s.animationIterationCount,
      }
    })
    await ctx.close()
    return out
  }
  const reduced = await probe('reduce')
  const normal = await probe('no-preference')
  await browser.close()
  console.log('  reduced motion:', JSON.stringify({ reduced, normal }))
  if (reduced.sidebar > 0.001) fail('reduced motion', `sidebar still transitions for ${reduced.sidebar}s`)
  if (reduced.scroll !== 'auto') fail('reduced motion', `scroll-behavior is ${reduced.scroll}`)
  if (reduced.spinIterations !== 'infinite') fail('reduced motion', 'the loading spinner stopped')
  if (normal.sidebar < 0.1) fail('reduced motion', 'the rule also removed motion for everyone else')
}

async function crawlFiles() {
  const sm = await fetch(`${BASE}/s/${SLUG}/sitemap.xml`)
  if (sm.status !== 200) return fail('sitemap', `status ${sm.status}`)
  const xml = await sm.text()
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1])
  if (locs.length !== 1 + fx.feed.products.length) fail('sitemap', `expected ${1 + fx.feed.products.length} URLs, got ${locs.length}`)
  if (locs.some(u => /\/(cart|order)\//.test(u))) fail('sitemap', 'lists a private page')
  const missing = await fetch(`${BASE}/s/no-such-store/sitemap.xml`)
  if (missing.status !== 404) fail('sitemap', `unknown store answered ${missing.status}`)

  const robots = await (await fetch(`${BASE}/robots.txt`)).text()
  for (const line of ['Allow: /s/', 'Disallow: /s/*/cart/', 'Disallow: /s/*/order/', 'Disallow: /']) {
    if (!robots.split('\n').map(l => l.trim()).includes(line)) fail('robots.txt', `missing "${line}"`)
  }
}

await run({ width: 1280, height: 900 }, 'desktop')
await run({ width: 375, height: 800 }, 'phone')
await reducedMotion()
await crawlFiles()

if (failures.length) {
  console.error(`\n${failures.length} storefront audit failure(s):`)
  for (const f of failures) console.error(`  - ${f}`)
  process.exit(1)
}
console.log('\nstorefront audit: no serious or critical WCAG 2.1 AA violations; JSON-LD, sitemap and robots.txt valid')
