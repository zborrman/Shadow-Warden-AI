// The seller's whole path, against a real gateway and a real Postgres:
// register -> sign in -> create a store -> category -> shipping zone -> product
// -> the buyer orders on the storefront -> the seller accepts the order, sees the
// customer and writes in the journal -> settings (preferences + 2FA screen)
// -> export the data -> close the account, which then cannot sign in.
//
// Every step goes through the UI a person uses, so a button that does nothing,
// a form that never submits or a page that throws fails the build here instead
// of in front of a seller. Exit code 1 on the first failure, with a screenshot.
//
//   PORTAL_URL=http://localhost:3001 node e2e/seller-journey.mjs
import { mkdirSync } from 'node:fs'
import { chromium } from 'playwright'

const BASE = (process.env.PORTAL_URL || 'http://localhost:3001').replace(/\/$/, '')
const API = (process.env.API_URL || 'http://localhost:8001').replace(/\/$/, '')
const run = Date.now().toString(36)
const EMAIL = `seller-${run}@example.org`
const PASSWORD = `E2e-${run}-Passw0rd!`
const SLUG = `e2e-${run}`
const OUT = 'e2e-results'

let page
let step = ''
const errors = []

async function at(name, fn) {
  step = name
  const t = Date.now()
  await fn()
  console.log(`  ok  ${name} (${Date.now() - t} ms)`)
}

async function main() {
  const browser = await chromium.launch()
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } })
  page = await ctx.newPage()
  page.setDefaultTimeout(15_000)
  // A page that throws is a failure even when the step's assertion still passes.
  page.on('pageerror', e => errors.push(`${step}: ${e.message}`))

  await at('register', async () => {
    await page.goto(`${BASE}/register/`)
    await page.locator('input[name="email"]').fill(EMAIL)
    await page.locator('input[name="password"]').fill(PASSWORD)
    await page.locator('input[name="confirm"]').fill(PASSWORD)
    await page.getByRole('button', { name: /create account/i }).click()
    await page.waitForURL(/\/dashboard\/?$/)
  })

  await at('sign out and sign in again', async () => {
    await page.getByRole('button', { name: /sign out/i }).click()
    await page.waitForURL(/\/login\/?/)
    await page.locator('input[name="email"]').fill(EMAIL)
    await page.locator('input[name="password"]').fill(PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()
    await page.waitForURL(/\/dashboard\/?$/)
  })

  await at('create a store', async () => {
    await page.goto(`${BASE}/store/manage/`)
    await page.getByRole('button', { name: /new store/i }).first().click()
    await page.getByLabel(/^name/i).fill(`E2E Shop ${run}`)
    await page.getByLabel(/^address/i).fill(SLUG)
    await page.getByRole('button', { name: /create store/i }).click()
    await page.getByRole('heading', { name: 'Products' }).waitFor()
  })

  await at('add a category', async () => {
    await page.getByRole('button', { name: 'Categories' }).click()
    await page.getByLabel(/^name/i).fill('Colors')
    await page.getByRole('button', { name: /^add$/i }).click()
    // The new row shows its slug; the toast and the select do not.
    await page.getByText('colors', { exact: true }).waitFor()
  })

  await at('add a shipping zone', async () => {
    await page.getByRole('button', { name: 'Shipping' }).click()
    await page.getByLabel(/zone name/i).fill('Germany')
    await page.getByLabel(/^countries/i).fill('DE')
    await page.getByLabel(/^rate/i).fill('5')
    await page.getByRole('button', { name: /add zone/i }).click()
    await page.getByText('Germany').first().waitFor()
  })

  await at('create a product with a category and a unit', async () => {
    await page.getByRole('button', { name: 'Products' }).click()
    await page.getByRole('button', { name: /new product/i }).first().click()
    await page.getByLabel(/^name/i).fill('Red paint')
    await page.getByLabel(/^category/i).selectOption({ label: 'Colors' })
    await page.getByLabel(/^stock/i).fill('10')
    await page.getByLabel(/^unit/i).selectOption('l')
    await page.getByLabel(/^usd/i).fill('12.50')
    await page.getByLabel(/barcode \(gtin\)/i).fill('4006381333931')
    await page.getByRole('img', { name: /barcode 4006381333931/i }).waitFor()
    await page.getByRole('button', { name: /create product/i }).click()
    // A created product reopens in edit mode, where photos can be added.
    await page.getByText('Edit product').waitFor()
  })

  await at('print product labels (PDF)', async () => {
    await page.getByRole('button', { name: /close/i }).first().click()
    await page.getByRole('button', { name: /print labels/i }).click()
    const [pdf] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: /download pdf/i }).click(),
    ])
    if (!pdf.suggestedFilename().endsWith('.pdf')) throw new Error('labels are not a PDF')
  })

  await at('buyer orders on the storefront', async () => {
    const buyer = await ctx.newPage()
    buyer.on('pageerror', e => errors.push(`${step} (buyer): ${e.message}`))
    await buyer.goto(`${BASE}/s/${SLUG}/`)
    await buyer.getByText('Red paint').first().click()
    await buyer.getByRole('button', { name: /add to cart/i }).click()
    await buyer.goto(`${BASE}/s/${SLUG}/cart/`)
    await buyer.getByLabel(/destination country/i).fill('DE')
    await buyer.getByRole('button', { name: /calculate shipping/i }).click()
    await buyer.getByLabel(/full name/i).fill('Ada Buyer')
    await buyer.getByLabel(/^email/i).fill('ada@example.org')
    await buyer.getByLabel(/^address$/i).fill('1 Test Street')
    await buyer.getByLabel(/^city/i).fill('Berlin')
    await buyer.getByRole('button', { name: /send order request/i }).click()
    await buyer.waitForURL(/\/order\/.+#t=/)
    await buyer.close()
  })

  await at('seller accepts the order', async () => {
    await page.getByRole('button', { name: 'Orders' }).click()
    await page.getByText('Ada Buyer').first().waitFor()
    await page.getByRole('button', { name: /^accept$/i }).first().click()
    await page.getByText(/accepted/i).first().waitFor()
    const [label] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: /shipping label/i }).first().click(),
    ])
    if (!label.suggestedFilename().startsWith('shipping-label-')) throw new Error('no shipping label')
  })

  await at('customer card and journal', async () => {
    await page.getByRole('button', { name: 'Customers' }).click()
    await page.getByRole('button', { name: /ada buyer/i }).click()
    await page.getByLabel('Note', { exact: true }).fill('Prefers morning delivery')
    await page.getByRole('button', { name: /add note/i }).click()
    await page.getByText('Prefers morning delivery').first().waitFor()
    await page.getByText(/order request accepted/i).first().waitFor()
  })

  await at('settings: preferences and the 2FA screen', async () => {
    await page.goto(`${BASE}/settings/`)
    await page.getByLabel('Timezone').selectOption('Europe/Berlin')
    await page.getByRole('switch', { name: /24-hour/i }).waitFor()
    await page.getByRole('link', { name: /security/i }).click()
    await page.getByRole('button', { name: /set up/i }).click()
    await page.getByLabel(/qr code/i).waitFor()
    await page.getByRole('button', { name: /^cancel$/i }).click()
  })

  await at('export data, then close the account', async () => {
    await page.goto(`${BASE}/settings/#close`)
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: /export data/i }).click(),
    ])
    if (!download.suggestedFilename().endsWith('.json')) throw new Error('export is not a JSON file')
    await page.getByLabel('Password').fill(PASSWORD)
    await page.getByLabel(/type delete/i).fill('DELETE')
    await page.getByRole('button', { name: /close my account/i }).click()
    await page.waitForURL(/\/login\/?/)
  })

  await at('a closed account cannot sign in, and its storefront is gone', async () => {
    await page.locator('input[name="email"]').fill(EMAIL)
    await page.locator('input[name="password"]').fill(PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()
    await page.getByText(/invalid email or password/i).waitFor()
    // The gateway is asked, not the page: storefront pages are cached for 60 s
    // (ISR), so the rendered page outlives the store by up to that long.
    const r = await fetch(`${API}/m2m-store/storefront/${SLUG}`)
    if (r.status !== 404) throw new Error(`the store still answers (${r.status})`)
  })

  await browser.close()
  if (errors.length) {
    console.error('Page errors:\n' + errors.join('\n'))
    process.exit(1)
  }
  console.log('Seller journey passed.')
}

main().catch(async e => {
  console.error(`FAILED at "${step}": ${e.message.split('\n')[0]}`)
  if (errors.length) console.error('Page errors:\n' + errors.join('\n'))
  try {
    mkdirSync(OUT, { recursive: true })
    await page?.screenshot({ path: `${OUT}/seller-journey-failure.png`, fullPage: true })
    console.error(`Screenshot: ${OUT}/seller-journey-failure.png`)
  } catch { /* the browser may already be gone */ }
  process.exit(1)
})
