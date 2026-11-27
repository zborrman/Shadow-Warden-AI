/**
 * Shadow Warden AI — Exhaustive E2E Test Suite
 *
 * Covers:
 *   1. Global navigation & CSS hover dropdowns
 *   2. 6-step community creation wizard (state machine)
 *   3. /agentic marketplace dashboard — buttons and Chart.js canvases
 *
 * Run against production:  npx playwright test
 * Run against local dev:   PLAYWRIGHT_BASE_URL=http://localhost:4321 npx playwright test
 */
import { test, expect, Page } from '@playwright/test';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Open the sidebar hub matching `label` and return its item list. The desktop
 * nav is a sidebar inside <header id="navbar">: each hub is a section whose
 * list opens from a chevron (it was a hover dropdown before 2026-11-25).
 */
async function hoverNavItem(page: Page, label: string) {
  const hub = page.locator(`#navbar [data-hub="${label}"]`);
  const trigger = hub.locator('a.sw-hub__link');
  await trigger.hover();
  const toggle = hub.locator('.sw-hub__toggle');
  if ((await toggle.getAttribute('aria-expanded')) !== 'true') await toggle.click();
  const dropdown = hub.locator('[data-hub-list]');
  return { trigger, dropdown };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Global Navigation & Dropdowns
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Global Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Dismiss the fixed top banner if present so it doesn't cover nav clicks
    const banner = page.locator('#banner-close');
    if (await banner.isVisible().catch(() => false)) await banner.click();
  });

  // ── Desktop nav visible ────────────────────────────────────────────────────
  test('navbar renders with logo', async ({ page }) => {
    await expect(page.locator('#navbar')).toBeVisible();
    await expect(page.locator('#navbar img[alt*="Shadow Warden"]')).toBeVisible();
  });

  // ── Protect hub ──────────────────────────────────────────────────────────────
  test('Protect dropdown shows sub-items on hover', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Protect');
    await expect(dropdown).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Security Pipeline' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Agentic SOC' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Playground' })).toBeVisible();
  });

  test('Protect → Agentic SOC link has correct href', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Protect');
    await expect(dropdown).toBeVisible();
    const link = dropdown.locator('a', { hasText: 'Agentic SOC' });
    await expect(link).toHaveAttribute('href', '/cyber-security/agentic-soc');
  });

  // ── Govern hub ───────────────────────────────────────────────────────────────
  test('Govern dropdown shows Trust Center and the live dashboards', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Govern');
    await expect(dropdown).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Trust Center' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Compliance & Privacy' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Live — Service Health' })).toBeVisible();
  });

  test('Govern → live dashboard links point at the public metrics host', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Govern');
    const link = dropdown.locator('a', { hasText: 'Live — Service Health' });
    await expect(link).toHaveAttribute('href', /^https:\/\/metrics\.shadow-warden-ai\.com\/public-dashboards\//);
  });

  // ── Trade hub ────────────────────────────────────────────────────────────────
  test('Trade dropdown shows business community, store and tunnel', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Trade');
    await expect(dropdown).toBeVisible();
    // Labels follow BaseLayout.astro's Trade menu. "Agentic Commerce" was
    // renamed to "Agentic Marketplace" when the M2M Commerce Store got its own
    // entry (M0, #666) and this expectation was left behind — it has failed
    // against production every night since.
    // /agentic and /community were retired on 2026-11-27.
    await expect(dropdown.locator('a', { hasText: 'Agentic Marketplace' })).toHaveCount(0);
    await expect(dropdown.locator('a', { hasText: 'M2M Commerce Store' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Business Community' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'MASQUE Tunnels' })).toBeVisible();
  });

  test('Trade → MASQUE Tunnels link has correct href', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Trade');
    const link = dropdown.locator('a', { hasText: 'MASQUE Tunnels' });
    await expect(link).toHaveAttribute('href', '/tunnel/masque-tunnels');
  });

  // ── Hub links ──────────────────────────────────────────────────────────────
  test('static nav links are present and have correct hrefs', async ({ page }) => {
    const nav = page.locator('#navbar nav');
    const checks: [string, string][] = [
      ['Protect', '/cyber-security'],
      ['Govern',  '/trust'],
      ['Trade',   '/business-community'],
      ['Build',   '/doc'],
      ['Account', '/price'],
    ];
    for (const [label, href] of checks) {
      await expect(nav.locator('a', { hasText: label }).first()).toHaveAttribute('href', href);
    }
  });

  test('GitHub link opens in new tab', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'GitHub link lives in the desktop nav (hidden behind hamburger on mobile)');
    const gh = page.locator('#navbar a[href*="github.com"]');
    await expect(gh).toBeVisible();
    await expect(gh).toHaveAttribute('target', '_blank');
  });

  // Site accounts were retired on 2026-11-26 (owner decision): every account
  // lives in the portal, which has two-step verification. See warden/auth/router.py.
  test('Sign In button links to the portal sign-in', async ({ page }) => {
    await expect(page.locator('#nav-signin')).toHaveAttribute('href', 'https://portal.shadow-warden-ai.com/login');
  });

  test('"Get Started" CTA links to the portal sign-up and is visible', async ({ page }) => {
    const cta = page.locator('a[href="https://portal.shadow-warden-ai.com/register"]', { hasText: /get started/i }).first();
    await expect(cta).toBeVisible();
  });

  test('Agent Discovery Protocol link tag is present', async ({ page }) => {
    // This must NEVER be removed — it drives the SSE API resolution
    const adpLink = page.locator('link[rel="agent-protocol"]');
    await expect(adpLink).toHaveCount(1);
  });

  // ── Theme toggle ───────────────────────────────────────────────────────────
  test('theme toggle button is present and clickable', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'theme toggle lives in the desktop nav (hidden behind hamburger on mobile)');
    const toggle = page.locator('#theme-toggle');
    await expect(toggle).toBeVisible();
    await toggle.click();
    // Should not throw; body class or data-theme may change
    await expect(page.locator('body')).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Retired pages — /agentic and /community/* (2026-11-27)
// The agentic marketplace dashboard and the Community & Tunnel pages showed
// gateway features that are not the product and broke on load. Their 15 tests
// were replaced by these and the seller-page block below, keeping the floor.
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Retired pages', () => {
  test('/agentic lands on the seller page', async ({ page }) => {
    await page.goto('/agentic');
    await page.waitForURL(/\/sellers\/?$/);
    await expect(page.locator('h1')).toBeVisible();
  });

  test('no navigation link points at a retired page', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#navbar a[href="/agentic"], #navbar a[href="/community"]')).toHaveCount(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. /sellers — the product page
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Seller page', () => {
  const PORTAL_REGISTER = /^https:\/\/portal\.shadow-warden-ai\.com\/register\/?$/;
  test.beforeEach(async ({ page }) => { await page.goto('/sellers'); });

  test('hero headline is visible', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Label every unit');
  });

  test('primary call to action opens portal sign-up', async ({ page }) => {
    await expect(page.locator('.sl-hero a', { hasText: 'Start free' })).toHaveAttribute('href', PORTAL_REGISTER);
  });

  test('catalog-check link targets its section', async ({ page }) => {
    await expect(page.locator('.sl-hero a[href="#catalog-check"]')).toBeVisible();
    await expect(page.locator('#catalog-check')).toBeAttached();
  });

  for (const heading of ['What changed for sellers', 'Everything in one seller workspace',
    'Two channels, kept apart on purpose', 'Up and running in an afternoon', 'Free catalog check', 'Questions']) {
    test(`section "${heading}" is present`, async ({ page }) => {
      await expect(page.locator('h2', { hasText: heading })).toBeVisible();
    });
  }

  test('manual review goes to the contact form', async ({ page }) => {
    await expect(page.locator('a[href="/contact?topic=catalog-check"]')).toBeVisible();
  });

  test('a question expands on click', async ({ page }) => {
    const first = page.locator('details.sl-faq').first();
    await first.locator('summary').click();
    await expect(first).toHaveAttribute('open', '');
  });

  test('every sign-up link goes to the portal', async ({ page }) => {
    const links = page.locator('a', { hasText: /Start free|free account/ });
    expect(await links.count()).toBeGreaterThanOrEqual(3);
    for (const href of await links.evaluateAll(els => els.map(e => e.getAttribute('href')))) {
      expect(href).toMatch(PORTAL_REGISTER);
    }
  });

  test('page carries structured data and the agent-protocol link', async ({ page }) => {
    await expect(page.locator('script[type="application/ld+json"]').first()).toBeAttached();
    await expect(page.locator('link[rel="agent-protocol"]')).toHaveCount(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. /marketplace — the storefront, not a redirect
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Routes', () => {
  test('/marketplace is its own page, not a redirect to /agentic', async ({ page }) => {
    // R3 gave the M2M marketplace a public surface; before that `/marketplace`
    // was a 301 to `/agentic` and the product had no storefront at all. This
    // test still asserted the 301, so it contradicted
    // warden/tests/test_site_marketplace_storefront.py, which asserts the
    // opposite — two suites in one repo disagreeing about one URL.
    await page.goto('/marketplace');
    await expect(page).toHaveURL(/\/marketplace\/?$/);
    await expect(page.locator('#listings-body')).toBeAttached();
  });

  test('/community lands on the seller page', async ({ page }) => {
    const resp = await page.goto('/community');
    expect(resp?.status()).toBeLessThan(400);
    await page.waitForURL(/\/sellers\/?$/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Mobile nav
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Mobile Navigation', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('mobile hamburger opens mobile menu', async ({ page }) => {
    await page.goto('/');
    const hamburger = page.locator('#mobile-btn');
    await expect(hamburger).toBeVisible();
    await hamburger.click();
    await expect(page.locator('#mobile-menu')).toBeVisible();
  });

  test('mobile menu contains Business Community link', async ({ page }) => {
    await page.goto('/');
    await page.locator('#mobile-btn').click();
    const menu = page.locator('#mobile-menu');
    await expect(menu.locator('a', { hasText: 'Business Community' })).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Sign Up / Sign In pages
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Auth Pages', () => {
  // /signup and /login are hand-off pages to the portal: no password field on
  // the marketing site, ever.
  test('signup page hands off to the portal', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('h1')).toContainText('Create your account');
    await expect(page.locator('#continue-btn')).toHaveAttribute('href', 'https://portal.shadow-warden-ai.com/register');
    await expect(page.locator('#continue-btn')).toBeVisible();
  });

  test('signup page has link to sign in', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('a[href="https://portal.shadow-warden-ai.com/login"]')).toBeVisible();
  });

  test('signup and login pages collect no password', async ({ page }) => {
    for (const path of ['/signup', '/login']) {
      await page.goto(path);
      await expect(page.locator('input')).toHaveCount(0);
      await expect(page.locator('form')).toHaveCount(0);
    }
  });

  test('login page hands off to the portal', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('h1')).toContainText('Sign in');
    await expect(page.locator('#continue-btn')).toHaveAttribute('href', 'https://portal.shadow-warden-ai.com/login');
    await expect(page.locator('a[href="https://portal.shadow-warden-ai.com/register"]')).toBeVisible();
  });

  test('signup agent-protocol link tag is present', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('link[rel="agent-protocol"]')).toHaveCount(1);
  });
});
