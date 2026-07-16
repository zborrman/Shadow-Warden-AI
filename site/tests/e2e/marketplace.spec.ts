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

/** Hover the nav item matching `label` and return the dropdown locator. */
async function hoverNavItem(page: Page, label: string) {
  // The desktop nav lives inside <header id="navbar">. We locate the link by text.
  const trigger = page.locator('#navbar nav').locator('a', { hasText: label }).first();
  await trigger.hover();
  // The sibling dropdown div appears when the .group ancestor is hovered.
  const group = trigger.locator('xpath=ancestor::div[contains(@class,"group")]');
  const dropdown = group.locator('div[class*="group-hover"]').first();
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

  // ── Business Community dropdown ────────────────────────────────────────────
  test('Business Community dropdown shows sub-items on hover', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Business Community');
    await expect(dropdown).toBeVisible();
    // Verify known sub-items from roadmap.json
    await expect(dropdown.locator('a', { hasText: 'Community & Collaboration' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Agentic Commerce' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Business Intelligence' })).toBeVisible();
  });

  test('Business Community → Agentic Commerce link has correct href', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Business Community');
    await expect(dropdown).toBeVisible();
    const link = dropdown.locator('a', { hasText: 'Agentic Commerce' });
    await expect(link).toHaveAttribute('href', '/business-community/agentic-commerce');
  });

  // ── Cyber Security dropdown ────────────────────────────────────────────────
  test('Cyber Security dropdown shows sub-items on hover', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Cyber Security');
    await expect(dropdown).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Agentic SOC' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Cryptography' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Compliance & Privacy' })).toBeVisible();
    // Cyber Security also has a static "Trust Center" link
    await expect(dropdown.locator('a', { hasText: 'Trust Center' })).toBeVisible();
  });

  test('Cyber Security → Agentic SOC link has correct href', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Cyber Security');
    const link = dropdown.locator('a', { hasText: 'Agentic SOC' });
    await expect(link).toHaveAttribute('href', '/cyber-security/agentic-soc');
  });

  // ── Tunnel dropdown ────────────────────────────────────────────────────────
  test('Tunnel dropdown shows MASQUE Tunnels and Per-Tenant Routing', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Tunnel');
    await expect(dropdown).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'MASQUE Tunnels' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Per-Tenant Routing' })).toBeVisible();
    await expect(dropdown.locator('a', { hasText: 'Sovereign AI Cloud' })).toBeVisible();
  });

  test('Tunnel → MASQUE Tunnels link has correct href', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name === 'mobile', 'desktop-only CSS hover dropdown; mobile uses hamburger nav');
    const { dropdown } = await hoverNavItem(page, 'Tunnel');
    const link = dropdown.locator('a', { hasText: 'MASQUE Tunnels' });
    await expect(link).toHaveAttribute('href', '/tunnel/masque-tunnels');
  });

  // ── Static nav links ───────────────────────────────────────────────────────
  test('static nav links are present and have correct hrefs', async ({ page }) => {
    const nav = page.locator('#navbar nav');
    const checks: [string, string][] = [
      ['Business Community', '/business-community'],
      ['Cyber Security',     '/cyber-security'],
      ['Tunnel',             '/tunnel'],
      ['Dashboard',          '/dashboard'],
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

  test('Sign In button links to /login', async ({ page }) => {
    await expect(page.locator('#nav-signin')).toHaveAttribute('href', '/login');
  });

  test('"Get Started" CTA links to /signup and is visible', async ({ page }) => {
    const cta = page.locator('a[href="/signup"]', { hasText: /get started/i }).first();
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
// 2. 6-Step Community Wizard — /community/new
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Community Creation Wizard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/community/new');
    await expect(page.locator('#wizard-card')).toBeVisible();
  });

  test('wizard renders 6 step indicators', async ({ page }) => {
    for (let i = 0; i <= 5; i++) {
      await expect(page.locator(`#sc-${i}`)).toBeVisible();
    }
    // Step 1 starts active
    await expect(page.locator('#sc-0')).toHaveClass(/active/);
  });

  // ── Full happy-path walkthrough ────────────────────────────────────────────
  test('completes all 6 steps and launches community', { timeout: 60_000 }, async ({ page }) => {
    // ── Step 1: Name & Description ──────────────────────────────────────────
    await expect(page.locator('#panel-0')).toBeVisible();
    await page.fill('#f-name', 'E2E Security Research Hub');
    await page.fill('#f-desc', 'Automated E2E test community — safe to delete');
    await page.click('#next-0');

    // ── Step 2: Visibility & Type ───────────────────────────────────────────
    await expect(page.locator('#panel-1')).toBeVisible();
    // PUBLIC is selected by default; explicitly click to ensure state
    await page.click('#rc-public');
    // Select MARKETPLACE type
    await page.click('#rc-marketplace');
    await expect(page.locator('#rc-marketplace')).toHaveClass(/selected/);
    await page.click('#next-1');

    // ── Step 3: Security ────────────────────────────────────────────────────
    await expect(page.locator('#panel-2')).toBeVisible();
    // E2E encryption is checked by default — verify it
    await expect(page.locator('#t-e2e')).toBeChecked();
    // PQC toggle is Enterprise-locked — must remain disabled
    await expect(page.locator('#t-pqc')).toBeDisabled();
    // Toggle disappearing messages — checkbox is visually hidden behind a CSS slider;
    // use evaluate to toggle it programmatically (scrollIntoViewIfNeeded can't reach it
    // when the navbar pushes content below viewport in headless mode)
    await page.evaluate(() => {
      const el = document.getElementById('t-disappear') as HTMLInputElement;
      if (el && !el.checked) {
        el.checked = true;
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    });
    await expect(page.locator('#t-disappear')).toBeChecked();
    await page.click('#next-2');

    // ── Step 4: Governance ──────────────────────────────────────────────────
    await expect(page.locator('#panel-3')).toBeVisible();
    // Change max members
    await page.selectOption('#f-maxmembers', '50');
    await page.click('#next-3');

    // ── Step 5: Integrations & Tags ─────────────────────────────────────────
    await expect(page.locator('#panel-4')).toBeVisible();
    // Enable SOVA Agent — use evaluate; visually hidden checkbox (same slider pattern as t-disappear)
    await page.evaluate(() => {
      const el = document.getElementById('t-sova') as HTMLInputElement;
      if (el && !el.checked) {
        el.checked = true;
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    });
    await expect(page.locator('#t-sova')).toBeChecked();
    // Add a tag
    await page.fill('#tag-input', 'threat-intel');
    await page.keyboard.press('Enter');
    // Verify tag chip rendered
    await expect(page.locator('#tags-wrap')).toContainText('threat-intel');
    await page.click('#next-4');

    // ── Step 6: Review & Launch ─────────────────────────────────────────────
    await expect(page.locator('#panel-5')).toBeVisible();
    // Review table must show the community name
    await expect(page.locator('#rv-name')).toHaveText('E2E Security Research Hub');
    // Visibility row
    await expect(page.locator('#rv-vis')).not.toHaveText('—');
    // Encryption must show as enabled
    await expect(page.locator('#rv-enc')).not.toHaveText('—');

    // Clear any stale community data so btn-create always generates a fresh entry
    await page.evaluate(() => localStorage.removeItem('sw_communities'));

    // Launch — wizard writes to localStorage and redirects
    await page.click('#btn-create');

    // The view page may strip created=1 via history.replaceState; just verify /community/view
    await expect(page).toHaveURL(/\/community\/view/, { timeout: 10_000 });
  });

  // ── Back navigation ─────────────────────────────────────────────────────
  test('back button returns to previous step', async ({ page }) => {
    await page.fill('#f-name', 'Back-Test Community');
    await page.click('#next-0');
    await expect(page.locator('#panel-1')).toBeVisible();
    await page.click('#back-1');
    await expect(page.locator('#panel-0')).toBeVisible();
  });

  // ── Name required validation ───────────────────────────────────────────────
  test('Launch without name returns to step 1', { timeout: 60_000 }, async ({ page }) => {
    // next-0 validates name — fill it so we can advance, then clear it before launching
    await page.fill('#f-name', 'Temp Name');
    await page.click('#next-0');
    await expect(page.locator('#panel-1')).toBeVisible();
    await page.click('#next-1');
    await expect(page.locator('#panel-2')).toBeVisible();
    await page.click('#next-2');
    await expect(page.locator('#panel-3')).toBeVisible();
    await page.click('#next-3');
    await expect(page.locator('#panel-4')).toBeVisible();
    await page.click('#next-4');
    await expect(page.locator('#panel-5')).toBeVisible();
    // Clear the name at runtime so btn-create sees empty string
    await page.evaluate(() => {
      const el = document.getElementById('f-name') as HTMLInputElement;
      if (el) el.value = '';
    });
    await page.click('#btn-create');
    // Wizard calls goTo(0) and stays on same URL
    await expect(page).toHaveURL(/\/community\/new/);
    await expect(page.locator('#panel-0')).toBeVisible();
  });

  // ── Radio card selection ───────────────────────────────────────────────────
  test('radio cards toggle selected class correctly', async ({ page }) => {
    await page.fill('#f-name', 'Radio Test');
    await page.click('#next-0');
    await expect(page.locator('#panel-1')).toBeVisible();
    // Click PRIVATE
    await page.click('#rc-private');
    await expect(page.locator('#rc-private')).toHaveClass(/selected/);
    await expect(page.locator('#rc-public')).not.toHaveClass(/selected/);
    // Click back to PUBLIC
    await page.click('#rc-public');
    await expect(page.locator('#rc-public')).toHaveClass(/selected/);
    await expect(page.locator('#rc-private')).not.toHaveClass(/selected/);
  });

  // ── PQC locked badge ──────────────────────────────────────────────────────
  test('PQC badge shows Enterprise label', async ({ page }) => {
    await page.fill('#f-name', 'PQC Test');
    await page.click('#next-0');
    await page.click('#next-1');
    await expect(page.locator('#panel-2')).toBeVisible();
    await expect(page.locator('#pqc-badge')).toHaveText('Enterprise');
    await expect(page.locator('#t-pqc')).toBeDisabled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. /agentic — Marketplace Dashboard & Chart.js Canvases
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Agentic Marketplace Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // /marketplace 301s to /agentic
    await page.goto('/agentic');
    // mk-hero is the first/only hero section on the redesigned marketplace page
    await expect(page.locator('section.mk-hero')).toBeVisible({ timeout: 10_000 });
  });

  // ── Hero stat counters ─────────────────────────────────────────────────────
  test('hero stat bar has 5 stat elements', async ({ page }) => {
    // 4 SSE-updatable counters + 1 static "Platform Take Rate" card
    const stats = page.locator('.stats-bar .stat-n');
    await expect(stats).toHaveCount(5);
  });

  test('stat IDs are present for SSE updates', async ({ page }) => {
    for (const id of ['st-agents', 'st-listings', 'st-trades', 'st-vol']) {
      await expect(page.locator(`#${id}`)).toBeVisible();
    }
  });

  // ── Chart.js canvases ─────────────────────────────────────────────────────
  test('chart canvas elements exist in the DOM', async ({ page }) => {
    // Chart.js canvases must be present regardless of CDN load
    for (const id of ['chart-volume', 'chart-payments', 'chart-agents']) {
      await expect(page.locator(`canvas#${id}`)).toBeAttached();
    }
  });

  test('chart canvases are visible in the analytics section', async ({ page }) => {
    // Scroll to the analytics section first
    await page.locator('#analytics').scrollIntoViewIfNeeded();
    for (const id of ['chart-volume', 'chart-payments']) {
      await expect(page.locator(`canvas#${id}`)).toBeVisible();
    }
  });

  test('live market ticker element is present', async ({ page }) => {
    // The ticker is fed live trade data via SSE; it must render regardless of feed state
    await expect(page.locator('#ticker')).toBeAttached();
  });

  // ── Marketplace data tables ─────────────────────────────────────────────────
  test('marketplace tables render (agents, tools, auctions, trades)', async ({ page }) => {
    for (const id of ['agents-table', 'tools-table', 'auctions-grid', 'trades-body']) {
      await expect(page.locator(`#${id}`)).toBeAttached();
    }
  });

  // ── Core sections ───────────────────────────────────────────────────────────
  test('core marketplace sections are present', async ({ page }) => {
    for (const id of ['analytics', 'agents', 'tools', 'auctions', 'payments']) {
      await expect(page.locator(`section#${id}`)).toBeAttached();
    }
  });

  test('agent-protocol link tag is present on /agentic', async ({ page }) => {
    await expect(page.locator('link[rel="agent-protocol"]')).toHaveCount(1);
  });

  // ── Settlement / protocol sections ──────────────────────────────────────────
  test('payments and protocol sections render', async ({ page }) => {
    await page.locator('#payments').scrollIntoViewIfNeeded();
    await expect(page.locator('section#payments')).toBeVisible();
    await expect(page.locator('section#protocol')).toBeAttached();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. /marketplace redirect → /agentic
// ─────────────────────────────────────────────────────────────────────────────
test.describe('Redirects', () => {
  test('/marketplace redirects to /agentic', async ({ page }) => {
    await page.goto('/marketplace');
    await expect(page).toHaveURL(/\/agentic/);
  });

  test('/community redirects or loads community page', async ({ page }) => {
    const resp = await page.goto('/community');
    expect(resp?.status()).toBeLessThan(400);
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
  test('signup page renders with form and logo', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('h1')).toContainText('Create your account');
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('#confirm')).toBeVisible();
    await expect(page.locator('#submit-btn')).toBeVisible();
  });

  test('signup page has link to login', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('a[href="/login"]')).toBeVisible();
  });

  test('signup client validates password mismatch', async ({ page }) => {
    await page.goto('/signup');
    await page.fill('#email', 'test@example.com');
    await page.fill('#password', 'Password1!');
    await page.fill('#confirm', 'Different1!');
    await page.locator('#confirm').dispatchEvent('input');
    await expect(page.locator('#confirm-hint')).toBeVisible();
  });

  test('login page renders with form and signup link', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('h1')).toContainText('Sign in');
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('a[href="/signup"]')).toBeVisible();
  });

  test('signup agent-protocol link tag is present', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('link[rel="agent-protocol"]')).toHaveCount(1);
  });
});
