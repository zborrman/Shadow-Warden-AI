import { defineConfig, devices } from '@playwright/test';

// The site integrity sweep (tests/integrity) — separate from tests/e2e, whose
// 37 assertions CI ratchets with E2E_MIN_TESTS. Point it at a running build:
//   npm run build && npx astro preview --port 4321
//   PLAYWRIGHT_BASE_URL=http://localhost:4321 npx playwright test -c playwright.integrity.config.ts
// or at a deploy: PLAYWRIGHT_BASE_URL=https://www.shadow-warden-ai.com
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || process.env.BASE_URL || 'http://localhost:4321';

export default defineConfig({
  testDir: './tests/integrity',
  timeout: 60_000,
  fullyParallel: true,
  workers: process.env.CI ? 2 : 4,
  reporter: [['list']],
  use: { baseURL: BASE_URL, trace: 'off' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
