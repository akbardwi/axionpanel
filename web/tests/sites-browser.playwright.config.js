import { defineConfig } from '@playwright/test'
// Production-style dev server on a spare loopback port. Every /api request is
// route-mocked; the real panel and the live host are never contacted.
export default defineConfig({
  testDir: '.',
  testMatch: 'sites-browser.spec.js',
  timeout: 60000,
  use: { baseURL: 'http://127.0.0.1:15177', viewport: { width: 1440, height: 900 } },
  webServer: {
    command: 'npm run dev -- --port 15177 --strictPort',
    url: 'http://127.0.0.1:15177',
    reuseExistingServer: false,
    timeout: 60000,
  },
})
