import { defineConfig } from '@playwright/test'
// Production-mode dev server; tests route-mock every /api call so the real
// panel is never contacted.
export default defineConfig({
  testDir: '.',
  testMatch: 'overview-live-browser.spec.js',
  timeout: 60000,
  use: { baseURL: 'http://127.0.0.1:15176', viewport: { width: 1440, height: 900 } },
  webServer: {
    command: 'npm run dev -- --port 15176 --strictPort',
    url: 'http://127.0.0.1:15176',
    reuseExistingServer: false,
    timeout: 60000,
  },
})
