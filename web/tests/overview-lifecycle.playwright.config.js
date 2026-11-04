import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'overview-lifecycle-browser.spec.js',
  timeout: 15000,
  use: { baseURL: 'http://127.0.0.1:15177', viewport: { width: 1440, height: 900 } },
  webServer: {
    command: 'npm run dev -- --port 15177 --strictPort',
    url: 'http://127.0.0.1:15177',
    reuseExistingServer: false,
    timeout: 60000,
  },
})
