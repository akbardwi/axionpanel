import { defineConfig } from '@playwright/test'
// Design screenshots run against an explicit design-preview server. It never
// reuses an existing dev server, so a production-mode Vite cannot be picked up.
export default defineConfig({
  testDir: './tests',
  testMatch: 'browser-design.spec.js',
  timeout: 120000,
  use: { baseURL: 'http://127.0.0.1:15174', viewport: { width: 1440, height: 900 } },
  webServer: {
    command: 'VITE_DESIGN_PREVIEW=true npm run dev -- --port 15174 --strictPort',
    url: 'http://127.0.0.1:15174',
    reuseExistingServer: false,
    timeout: 60000,
  },
})
