import { defineConfig } from '@playwright/test'
export default defineConfig({
  testDir: './tests',
  timeout: 120000,
  use: { baseURL: 'http://127.0.0.1:15173', viewport: { width: 1440, height: 900 } },
  webServer: {
    command: 'npm run dev -- --port 15173 --strictPort',
    url: 'http://127.0.0.1:15173',
    reuseExistingServer: true,
    timeout: 60000,
  },
})
