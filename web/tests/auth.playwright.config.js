import { defineConfig } from '@playwright/test'
import { fileURLToPath } from 'node:url'
// Separate from design-preview screenshots: exercise production auth paths.
export default defineConfig({
  testDir: '.',
  testMatch: 'auth-ui.contract.mjs',
  timeout: 15000,
  use: { baseURL: 'http://127.0.0.1:15175', viewport: { width: 1440, height: 900 } },
  webServer: {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    command: 'VITE_DESIGN_PREVIEW=false npm run dev -- --port 15175 --strictPort',
    url: 'http://127.0.0.1:15175',
    reuseExistingServer: false,
  },
})
