import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({
  plugins: [vue()],
  build: {
    // Keep font-src 'self' strict: small font subsets must not become data: URLs.
    assetsInlineLimit: (file) => /\.(woff2?|ttf|otf)$/i.test(file) ? false : undefined,
  },
  server: {
    host: '127.0.0.1',
    // Dev only: forward API calls to the loopback panel. The browser Origin is
    // passed through untouched, so the panel's configured Origin must match the
    // Vite dev URL for state-changing auth requests to be accepted.
    proxy: { '/api': { target: 'http://127.0.0.1:7800', changeOrigin: false } },
  },
})
