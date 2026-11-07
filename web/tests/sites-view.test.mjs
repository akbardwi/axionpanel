import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createSSRApp } from 'vue'
import { renderToString } from '@vue/server-renderer'
import { readFileSync } from 'node:fs'
import { createSitesWorkflow } from '../src/lib/sitesWorkflow.js'

let server, component
before(async () => {
  server = await createServer({ server: { middlewareMode: true }, appType: 'custom', optimizeDeps: { noDiscovery: true, include: [] } })
  component = (await server.ssrLoadModule('/src/views/WebsitesView.vue')).default
})
after(async () => { await server?.close() })
function workflow() {
  return createSitesWorkflow({ client: {}, isAdmin: () => true })
}
async function render(w) {
  const app = createSSRApp(component)
  app.provide('sitesWorkflow', w)
  return renderToString(app)
}

test('real Vue renders loading and empty inventory without fabricated sites or controls', async () => {
  const w = workflow()
  assert.match(await render(w), /Loading website inventory/)
  w.state.loading = false; w.state.loaded = true
  const html = await render(w)
  assert.match(html, /No websites yet/)
  assert.doesNotMatch(html, /studio\.example|archive\.example|PHP|certificate|Preview only|Pause|Resume/)
})

test('unsupported agent keeps inventory visible and create explicitly disabled', async () => {
  const w = workflow()
  Object.assign(w.state, { loading: false, capability: 'unsupported', sites: [{ id: 1, domain: 'live.example.com', kind: 'static', root: '/test/root', listen: '127.0.0.1:18080', status: 'active', retained_content: false }] })
  const html = await render(w)
  assert.match(html, /live\.example\.com/)
  assert.match(html, /site\.plan/)
  assert.match(html, /Create unavailable/)
  assert.match(html, /<button[^>]*disabled[^>]*>Create website/)
})

test('reviewed plan is rendered as escaped text with explicit apply action', async () => {
  const w = workflow()
  Object.assign(w.state, { loading: false, capability: 'supported', operations: ['site.plan', 'site.apply'], domain: 'app.example.com', plan: { domain: 'app.example.com', root: '/test/root', vhost: '<script>alert(1)</script>', listen: '127.0.0.1:18080', applied: false, would_do: 'create' } })
  const html = await render(w)
  assert.match(html, /Review plan/)
  assert.match(html, /&lt;script&gt;/)
  assert.doesNotMatch(html, /<script>alert/)
  assert.match(html, /Create website/)
  assert.match(html, /not changed/i)
})

test('job failures, inventory errors and reconciliation remain visible', async () => {
  const w = workflow()
  Object.assign(w.state, { loading: false, inventoryError: 'network: Cannot load', reconciliation: true, error: 'Manual reconciliation required.', result: { success: false, job: { id: 'durable-job', status: 'failed', error: 'manual_reconciliation' }, site: { domain: 'app.example.com' } } })
  const html = await render(w)
  assert.match(html, /role="alert"/)
  assert.match(html, /Manual reconciliation/)
  assert.match(html, /durable-job/)
  assert.match(html, /failed/)
  assert.match(html, /Cannot load/)
})

test('removal form explains retention and uses exact-domain validation', async () => {
  const w = workflow()
  Object.assign(w.state, { loading: false, capability: 'supported', operations: ['site.plan', 'site.remove'], removal: { id: 1, domain: 'app.example.com', status: 'active', root: '/test/root' }, confirmDomain: 'APP.example.com' })
  const html = await render(w)
  assert.match(html, /content.*retained/i)
  assert.match(html, /exact domain/i)
  assert.match(html, /<button[^>]*disabled[^>]*>Remove vhost/)
})

test('Vue view only uses live workflow, real paths and existing auth protocol', () => {
  const src = readFileSync(new URL('../src/views/WebsitesView.vue', import.meta.url), 'utf8')
  assert.doesNotMatch(src, /v-html|href=["']#|localStorage|sessionStorage|setInterval|runtime:/)
  assert.match(src, /session\.check/)
  assert.match(src, /onMounted/)
  assert.match(src, /isDesignPreview/)
  assert.match(src, /type="password"/)
  assert.match(src, /autocomplete="current-password"/)
})
