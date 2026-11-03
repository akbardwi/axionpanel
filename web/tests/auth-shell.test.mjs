import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
const read = p => readFileSync(new URL('../' + p, import.meta.url), 'utf8')

test('router installs a fail-closed auth guard backed by the session store', () => {
  const router = read('src/router.js')
  assert.match(router, /beforeEach/)
  assert.match(router, /resolveGuard/)
  assert.match(router, /session\.(ensure|refresh)/)
  assert.match(router, /isDesignPreview/)
})

test('app shell shows the real signed-in identity and a real sign out', () => {
  const app = read('src/App.vue')
  assert.match(app, /session\.state\.user/)
  assert.match(app, /\.username/)
  assert.match(app, /\.role/)
  assert.match(app, /Sign out/)
  assert.match(app, /session\.logout\(\)/)
  assert.doesNotMatch(app, />admin</)
  assert.doesNotMatch(app, />Administrator</)
})

test('feature screens stay clearly labelled as samples outside design preview', () => {
  const app = read('src/App.vue')
  assert.match(app, /SAMPLE SCREENS/)
  assert.match(app, /Sample screens/)
  assert.match(app, /DESIGN PREVIEW/)
})

test('design preview only reaches the shell through the explicit env switch', () => {
  const app = read('src/App.vue')
  const router = read('src/router.js')
  assert.match(read('src/designMode.js'), /VITE_DESIGN_PREVIEW === 'true'/)
  for (const src of [app, router]) assert.doesNotMatch(src, /catch\s*\([^)]*\)\s*\{[^}]*preview/i)
})

test('no web storage writes anywhere in auth code or shell', () => {
  for (const f of ['src/App.vue', 'src/router.js', 'src/auth/client.js', 'src/auth/session.js', 'src/auth/loginFlow.js', 'src/views/LoginView.vue']) {
    assert.doesNotMatch(read(f), /localStorage|sessionStorage|indexedDB/, f)
  }
})

test('vite dev server proxies /api to the loopback panel on 7800', () => {
  const cfg = read('vite.config.js')
  assert.match(cfg, /'\/api'/)
  assert.match(cfg, /127\.0\.0\.1:7800/)
})
