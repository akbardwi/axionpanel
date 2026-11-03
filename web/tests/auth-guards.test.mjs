import test from 'node:test'
import assert from 'node:assert/strict'
import { resolveGuard } from '../src/auth/guards.js'

test('production guard blocks protected views when unauthenticated', () => {
  const next = resolveGuard({ path: '/websites', status: 'unauthenticated', designPreview: false })
  assert.equal(next, '/login')
})

test('production guard allows protected views when authenticated', () => {
  assert.equal(resolveGuard({ path: '/websites', status: 'authenticated', designPreview: false }), true)
})

test('unknown session state fails closed to login', () => {
  assert.equal(resolveGuard({ path: '/overview', status: 'unknown', designPreview: false }), '/login')
})

test('authenticated users get bounced off the login page', () => {
  assert.equal(resolveGuard({ path: '/login', status: 'authenticated', designPreview: false }), '/overview')
})

test('login page renders for unauthenticated users', () => {
  assert.equal(resolveGuard({ path: '/login', status: 'unauthenticated', designPreview: false }), true)
})

test('expired session (unauthenticated) redirects a protected view to login', () => {
  assert.equal(resolveGuard({ path: '/settings', status: 'unauthenticated', designPreview: false }), '/login')
})

test('design preview mode opens every route without auth', () => {
  for (const path of ['/login', '/overview', '/websites', '/settings']) {
    assert.equal(resolveGuard({ path, status: 'unknown', designPreview: true }), true)
  }
})

test('design preview is off unless VITE_DESIGN_PREVIEW is exactly true', async () => {
  const mod = await import('../src/designMode.js', { with: {} })
  assert.equal(mod.isDesignPreview(), false)
  assert.equal(mod.designPreviewEnabled({ VITE_DESIGN_PREVIEW: 'true' }), true)
  for (const value of ['1', 'TRUE', 'yes', '', undefined]) {
    assert.equal(mod.designPreviewEnabled({ VITE_DESIGN_PREVIEW: value }), false)
  }
})
