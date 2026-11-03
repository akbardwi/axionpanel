import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthClient, AuthError } from '../src/auth/client.js'
import { createSessionStore } from '../src/auth/session.js'
const response = body => ({ ok: true, status: 200, json: async () => body })

test('malformed successful identity responses fail closed rather than authenticating', async () => {
  for (const body of [{}, null, { user: null }, { user: {} }, { user: { username: 'ada' } }, { user: { username: '', role: 'admin' } }]) {
    const client = createAuthClient({ fetchImpl: async () => response(body), getCookie: () => '' })
    await assert.rejects(() => client.me(), e => e instanceof AuthError && e.code === 'invalid_response')
    const store = createSessionStore({ client })
    assert.equal(await store.ensure(), 'unauthenticated')
    assert.equal(store.state.user, null)
  }
})

test('malformed login responses never create local authenticated state', async () => {
  for (const body of [{}, { user: {}, mfa_required: false }, { user: { username: 'ada', role: 'admin' } }, { mfa_required: true }]) {
    const client = createAuthClient({ fetchImpl: async () => response(body), getCookie: () => '' })
    const store = createSessionStore({ client })
    await assert.rejects(() => store.login('ada', 'secret'), e => e.code === 'invalid_response')
    assert.equal(store.state.status, 'unauthenticated')
  }
})

test('MFA completion must return an identity, not another challenge', async () => {
  const client = createAuthClient({ fetchImpl: async () => response({ mfa_required: true, csrf_token: 'challenge' }), getCookie: () => '' })
  await assert.rejects(() => client.loginMfa({ code: '123456' }, 'challenge'), e => e.code === 'invalid_response')
})

test('logout client prefers current cookie token over stale in-memory fallback', async () => {
  let token
  const client = createAuthClient({
    fetchImpl: async (_url, init) => { token = init.headers['X-CSRF-Token']; return response({ ok: true }) },
    getCookie: () => 'axp_csrf=current-cookie',
  })
  await client.logout('stale-token')
  assert.equal(token, 'current-cookie')
})

test('logout network errors warn that remote session may still be active', async () => {
  const store = createSessionStore({ client: {
    csrfFromCookie: () => 'token',
    logout: async () => { throw new AuthError('network', 'Cannot reach the panel backend.', 0) },
  } })
  await store.logout()
  assert.equal(store.state.status, 'unauthenticated')
  assert.match(store.state.error, /server session may still be active/)
})
