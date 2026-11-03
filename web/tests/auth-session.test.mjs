import test from 'node:test'
import assert from 'node:assert/strict'
import { createSessionStore } from '../src/auth/session.js'
import { AuthError } from '../src/auth/client.js'

function fakeClient(overrides = {}) {
  const calls = []
  return {
    calls,
    async login(username, password) {
      calls.push(['login', username, password])
      return overrides.login ? overrides.login(username, password) : { user: { id: 1, username, role: 'Administrator' }, csrfToken: 'csrf-login', mfaRequired: false }
    },
    async loginMfa(payload, csrf) {
      calls.push(['loginMfa', payload, csrf])
      return overrides.loginMfa ? overrides.loginMfa(payload, csrf) : { user: { id: 1, username: 'ada', role: 'Administrator' }, csrfToken: 'csrf-final', mfaRequired: false }
    },
    async me() {
      calls.push(['me'])
      return overrides.me ? overrides.me() : { user: { id: 1, username: 'ada', role: 'Administrator' }, sudoUntil: '2026-11-03T12:00:00Z' }
    },
    async logout(csrf) {
      calls.push(['logout', csrf])
      if (overrides.logout) return overrides.logout(csrf)
      return { ok: true }
    },
    csrfFromCookie: () => (overrides.cookieCsrf ?? ''),
  }
}

test('session starts unauthenticated with no user', () => {
  const s = createSessionStore({ client: fakeClient() })
  assert.equal(s.state.status, 'unknown')
  assert.equal(s.state.user, null)
})

test('ensure() resolves identity from /me once and caches the result', async () => {
  const client = fakeClient()
  const s = createSessionStore({ client })
  assert.equal(await s.ensure(), 'authenticated')
  assert.equal(s.state.status, 'authenticated')
  assert.equal(s.state.user.username, 'ada')
  assert.equal(s.state.sudoUntil, '2026-11-03T12:00:00Z')
  await s.ensure()
  assert.equal(client.calls.filter(c => c[0] === 'me').length, 1)
})

test('ensure() fails closed to unauthenticated when /me errors', async () => {
  for (const failure of [
    new AuthError('unauthorized', 'Sign in required.', 401),
    new AuthError('network', 'Cannot reach the panel backend.', 0),
    new AuthError('request_failed', 'Request failed.', 500),
  ]) {
    const s = createSessionStore({ client: fakeClient({ me: () => { throw failure } }) })
    assert.equal(await s.ensure(), 'unauthenticated')
    assert.equal(s.state.status, 'unauthenticated')
    assert.equal(s.state.user, null)
  }
})

test('login without MFA authenticates and stores the returned csrf in memory only', async () => {
  const client = fakeClient()
  const s = createSessionStore({ client })
  const result = await s.login('ada', 'pw')
  assert.equal(result.mfaRequired, false)
  assert.equal(s.state.status, 'authenticated')
  assert.equal(s.state.user.username, 'ada')
  assert.equal(s.state.csrfToken, 'csrf-login')
})

test('login requiring MFA returns the challenge and stays unauthenticated', async () => {
  const client = fakeClient({ login: () => ({ user: null, csrfToken: 'csrf-challenge', mfaRequired: true }) })
  const s = createSessionStore({ client })
  const result = await s.login('ada', 'pw')
  assert.equal(result.mfaRequired, true)
  assert.equal(s.state.status, 'unauthenticated')
  assert.equal(s.state.user, null)
  assert.equal(s.state.csrfToken, 'csrf-challenge')
})

test('mfaLogin sends exactly one factor with the challenge csrf and authenticates', async () => {
  const client = fakeClient({ login: () => ({ user: null, csrfToken: 'csrf-challenge', mfaRequired: true }) })
  const s = createSessionStore({ client })
  await s.login('ada', 'pw')

  const result = await s.mfaLogin({ code: '123456' })
  assert.equal(result.mfaRequired, false)
  const mfaCall = client.calls.find(c => c[0] === 'loginMfa')
  assert.deepEqual(mfaCall[1], { code: '123456' })
  assert.equal(mfaCall[2], 'csrf-challenge')
  assert.equal(s.state.status, 'authenticated')
  assert.equal(s.state.csrfToken, 'csrf-final')
})

test('mfaLogin supports a recovery code and rejects ambiguous input', async () => {
  const client = fakeClient({ login: () => ({ user: null, csrfToken: 'csrf-challenge', mfaRequired: true }) })
  const s = createSessionStore({ client })
  await s.login('ada', 'pw')
  await s.mfaLogin({ recoveryCode: 'ABCD-EFGH' })
  assert.deepEqual(client.calls.find(c => c[0] === 'loginMfa')[1], { recoveryCode: 'ABCD-EFGH' })
  await assert.rejects(() => s.mfaLogin({ code: '1', recoveryCode: 'x' }), (e) => e.code === 'invalid_request')
  await assert.rejects(() => s.mfaLogin({}), (e) => e.code === 'invalid_request')
})

test('login failure surfaces the error and leaves the session unauthenticated', async () => {
  const client = fakeClient({ login: () => { throw new AuthError('invalid_credentials', 'Invalid credentials.', 401) } })
  const s = createSessionStore({ client })
  await assert.rejects(() => s.login('ada', 'wrong'), (e) => e.code === 'invalid_credentials')
  assert.equal(s.state.status, 'unauthenticated')
  assert.equal(s.state.user, null)
})

test('logout calls the API with the current csrf and always clears local state', async () => {
  const client = fakeClient()
  const s = createSessionStore({ client })
  await s.login('ada', 'pw')
  await s.logout()
  const logoutCall = client.calls.find(c => c[0] === 'logout')
  assert.equal(logoutCall[1], 'csrf-login')
  assert.equal(s.state.status, 'unauthenticated')
  assert.equal(s.state.user, null)
})

test('logout clears local state even when the API call fails', async () => {
  const client = fakeClient({ logout: () => { throw new AuthError('network', 'Cannot reach the panel backend.', 0) } })
  const s = createSessionStore({ client })
  await s.login('ada', 'pw')
  await s.logout()
  assert.equal(s.state.status, 'unauthenticated')
  assert.equal(s.state.user, null)
})

test('expire() marks the session unauthenticated after session expiry', async () => {
  const client = fakeClient()
  const s = createSessionStore({ client })
  await s.login('ada', 'pw')
  assert.equal(s.state.status, 'authenticated')
  s.expire()
  assert.equal(s.state.status, 'unauthenticated')
  assert.equal(s.state.user, null)
})

test('a 401 from /me during ensure after expiry re-resolves to unauthenticated', async () => {
  let meCalls = 0
  const client = fakeClient({ me: () => {
    meCalls++
    if (meCalls > 1) throw new AuthError('unauthorized', 'Sign in required.', 401)
    return { user: { id: 1, username: 'ada', role: 'Administrator' }, sudoUntil: null }
  } })
  const s = createSessionStore({ client })
  assert.equal(await s.ensure(), 'authenticated')
  s.expire()
  assert.equal(await s.ensure(), 'unauthenticated')
  assert.equal(s.state.user, null)
})

test('logout prefers the live axp_csrf cookie over the remembered token', async () => {
  const client = fakeClient({ cookieCsrf: 'cookie-csrf' })
  const s = createSessionStore({ client })
  await s.login('ada', 'pw')
  await s.logout()
  assert.equal(client.calls.find(c => c[0] === 'logout')[1], 'cookie-csrf')
})

test('check() revalidates on demand so route guards catch expired sessions', async () => {
  let n = 0
  const client = fakeClient({ me: () => {
    n++
    if (n > 1) throw new AuthError('unauthorized', 'Sign in required.', 401)
    return { user: { id: 1, username: 'ada', role: 'Administrator' }, sudoUntil: null }
  } })
  const s = createSessionStore({ client })
  assert.equal(await s.check(), 'authenticated')
  assert.equal(await s.check(), 'unauthenticated')
  assert.equal(s.state.user, null)
  assert.equal(n, 2)
})

test('a stale in-flight /me cannot resurrect an expired or logged-out session', async () => {
  let resolveMe
  const mePromise = new Promise((resolve) => { resolveMe = resolve })
  const client = fakeClient({ me: () => mePromise })
  const s = createSessionStore({ client })
  const refreshDone = s.check()
  await s.logout()
  resolveMe({ user: { id: 1, username: 'ada', role: 'Administrator' }, sudoUntil: null })
  assert.equal(await refreshDone, 'unauthenticated')
  assert.equal(s.state.status, 'unauthenticated')
  assert.equal(s.state.user, null)
})

function deferred() {
  let resolve, reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

for (const method of ['login', 'mfaLogin']) {
  for (const outcome of ['success', '401']) {
    test(`/me started during pending ${method} cannot change authenticated state after stale ${outcome}`, async () => {
      const auth = deferred()
      const me = deferred()
      const user = { id: 2, username: 'grace', role: 'Operator', email: 'grace@example.test' }
      const expected = { status: 'authenticated', user, sudoUntil: null, csrfToken: 'csrf-new-identity', error: '' }
      const client = fakeClient({
        login: () => method === 'login' ? auth.promise : { user: null, csrfToken: 'csrf-challenge', mfaRequired: true },
        loginMfa: () => auth.promise,
        me: () => me.promise,
      })
      const s = createSessionStore({ client })
      if (method === 'mfaLogin') await s.login('grace', 'pw')

      const authDone = method === 'login' ? s.login('grace', 'pw') : s.mfaLogin({ code: '123456' })
      const refreshDone = s.check()
      assert.equal(client.calls.filter(c => c[0] === 'me').length, 1)
      auth.resolve({ user, csrfToken: expected.csrfToken, mfaRequired: false })
      await authDone
      assert.deepEqual(s.state, expected)

      if (outcome === 'success') {
        me.resolve({ user: { id: 1, username: 'ada', role: 'Administrator' }, sudoUntil: '2026-11-03T12:00:00Z' })
      } else {
        me.reject(new AuthError('unauthorized', 'Sign in required.', 401))
      }
      await refreshDone
      assert.deepEqual(s.state, expected)
    })
  }
}

test('session store never writes to web storage', async () => {
  const writes = []
  const storage = { setItem: (k) => writes.push(k), getItem: () => null, removeItem: () => {} }
  globalThis.localStorage = storage
  globalThis.sessionStorage = storage
  try {
    const s = createSessionStore({ client: fakeClient({ login: () => ({ user: null, csrfToken: 'c', mfaRequired: true }) }) })
    await s.login('ada', 'pw')
    await s.mfaLogin({ code: '123456' })
    await s.logout()
    assert.deepEqual(writes, [])
  } finally {
    delete globalThis.localStorage
    delete globalThis.sessionStorage
  }
})
