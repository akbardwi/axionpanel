import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthClient, AuthError, parseCookies, csrfFromCookie } from '../src/auth/client.js'

function stubFetch(handler) {
  const calls = []
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init })
    return handler(url, init, calls.length)
  }
  return { fetchImpl, calls }
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }
}

test('parseCookies reads name=value pairs and csrfFromCookie recovers axp_csrf', () => {
  assert.deepEqual(parseCookies('a=1; axp_csrf=tok123; b=x=y'), { a: '1', axp_csrf: 'tok123', b: 'x=y' })
  assert.equal(csrfFromCookie('axp_csrf=hello'), 'hello')
  assert.equal(csrfFromCookie('other=1'), '')
  assert.equal(csrfFromCookie(''), '')
})

test('login posts credentials same-origin and returns user, csrf and mfa flag', async () => {
  const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, {
    user: { id: 7, username: 'ada', role: 'Administrator' },
    csrf_token: 'csrf-login',
    mfa_required: false,
  }))
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  const result = await client.login('ada', 'hunter2')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/api/v1/auth/login')
  assert.equal(calls[0].init.method, 'POST')
  assert.equal(calls[0].init.credentials, 'same-origin')
  assert.deepEqual(JSON.parse(calls[0].init.body), { username: 'ada', password: 'hunter2' })
  assert.equal(calls[0].init.headers['Content-Type'], 'application/json')
  assert.deepEqual(result.user, { id: 7, username: 'ada', role: 'Administrator' })
  assert.equal(result.csrfToken, 'csrf-login')
  assert.equal(result.mfaRequired, false)
})

test('login reports mfa_required true and exposes the challenge csrf token', async () => {
  const { fetchImpl } = stubFetch(() => jsonResponse(200, { mfa_required: true, csrf_token: 'challenge-csrf' }))
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  const result = await client.login('ada', 'hunter2')
  assert.equal(result.mfaRequired, true)
  assert.equal(result.csrfToken, 'challenge-csrf')
  assert.equal(result.user, null)
})

test('loginMfa sends exactly one of code or recovery_code with X-CSRF-Token', async () => {
  {
    const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, {
      user: { id: 7, username: 'ada', role: 'Administrator' },
      csrf_token: 'csrf-session',
      mfa_required: false,
    }))
    const client = createAuthClient({ fetchImpl, getCookie: () => '' })
    const result = await client.loginMfa({ code: '123456' }, 'challenge-csrf')
    assert.equal(calls[0].url, '/api/v1/auth/login/mfa')
    assert.equal(calls[0].init.method, 'POST')
    assert.equal(calls[0].init.credentials, 'same-origin')
    assert.deepEqual(JSON.parse(calls[0].init.body), { code: '123456' })
    assert.equal(calls[0].init.headers['X-CSRF-Token'], 'challenge-csrf')
    assert.equal(result.csrfToken, 'csrf-session')
    assert.equal(result.user.username, 'ada')
    assert.equal(result.mfaRequired, false)
  }
  {
    const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, { user: { id: 7, username: 'ada', role: 'Administrator' }, csrf_token: 'csrf-session', mfa_required: false }))
    const client = createAuthClient({ fetchImpl, getCookie: () => '' })
    await client.loginMfa({ recoveryCode: 'abcd-efgh' }, 'challenge-csrf')
    assert.deepEqual(JSON.parse(calls[0].init.body), { recovery_code: 'abcd-efgh' })
  }
})

test('loginMfa rejects ambiguous payloads instead of sending them', async () => {
  const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, {}))
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  await assert.rejects(() => client.loginMfa({ code: '1', recoveryCode: 'x' }, 't'), (err) => err instanceof AuthError && err.code === 'invalid_request')
  await assert.rejects(() => client.loginMfa({}, 't'), (err) => err instanceof AuthError && err.code === 'invalid_request')
  assert.equal(calls.length, 0)
})

test('me fetches /api/v1/auth/me same-origin and returns user and sudo_until', async () => {
  const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, {
    user: { id: 7, username: 'ada', role: 'Administrator' },
    sudo_until: '2026-11-03T12:00:00Z',
  }))
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  const result = await client.me()
  assert.equal(calls[0].url, '/api/v1/auth/me')
  assert.equal(calls[0].init.method, 'GET')
  assert.equal(calls[0].init.credentials, 'same-origin')
  assert.deepEqual(result.user, { id: 7, username: 'ada', role: 'Administrator' })
  assert.equal(result.sudoUntil, '2026-11-03T12:00:00Z')
})

test('logout posts with X-CSRF-Token recovered from the axp_csrf cookie', async () => {
  const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, { ok: true }))
  const client = createAuthClient({ fetchImpl, getCookie: () => 'axp_csrf=cookie-csrf; other=1' })
  await client.logout()
  assert.equal(calls[0].url, '/api/v1/auth/logout')
  assert.equal(calls[0].init.method, 'POST')
  assert.equal(calls[0].init.credentials, 'same-origin')
  assert.equal(calls[0].init.headers['X-CSRF-Token'], 'cookie-csrf')
})

test('logout falls back to a session csrf token when no cookie is readable', async () => {
  const { fetchImpl, calls } = stubFetch(() => jsonResponse(200, { ok: true }))
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  await client.logout('memory-csrf')
  assert.equal(calls[0].init.headers['X-CSRF-Token'], 'memory-csrf')
})

test('api errors map to AuthError with code, message and status', async () => {
  const { fetchImpl } = stubFetch(() => jsonResponse(401, { error: { code: 'invalid_credentials', message: 'Invalid credentials.' } }))
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  await assert.rejects(() => client.login('ada', 'wrong'), (err) => {
    assert.ok(err instanceof AuthError)
    assert.equal(err.code, 'invalid_credentials')
    assert.equal(err.message, 'Invalid credentials.')
    assert.equal(err.status, 401)
    return true
  })
})

test('network failures fail closed as AuthError code network', async () => {
  const fetchImpl = async () => { throw new TypeError('Failed to fetch') }
  const client = createAuthClient({ fetchImpl, getCookie: () => '' })
  await assert.rejects(() => client.me(), (err) => err instanceof AuthError && err.code === 'network' && err.status === 0)
})

test('non-JSON error responses still produce a usable AuthError', async () => {
  const res = { ok: false, status: 502, json: async () => { throw new SyntaxError('bad json') } }
  const client = createAuthClient({ fetchImpl: async () => res, getCookie: () => '' })
  await assert.rejects(() => client.me(), (err) => err instanceof AuthError && err.code === 'request_failed' && err.status === 502)
})

test('default client reads the live axp_csrf cookie through the injected reader', () => {
  let seen = 0
  const client = createAuthClient({ fetchImpl: async () => jsonResponse(200, {}), getCookie: () => { seen++; return 'axp_csrf=live' } })
  assert.equal(client.csrfFromCookie(), 'live')
  assert.equal(seen, 1)
})
