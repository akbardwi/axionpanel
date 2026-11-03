import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createLoginFlow } from '../src/auth/loginFlow.js'
import { AuthError } from '../src/auth/client.js'

function fakeSession({ login, mfaLogin } = {}) {
  const calls = []
  return {
    calls,
    async login(u, p) { calls.push(['login', u, p]); return login ? login(u, p) : { mfaRequired: false } },
    async mfaLogin(payload) { calls.push(['mfa', payload]); return mfaLogin ? mfaLogin(payload) : { mfaRequired: false } },
  }
}

test('password step validates input locally without calling the API', async () => {
  const session = fakeSession()
  const flow = createLoginFlow(session)
  flow.form.username = ' '
  flow.form.password = 'x'
  assert.equal(await flow.submitPassword(), false)
  assert.match(flow.error.value, /username/i)
  assert.equal(session.calls.length, 0)
})

test('password-only login signs in and clears the password', async () => {
  const session = fakeSession()
  const flow = createLoginFlow(session)
  flow.form.username = 'ada'
  flow.form.password = 'secret'
  assert.equal(await flow.submitPassword(), true)
  assert.deepEqual(session.calls[0], ['login', 'ada', 'secret'])
  assert.equal(flow.form.password, '')
  assert.equal(flow.stage.value, 'done')
})

test('password is cleared before the request resolves and busy blocks duplicates', async () => {
  let release
  const session = fakeSession({ login: () => new Promise(r => { release = r }) })
  const flow = createLoginFlow(session)
  flow.form.username = 'ada'
  flow.form.password = 'secret'
  const first = flow.submitPassword()
  assert.equal(flow.busy.value, true)
  assert.equal(flow.form.password, '')
  assert.equal(await flow.submitPassword(), false)
  release({ mfaRequired: false })
  assert.equal(await first, true)
  assert.equal(flow.busy.value, false)
  assert.equal(session.calls.length, 1)
})

test('MFA challenge moves to the verification stage', async () => {
  const flow = createLoginFlow(fakeSession({ login: () => ({ mfaRequired: true }) }))
  flow.form.username = 'ada'
  flow.form.password = 'secret'
  assert.equal(await flow.submitPassword(), false)
  assert.equal(flow.stage.value, 'mfa')
  assert.equal(flow.form.password, '')
})

test('authenticator code sends only code and clears input on failure', async () => {
  let n = 0
  const session = fakeSession({
    login: () => ({ mfaRequired: true }),
    mfaLogin: () => { if (++n === 1) throw new AuthError('invalid_credentials', 'Invalid credentials.', 401); return { mfaRequired: false } },
  })
  const flow = createLoginFlow(session)
  flow.form.username = 'ada'; flow.form.password = 'secret'
  await flow.submitPassword()
  flow.factor.value = '123456'
  assert.equal(await flow.submitMfa(), false)
  assert.deepEqual(session.calls[1], ['mfa', { code: '123456' }])
  assert.equal(flow.factor.value, '')
  assert.equal(flow.error.value, 'Invalid credentials.')
  flow.factor.value = '654321'
  assert.equal(await flow.submitMfa(), true)
  assert.equal(flow.stage.value, 'done')
})

test('recovery mode sends only recovery_code payload', async () => {
  const session = fakeSession({ login: () => ({ mfaRequired: true }) })
  const flow = createLoginFlow(session)
  flow.form.username = 'ada'; flow.form.password = 'secret'
  await flow.submitPassword()
  flow.toggleRecovery()
  assert.equal(flow.useRecovery.value, true)
  flow.factor.value = 'abcd-efgh'
  await flow.submitMfa()
  assert.deepEqual(session.calls[1], ['mfa', { recoveryCode: 'abcd-efgh' }])
})

test('authenticator code must be six digits before sending', async () => {
  const session = fakeSession({ login: () => ({ mfaRequired: true }) })
  const flow = createLoginFlow(session)
  flow.form.username = 'ada'; flow.form.password = 'secret'
  await flow.submitPassword()
  flow.factor.value = '12a'
  assert.equal(await flow.submitMfa(), false)
  assert.match(flow.error.value, /6-digit/)
  assert.equal(session.calls.length, 1)
})

test('expired MFA challenge returns to password step', async () => {
  const session = fakeSession({
    login: () => ({ mfaRequired: true }),
    mfaLogin: () => { throw new AuthError('mfa_challenge', 'Sign in again.', 401) },
  })
  const flow = createLoginFlow(session)
  flow.form.username = 'ada'; flow.form.password = 'secret'
  await flow.submitPassword()
  flow.factor.value = '123456'
  await flow.submitMfa()
  assert.equal(flow.stage.value, 'password')
  assert.match(flow.error.value, /expired|again/i)
})

test('network failure surfaces a fail-closed message and keeps user signed out', async () => {
  const flow = createLoginFlow(fakeSession({ login: () => { throw new AuthError('network', 'Cannot reach the panel backend.', 0) } }))
  flow.form.username = 'ada'; flow.form.password = 'secret'
  assert.equal(await flow.submitPassword(), false)
  assert.equal(flow.stage.value, 'password')
  assert.equal(flow.error.value, 'Cannot reach the panel backend.')
  assert.equal(flow.form.password, '')
})

test('reset clears every secret and returns to password stage', async () => {
  const flow = createLoginFlow(fakeSession({ login: () => ({ mfaRequired: true }) }))
  flow.form.username = 'ada'; flow.form.password = 'secret'
  await flow.submitPassword()
  flow.factor.value = '123'
  flow.reset()
  assert.equal(flow.stage.value, 'password')
  assert.equal(flow.factor.value, '')
  assert.equal(flow.form.password, '')
  assert.equal(flow.useRecovery.value, false)
})

test('LoginView uses the real flow with no demo codes or web storage', () => {
  const src = readFileSync(new URL('../src/views/LoginView.vue', import.meta.url), 'utf8')
  assert.match(src, /createLoginFlow/)
  assert.doesNotMatch(src, /123456|123 456|localStorage|sessionStorage|Demo password|simulated/i)
  assert.match(src, /autocomplete="current-password"/)
  assert.match(src, /autocomplete="one-time-code"/)
})
