import test from 'node:test'
import assert from 'node:assert/strict'
import { createSitesClient } from '../src/lib/sitesClient.js'

const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body })

test('sites client uses same-origin API, existing CSRF cookie and exact mutation bodies without a short timeout', async () => {
  const calls = []
  const client = createSitesClient({ getCookie: () => 'axp_csrf=current-token', getCSRF: () => 'stale', fetchImpl: async (...args) => { calls.push(args); return response({}) } })
  await client.list()
  await client.capabilities()
  await client.plan('app.example.com')
  await client.create('app.example.com')
  await client.remove(7, 'app.example.com')
  await client.reauth({ password: 'test-only', code: '123456' })
  assert.deepEqual(calls.map(([url]) => url), ['/api/v1/sites', '/api/v1/system/info', '/api/v1/sites/plan?domain=app.example.com', '/api/v1/sites', '/api/v1/sites/7', '/api/v1/auth/reauth'])
  for (const [, options] of calls) {
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.signal, undefined)
  }
  assert.equal(calls[3][1].headers['X-CSRF-Token'], 'current-token')
  assert.deepEqual(JSON.parse(calls[3][1].body), { domain: 'app.example.com' })
  assert.deepEqual(JSON.parse(calls[4][1].body), { confirm_domain: 'app.example.com' })
  assert.equal(calls[4][1].method, 'DELETE')
  assert.deepEqual(JSON.parse(calls[5][1].body), { password: 'test-only', code: '123456' })
})

test('HTTP errors preserve code and status and revalidate unauthorized sessions', async () => {
  let checks = 0
  const client = createSitesClient({ fetchImpl: async () => response({ error: { code: 'unauthorized', message: 'Sign in required.' } }, 401), onUnauthorized: async () => { checks++ } })
  await assert.rejects(client.list(), { code: 'unauthorized', status: 401 })
  assert.equal(checks, 1)
})

test('network and malformed responses are explicit failures, never empty inventory', async () => {
  const client = createSitesClient({ fetchImpl: async () => { throw new Error('private detail') } })
  await assert.rejects(client.list(), { code: 'network', status: 0 })
  const malformed = createSitesClient({ fetchImpl: async () => ({ ok: true, status: 200, json: async () => { throw new Error('bad json') } }) })
  await assert.rejects(malformed.create('app.example.com'), { code: 'invalid_response' })
})
