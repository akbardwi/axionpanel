import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadHost, formatBytes, formatUptime } from '../src/system/host.js'
import { createSessionStore } from '../src/auth/session.js'

const validInfo = { connected: true, hostname: 'node-01', os: 'Ubuntu 26.04', arch: 'amd64', kernel: '7.0.0', version: '0.1.0-dev', protocol: 1, detected_tools: {}, capabilities: {}, capability_revision: 'rev1', observed_at: '2026-11-03T10:00:00Z', operations: ['system.stats'] }
const validStats = { load1: 0.5, load5: 0.4, load15: 0.3, mem_total_bytes: 1024, mem_available_bytes: 512, uptime_seconds: 90, observed_at: '2026-11-03T10:00:00Z' }

const validMetrics = {
  cpu: { usage_percent: 34.2, logical_cpus: 4 }, cpu_reason: '',
  disk: { mount: '/', total_bytes: 160 * 1024 ** 3, used_bytes: 58 * 1024 ** 3, available_bytes: 102 * 1024 ** 3 }, disk_reason: '',
  network: { interface: 'eth0', rx_bytes_per_second: 1024 * 1024, tx_bytes_per_second: 512 * 1024 }, network_reason: '',
  observed_at: '2026-11-03T10:00:05Z',
}

function stubFetch(routes) {
  const calls = []
  const fn = async (url, opts) => {
    calls.push({ url, opts })
    const route = routes[url]
    if (!route) throw new Error('unexpected ' + url)
    return {
      ok: route.status >= 200 && route.status < 300,
      status: route.status,
      json: async () => route.body,
    }
  }
  fn.calls = calls
  return fn
}

test('loadHost returns info and stats from the panel API', async () => {
  const f = stubFetch({
    '/api/v1/system/info': { status: 200, body: validInfo },
    '/api/v1/system/stats': { status: 200, body: validStats },
  })
  const host = await loadHost(f)
  assert.equal(host.connected, true)
  assert.equal(host.info.hostname, 'node-01')
  assert.equal(host.stats.load1, 0.5)
  assert.deepEqual(f.calls.map(c => c.url), ['/api/v1/system/info', '/api/v1/system/stats', '/api/v1/system/metrics'])
  assert.equal(host.metrics, null)
  assert.equal(host.metricsReason, 'network')
  assert.equal(f.calls[0].opts.credentials, 'same-origin')
})

test('loadHost reports signed-out sessions without inventing data', async () => {
  const f = stubFetch({
    '/api/v1/system/info': { status: 401, body: { error: { code: 'unauthorized' } } },
  })
  const host = await loadHost(f)
  assert.equal(host.connected, false)
  assert.equal(host.reason, 'unauthorized')
  assert.equal(host.info, null)
  assert.equal(f.calls.length, 1)
})

test('loadHost reports an unreachable agent', async () => {
  const f = stubFetch({
    '/api/v1/system/info': { status: 503, body: { error: { code: 'agent_unavailable' } } },
  })
  const host = await loadHost(f)
  assert.equal(host.connected, false)
  assert.equal(host.reason, 'agent_unavailable')
})

test('loadHost reports network failure without throwing', async () => {
  const host = await loadHost(async () => { throw new Error('offline') })
  assert.equal(host.connected, false)
  assert.equal(host.reason, 'network')
})

test('loadHost keeps info when stats fail', async () => {
  const f = stubFetch({
    '/api/v1/system/info': { status: 200, body: validInfo },
    '/api/v1/system/stats': { status: 503, body: { error: { code: 'agent_unavailable' } } },
  })
  const host = await loadHost(f)
  assert.equal(host.connected, true)
  assert.equal(host.stats, null)
  assert.equal(host.statsReason, 'agent_unavailable')
})

for (const body of [null, [], 'not info', {}, { ...validInfo, connected: false }, { ...validInfo, hostname: null }, { ...validInfo, os: 42 }, { ...validInfo, protocol: '1' }]) {
  test(`loadHost rejects malformed successful info: ${JSON.stringify(body)}`, async () => {
    const f = stubFetch({ '/api/v1/system/info': { status: 200, body } })
    const host = await loadHost(f)
    assert.deepEqual(host, { connected: false, reason: 'invalid_response', info: null, stats: null })
    assert.equal(f.calls.length, 1)
  })
}

for (const protocol of [-1, 0, 1.5, Infinity]) {
  test(`loadHost rejects invalid info protocol ${protocol}`, async () => {
    const host = await loadHost(stubFetch({ '/api/v1/system/info': { status: 200, body: { ...validInfo, protocol } } }))
    assert.equal(host.connected, false)
    assert.equal(host.reason, 'invalid_response')
  })
}

test('loadHost rejects invalid JSON in successful info', async () => {
  const host = await loadHost(async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('invalid JSON') } }))
  assert.equal(host.reason, 'invalid_response')
  assert.equal(host.connected, false)
})

const malformedStats = [null, [], {}, { load1: 1 }, ...['load1', 'load5', 'load15', 'mem_total_bytes', 'mem_available_bytes', 'uptime_seconds'].flatMap(key => [
  { ...validStats, [key]: undefined }, { ...validStats, [key]: '1' },
  { ...validStats, [key]: -1 }, { ...validStats, [key]: Infinity },
]), { ...validStats, mem_total_bytes: 0 }, { ...validStats, mem_available_bytes: 2048 }]
for (const [index, body] of malformedStats.entries()) {
  test(`loadHost rejects malformed stats without inventing metrics: ${index}`, async () => {
    const f = stubFetch({
      '/api/v1/system/info': { status: 200, body: validInfo },
      '/api/v1/system/stats': { status: 200, body },
      '/api/v1/system/metrics': { status: 200, body: validMetrics },
    })
    const host = await loadHost(f)
    assert.equal(host.connected, true)
    assert.equal(host.info, validInfo)
    assert.equal(host.stats, null)
    assert.equal(host.statsReason, 'invalid_response')
  })
}

test('loadHost rejects invalid JSON in successful stats', async () => {
  const host = await loadHost(async url => ({ ok: true, status: 200, json: async () => {
    if (url.endsWith('/info')) return validInfo
    throw new SyntaxError('invalid JSON')
  } }))
  assert.equal(host.stats, null)
  assert.equal(host.statsReason, 'invalid_response')
})

for (const endpoint of ['info', 'stats']) {
  for (const body of [null, { error: { code: 'different_code' } }]) {
    test(`loadHost propagates ${endpoint} HTTP 401 and clears all details: ${JSON.stringify(body)}`, async () => {
      const f = stubFetch({
        '/api/v1/system/info': { status: 200, body: validInfo },
        '/api/v1/system/stats': { status: 200, body: validStats },
        ['/api/v1/system/' + endpoint]: { status: 401, body },
      })
      let checks = 0
      const store = createSessionStore({ client: { me: async () => { checks++; throw Object.assign(new Error('expired'), { status: 401 }) } } })
      store.state.status = 'authenticated'
      store.state.user = { username: 'ada', role: 'operator' }
      const host = await loadHost(f, { onUnauthorized: () => store.check() })
      assert.equal(checks, 1)
      assert.equal(store.state.status, 'unauthenticated')
      assert.equal(store.state.user, null)
      assert.deepEqual(host, { connected: false, reason: 'unauthorized', info: null, stats: null })
    })
  }
}

test('a stale system 401 recheck cannot expire a newly authenticated session', { timeout: 1000 }, async () => {
  let release
  let started
  const checking = new Promise(resolve => { started = resolve })
  const store = createSessionStore({ client: {
    me: () => { started(); return new Promise((_, reject) => { release = () => reject(Object.assign(new Error('expired'), { status: 401 })) }) },
    login: async () => ({ user: { username: 'new-user', role: 'admin' }, csrfToken: 'new-token', mfaRequired: false }),
  } })
  store.state.status = 'authenticated'
  const request = loadHost(stubFetch({ '/api/v1/system/info': { status: 401, body: null } }), { onUnauthorized: () => store.check() })
  await checking
  await store.login('new-user', 'test-only')
  release()
  await request
  assert.equal(store.state.status, 'authenticated')
  assert.equal(store.state.user.username, 'new-user')
})

test('formatBytes and formatUptime stay readable', () => {
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(1024), '1.0 KiB')
  assert.equal(formatBytes(8 * 1024 ** 3), '8.0 GiB')
  assert.equal(formatBytes(-1), '—')
  assert.equal(formatUptime(90), '1m 30s')
  assert.equal(formatUptime(90061), '1d 1h')
  assert.equal(formatUptime(null), '—')
})
