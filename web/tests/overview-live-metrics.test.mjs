import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadHost } from '../src/system/host.js'
const info = { connected: true, hostname: 'real-host', os: 'Linux', arch: 'amd64', kernel: '6.8', version: 'dev', protocol: 1, capability_revision: 'rev' }
const stats = { load1: 0, load5: 0, load15: 0, mem_total_bytes: 1024, mem_available_bytes: 256, uptime_seconds: 0 }
const metrics = {
  cpu: { usage_percent: 0, logical_cpus: 1 }, cpu_reason: '',
  disk: { mount: '/', total_bytes: 1024, used_bytes: 0, available_bytes: 1024 }, disk_reason: '',
  network: { interface: 'ens3', rx_bytes_per_second: 0, tx_bytes_per_second: 42.5 }, network_reason: '',
  observed_at: '2026-11-04T10:00:00.123456789Z',
}
const fetchMetrics = body => async url => ({ ok: true, status: 200, json: async () => url.endsWith('/info') ? info : url.endsWith('/stats') ? stats : body })

test('metrics contract accepts real zero usage and resource-specific unavailable reasons', async () => {
  assert.deepEqual((await loadHost(fetchMetrics(metrics))).metrics, metrics)
  const partial = { ...metrics, cpu: null, cpu_reason: 'read_failed' }
  const host = await loadHost(fetchMetrics(partial))
  assert.deepEqual(host.metrics, partial)
  assert.equal(host.stats, stats)
})

const invalid = [null, [], {}, { ...metrics, observed_at: 'yesterday' }, { ...metrics, observed_at: '2026-99-99T00:00:00Z' },
  { ...metrics, cpu: null }, { ...metrics, cpu_reason: 'unsupported' }, { ...metrics, disk: null, disk_reason: ' ' },
  ...[-1, 101, Infinity, '4'].map(usage_percent => ({ ...metrics, cpu: { ...metrics.cpu, usage_percent } })),
  ...[0, 1.5, '1'].map(logical_cpus => ({ ...metrics, cpu: { ...metrics.cpu, logical_cpus } })),
  { ...metrics, disk: { ...metrics.disk, mount: '/home' } }, { ...metrics, disk: { ...metrics.disk, total_bytes: 0 } },
  { ...metrics, disk: { ...metrics.disk, used_bytes: 1 } }, { ...metrics, disk: { ...metrics.disk, available_bytes: -1 } },
  { ...metrics, network: { ...metrics.network, interface: ' ' } },
  { ...metrics, network: { ...metrics.network, rx_bytes_per_second: -1 } },
  { ...metrics, network: { ...metrics.network, tx_bytes_per_second: '1' } },
  { ...metrics, network_reason: null },
  ...['cpu', 'disk', 'network'].map(resource => ({ ...metrics, [resource]: null, [resource + '_reason']: 'unsupported' })),
  ...['cpu', 'disk'].map(resource => ({ ...metrics, [resource]: null, [resource + '_reason']: 'no_default_route' })),
  ...['lo', '.', '..', 'eth/0', ' space', 'eth0\n', 'abcdefghijklmnop'].map(interfaceName => ({ ...metrics, network: { ...metrics.network, interface: interfaceName } })),
  ...['total_bytes', 'used_bytes', 'available_bytes'].flatMap(key => [0.5, Number.MAX_SAFE_INTEGER + 1].map(value => ({ ...metrics, disk: { ...metrics.disk, [key]: value } }))),
]
for (const [index, body] of invalid.entries()) {
  test(`malformed metrics fail closed but preserve valid RAM: ${index}`, async () => {
    const host = await loadHost(fetchMetrics(body))
    assert.equal(host.metrics, null)
    assert.equal(host.metricsReason, 'invalid_response')
    assert.equal(host.stats, stats)
  })
}

test('metrics HTTP 401 clears host identity through callback even with misleading error code', async () => {
  let checks = 0
  const host = await loadHost(async url => url.endsWith('/metrics')
    ? { ok: false, status: 401, json: async () => ({ error: { code: 'wrong' } }) }
    : fetchMetrics(metrics)(url), { onUnauthorized: async () => { checks++ } })
  assert.equal(checks, 1)
  assert.equal(host.connected, false)
  assert.equal(host.reason, 'unauthorized')
  assert.equal(host.info, null)
  assert.equal(host.stats, null)
  assert.equal(host.metrics ?? null, null)
})

for (const mode of ['network', 'http', 'json']) {
  test(`metrics ${mode} failure keeps RAM, clears metrics`, async () => {
    const host = await loadHost(async url => {
      if (!url.endsWith('/metrics')) return fetchMetrics(metrics)(url)
      if (mode === 'network') throw new Error('offline')
      return { ok: mode !== 'http', status: mode === 'http' ? 503 : 200, json: async () => {
        if (mode === 'json') throw new SyntaxError('bad')
        return { error: { code: 'agent_unavailable' } }
      } }
    })
    assert.equal(host.stats, stats)
    assert.equal(host.metrics, null)
    assert.equal(host.metricsReason, mode === 'http' ? 'agent_unavailable' : mode === 'json' ? 'invalid_response' : 'network')
  })
}
