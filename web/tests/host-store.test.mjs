import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
const read = p => readFileSync(new URL('../' + p, import.meta.url), 'utf8')

// Sidebar release is tested against the actual App/Overview router lifecycle
// in overview-lifecycle-browser.spec.js, using the existing axp:host event.

test('overview keeps staleness on a reactive clock, not the last metrics read', () => {
  const view = read('src/views/OverviewView.vue')
  assert.match(view, /setInterval\(/, 'a mounted clock must tick')
  assert.match(view, /clearInterval\(/, 'the clock must be cleaned up on unmount')
  assert.match(view, /staleAfter\(host\.value\?\.metrics,\s*now\.value\)/, 'stale must be computed from the reactive clock')
})

test('overview drops late 401 side effects after unmount', () => {
  const view = read('src/views/OverviewView.vue')
  assert.match(view, /let disposed = false/, 'onUnauthorized must be guarded by a disposed flag')
  assert.match(view, /if \(disposed\) return/, 'the unauthorized callback must bail out once disposed')
  assert.match(view, /onUnmounted\([\s\S]*?disposed = true[\s\S]*?poller\?\.stop\(\)/, 'unmount must mark disposed before stopping the poller')
})

test('formatRate rounds sub-1024 throughput to whole bytes', async () => {
  const { formatRate } = await import('../src/system/overview.js')
  assert.equal(formatRate(15.98082301238514), '16 B/s')
  assert.equal(formatRate(0.4), '0 B/s')
  assert.equal(formatRate(2048), '2.0 KiB/s')
})

test('host reader rejects metrics the backend would refuse', async () => {
  const { loadHost } = await import('../src/system/host.js')
  const base = {
    observed_at: '2026-11-04T12:00:00Z',
    cpu: { usage_percent: 3, logical_cpus: 4 }, cpu_reason: '',
    disk: { mount: '/', total_bytes: 1000, used_bytes: 400, available_bytes: 600 }, disk_reason: '',
    network: { interface: 'eth0', rx_bytes_per_second: 0, tx_bytes_per_second: 0 }, network_reason: '',
  }
  const badReason = { ...base, cpu: null, cpu_reason: 'unsupported' }
  const badInterface = { ...base, network: { interface: 'lo', rx_bytes_per_second: 0, tx_bytes_per_second: 0 }, network_reason: '' }
  const fractional = { ...base, disk: { mount: '/', total_bytes: 1000.5, used_bytes: 400, available_bytes: 600 }, disk_reason: '' }
  for (const metrics of [badReason, badInterface, fractional]) {
    const fakeFetch = async (url) => {
      if (url.endsWith('/info')) return { ok: true, status: 200, json: async () => ({ connected: true, hostname: 'h', os: 'os', arch: 'a', kernel: 'k', version: 'v', protocol: 1, capability_revision: 'r' }) }
      if (url.endsWith('/stats')) return { ok: true, status: 200, json: async () => ({ load1: 0, load5: 0, load15: 0, mem_total_bytes: 100, mem_available_bytes: 50, uptime_seconds: 1 }) }
      return { ok: true, status: 200, json: async () => metrics }
    }
    const result = await loadHost(fakeFetch)
    assert.equal(result.metrics, null, 'malformed metrics must be rejected, not accepted')
    assert.equal(result.metricsReason, 'invalid_response')
  }
})
