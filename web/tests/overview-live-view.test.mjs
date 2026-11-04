import { test } from 'node:test'
import assert from 'node:assert/strict'
import { hostSummary, cpuCard, memoryCard, diskCard, networkCard, formatRate, formatPercent, staleAfter } from '../src/system/overview.js'

const info = { connected: true, hostname: 'web-01', os: 'Debian GNU/Linux 13', arch: 'arm64', kernel: '6.8.12', version: '0.1.0', protocol: 1, capability_revision: 'r' }
const stats = { load1: 1.5, load5: 1, load15: 0.5, mem_total_bytes: 8 * 1024 ** 3, mem_available_bytes: 2 * 1024 ** 3, uptime_seconds: 93784 }
const metrics = {
  cpu: { usage_percent: 12.5, logical_cpus: 4 }, cpu_reason: '',
  disk: { mount: '/', total_bytes: 100 * 1024 ** 3, used_bytes: 61 * 1024 ** 3, available_bytes: 39 * 1024 ** 3 }, disk_reason: '',
  network: { interface: 'ens3', rx_bytes_per_second: 2 * 1024 ** 2, tx_bytes_per_second: 512 * 1024 }, network_reason: '',
  observed_at: '2026-11-04T10:00:00Z',
}
const host = { connected: true, reason: '', info, stats, statsReason: '', metrics, metricsReason: '' }

test('header shows real identity and uptime, never sample node/IP/DC', () => {
  const header = hostSummary(host)
  assert.equal(header.hostname, 'web-01')
  assert.equal(header.os, 'Debian GNU/Linux 13')
  assert.equal(header.kernel, '6.8.12')
  assert.equal(header.arch, 'arm64')
  assert.equal(header.uptime, '1d 2h')
  assert.equal(header.totalRam, '8.0 GiB')
  assert.equal(header.linkStatus, 'live')
  const text = JSON.stringify(header)
  for (const sample of ['node-01', '203.0.113.10', 'SGP-DC-02', 'Ubuntu 24.04', '99.98%']) assert.ok(!text.includes(sample), sample)
})

test('header marks unavailable identity explicitly instead of filling samples', () => {
  const header = hostSummary({ connected: false, reason: 'agent_unavailable', info: null, stats: null })
  assert.equal(header.hostname, null)
  assert.equal(header.os, null)
  assert.equal(header.uptime, null)
  assert.equal(header.linkStatus, 'unavailable')
  assert.equal(hostSummary(null).linkStatus, 'loading')
  assert.equal(hostSummary(host, { loading: true }).linkStatus, 'loading')
  assert.equal(hostSummary(host, { preview: true }).linkStatus, 'preview')
})

test('CPU card reports real percent and logical CPUs, no invented model or trend', () => {
  const card = cpuCard(host)
  assert.equal(card.available, true)
  assert.equal(card.percent, 12.5)
  assert.equal(card.logicalCpus, 4)
  assert.equal(card.load, '1.50 / 1.00 / 0.50')
  assert.equal(card.history, null)
  assert.equal(cpuCard({ ...host, metrics: { ...metrics, cpu: null, cpu_reason: 'read_failed' } }).reason, 'read_failed')
  assert.equal(cpuCard({ ...host, metrics: null, metricsReason: 'network' }).reason, 'network')
  assert.equal(cpuCard({ connected: false, reason: 'agent_unavailable' }).percent, null)
})

test('memory card reports actual used from total minus available', () => {
  const card = memoryCard(host)
  assert.equal(card.available, true)
  assert.equal(card.usedBytes, 6 * 1024 ** 3)
  assert.equal(card.totalBytes, 8 * 1024 ** 3)
  assert.equal(card.usedPercent, 75)
  assert.equal(card.statsReason, '')
  const noStats = memoryCard({ ...host, stats: null, statsReason: 'agent_error' })
  assert.equal(noStats.available, false)
  assert.equal(noStats.reason, 'agent_error')
  assert.equal(noStats.usedBytes, null)
})

test('disk card reports root filesystem actual usage', () => {
  const card = diskCard(host)
  assert.equal(card.available, true)
  assert.equal(card.usedBytes, 61 * 1024 ** 3)
  assert.equal(card.totalBytes, 100 * 1024 ** 3)
  assert.equal(card.availableBytes, 39 * 1024 ** 3)
  assert.equal(card.usedPercent, 61)
  for (const [patch, reason] of [
    [{ disk: null, disk_reason: 'read_failed' }, 'read_failed'],
    [{ disk: null, disk_reason: '' }, 'invalid_response'],
  ]) {
    const result = diskCard({ ...host, metrics: { ...metrics, ...patch } })
    assert.equal(result.available, false)
    assert.equal(result.reason, reason)
    assert.equal(result.usedBytes, null)
  }
})

test('network card reports chosen interface throughput', () => {
  const card = networkCard(host)
  assert.equal(card.available, true)
  assert.equal(card.interface, 'ens3')
  assert.equal(card.rxBytesPerSecond, 2 * 1024 ** 2)
  assert.equal(card.txBytesPerSecond, 512 * 1024)
  assert.equal(networkCard({ ...host, metrics: { ...metrics, network: null, network_reason: 'no_default_route' } }).reason, 'no_default_route')
})

test('metrics older than three poll intervals are flagged stale without inventing history', () => {
  const now = Date.parse('2026-11-04T10:00:20Z')
  assert.equal(staleAfter(metrics, now), true)
  assert.equal(staleAfter({ ...metrics, observed_at: '2026-11-04T10:00:14Z' }, now), false)
  assert.equal(staleAfter(null, now), false)
})

test('design preview cards say not loaded, never perpetually loading', () => {
  for (const card of [cpuCard, memoryCard, diskCard, networkCard]) {
    const result = card(null, { preview: true })
    assert.equal(result.available, false)
    assert.equal(result.reason, 'design_preview')
  }
})

test('rate and percent formatting stay honest', () => {
  assert.equal(formatRate(0), '0 B/s')
  assert.equal(formatRate(1536), '1.5 KiB/s')
  assert.equal(formatRate(null), '—')
  assert.equal(formatPercent(12.5), '12.5%')
  assert.equal(formatPercent(0), '0.0%')
  assert.equal(formatPercent(-1), '—')
})
