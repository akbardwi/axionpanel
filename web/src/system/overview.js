// View-model helpers for the Overview dashboard. They only reshape values
// already returned (and validated) by loadHost; they never invent data,
// history or trends. Every card is either available with real values or
// unavailable with a reason code.
import { formatBytes, formatUptime } from './host.js'

export const POLL_INTERVAL_MS = 5000
const STALE_AFTER_MS = POLL_INTERVAL_MS * 3

const isNum = v => typeof v === 'number' && Number.isFinite(v)

function unavailable(reason) {
  return { available: false, reason: reason || 'invalid_response' }
}

// Reason for the whole host read (agent down, 401, network) or for a missing
// metrics response; resource-specific reasons are handled by each card.
function metricsReason(host, preview = false) {
  if (preview) return 'design_preview'
  if (!host) return 'loading'
  if (!host.connected) return host.reason || 'invalid_response'
  if (!host.metrics) return host.metricsReason || 'invalid_response'
  return ''
}

export function hostSummary(host, { loading = false, preview = false } = {}) {
  const info = host?.connected ? host.info : null
  const stats = host?.connected ? host.stats : null
  let linkStatus = 'unavailable'
  if (preview) linkStatus = 'preview'
  else if (loading || !host) linkStatus = 'loading'
  else if (host.connected) linkStatus = 'live'
  return {
    linkStatus,
    reason: host && !host.connected ? host.reason : '',
    hostname: info?.hostname ?? null,
    os: info?.os ?? null,
    kernel: info?.kernel ?? null,
    arch: info?.arch ?? null,
    agentVersion: info?.version ?? null,
    uptime: stats ? formatUptime(stats.uptime_seconds) : null,
    totalRam: stats ? formatBytes(stats.mem_total_bytes) : null,
  }
}

export function cpuCard(host, { preview = false } = {}) {
  const reason = metricsReason(host, preview)
  const stats = host?.connected ? host.stats : null
  const load = stats ? [stats.load1, stats.load5, stats.load15].map(n => n.toFixed(2)).join(' / ') : null
  // No CPU history endpoint exists: the sparkline stays unavailable.
  const base = { percent: null, logicalCpus: null, load, history: null }
  if (reason) return { ...base, ...unavailable(reason) }
  const cpu = host.metrics.cpu
  if (!cpu) return { ...base, ...unavailable(host.metrics.cpu_reason) }
  return { ...base, available: true, reason: '', percent: cpu.usage_percent, logicalCpus: cpu.logical_cpus }
}

export function memoryCard(host, { preview = false } = {}) {
  const base = { usedBytes: null, totalBytes: null, availableBytes: null, usedPercent: null, statsReason: '' }
  if (preview) return { ...base, ...unavailable('design_preview') }
  if (!host) return { ...base, ...unavailable('loading') }
  if (!host.connected) return { ...base, ...unavailable(host.reason) }
  const s = host.stats
  if (!s) return { ...base, ...unavailable(host.statsReason), statsReason: host.statsReason || 'invalid_response' }
  const used = s.mem_total_bytes - s.mem_available_bytes
  return {
    available: true, reason: '', statsReason: '',
    usedBytes: used, totalBytes: s.mem_total_bytes, availableBytes: s.mem_available_bytes,
    usedPercent: (used / s.mem_total_bytes) * 100,
  }
}

export function diskCard(host, { preview = false } = {}) {
  const base = { mount: '/', usedBytes: null, totalBytes: null, availableBytes: null, usedPercent: null }
  const reason = metricsReason(host, preview)
  if (reason) return { ...base, ...unavailable(reason) }
  const d = host.metrics.disk
  if (!d) return { ...base, ...unavailable(host.metrics.disk_reason) }
  return {
    available: true, reason: '', mount: d.mount,
    usedBytes: d.used_bytes, totalBytes: d.total_bytes, availableBytes: d.available_bytes,
    usedPercent: (d.used_bytes / d.total_bytes) * 100,
  }
}

export function networkCard(host, { preview = false } = {}) {
  const base = { interface: null, rxBytesPerSecond: null, txBytesPerSecond: null }
  const reason = metricsReason(host, preview)
  if (reason) return { ...base, ...unavailable(reason) }
  const n = host.metrics.network
  if (!n) return { ...base, ...unavailable(host.metrics.network_reason) }
  return { available: true, reason: '', interface: n.interface, rxBytesPerSecond: n.rx_bytes_per_second, txBytesPerSecond: n.tx_bytes_per_second }
}

// True when the agent's observation is older than three poll intervals, so the
// UI can say the values are stale instead of presenting them as current.
export function staleAfter(metrics, now = Date.now()) {
  if (!metrics?.observed_at) return false
  const t = Date.parse(metrics.observed_at)
  return Number.isFinite(t) && now - t > STALE_AFTER_MS
}

export function formatRate(n) {
  if (!isNum(n) || n < 0) return '—'
  return n < 1024 ? `${Math.round(n)} B/s` : `${formatBytes(n)}/s`
}

export function formatPercent(n) {
  return isNum(n) && n >= 0 ? `${n.toFixed(1)}%` : '—'
}
