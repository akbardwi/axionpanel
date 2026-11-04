// Real host data from the panel's authenticated, read-only system API.
// Failures are reported as states; this module never substitutes example data.

async function getJSON(fetchFn, url) {
  const res = await fetchFn(url, {
    method: 'GET',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    cache: 'no-store',
  })
  let body = null
  try { body = await res.json() } catch { body = null }
  if (!res.ok) {
    const code = body?.error?.code || (res.status === 401 ? 'unauthorized' : 'http_' + res.status)
    return { ok: false, reason: code, status: res.status }
  }
  return { ok: true, body, status: res.status }
}

const isText = v => typeof v === 'string' && v.trim() !== ''
const isCount = v => typeof v === 'number' && Number.isFinite(v) && v >= 0

// The panel API must return the agent's real schema. A 200 with a null,
// non-JSON or shape-shifted body is a failure, never "connected with no data".
function validInfo(body) {
  return Boolean(body) && typeof body === 'object' && !Array.isArray(body) &&
    body.connected === true &&
    isText(body.hostname) && isText(body.os) && isText(body.arch) &&
    isText(body.kernel) && isText(body.version) &&
    Number.isInteger(body.protocol) && body.protocol > 0 &&
    isText(body.capability_revision)
}

function validStats(body) {
  return Boolean(body) && !Array.isArray(body) &&
    ['load1', 'load5', 'load15', 'mem_total_bytes', 'mem_available_bytes', 'uptime_seconds'].every(key => isCount(body[key])) &&
    body.mem_total_bytes > 0 && body.mem_available_bytes <= body.mem_total_bytes
}

// RFC3339 (seconds precision or finer) is required so the UI can stamp reads
// honestly. Null resources are allowed only with a closed-set reason, and a
// present resource must carry an empty reason — the API never half-reports.
const isRFC3339 = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v))
const isPct = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100
const isPosInt = v => Number.isInteger(v) && v > 0
// Match the backend's sanitized resource reasons; arbitrary error text and
// host paths must never pass as a valid unavailable resource.
const validReason = (key, reason) => reason === 'read_failed' || reason === 'invalid_data' ||
  (key === 'network' && reason === 'no_default_route')
const resourceOk = (body, key, shape) => shape(body[key])
  ? body[key + '_reason'] === ''
  : body[key] === null && validReason(key, body[key + '_reason'])
const isObj = v => Boolean(v) && typeof v === 'object' && !Array.isArray(v)
const cpuShape = c => isObj(c) && isPct(c.usage_percent) && isPosInt(c.logical_cpus)
const isByteCount = v => Number.isSafeInteger(v) && v >= 0
const diskShape = d => isObj(d) && d.mount === '/' && isByteCount(d.total_bytes) && d.total_bytes > 0 &&
  isByteCount(d.used_bytes) && isByteCount(d.available_bytes) && d.used_bytes <= d.total_bytes &&
  d.available_bytes <= d.total_bytes - d.used_bytes
const validInterface = name => typeof name === 'string' && name.length >= 1 && name.length <= 15 &&
  !/[^A-Za-z0-9_.@-]/.test(name) && !['lo', '.', '..'].includes(name)
const networkShape = n => isObj(n) && validInterface(n.interface) && isCount(n.rx_bytes_per_second) && isCount(n.tx_bytes_per_second)

function validMetrics(body) {
  return isObj(body) && isRFC3339(body.observed_at) &&
    resourceOk(body, 'cpu', cpuShape) && resourceOk(body, 'disk', diskShape) && resourceOk(body, 'network', networkShape)
}

export async function loadHost(fetchFn = globalThis.fetch.bind(globalThis), { onUnauthorized = async () => {} } = {}) {
  async function unauthorized() {
    // Revalidate via session.check(), not expire(): its generation guard keeps
    // an older /me response from clearing a newer login/MFA identity.
    await onUnauthorized()
    return { connected: false, reason: 'unauthorized', info: null, stats: null }
  }
  let info
  try {
    info = await getJSON(fetchFn, '/api/v1/system/info')
  } catch {
    return { connected: false, reason: 'network', info: null, stats: null }
  }
  if (info.status === 401) return unauthorized()
  if (!info.ok) return { connected: false, reason: info.reason, info: null, stats: null }
  if (!validInfo(info.body)) return { connected: false, reason: 'invalid_response', info: null, stats: null }

  let stats
  try {
    stats = await getJSON(fetchFn, '/api/v1/system/stats')
  } catch {
    stats = { ok: false, reason: 'network' }
  }
  if (stats.status === 401) return unauthorized()
  if (stats.ok && !validStats(stats.body)) stats = { ok: false, reason: 'invalid_response' }

  let metrics
  try {
    metrics = await getJSON(fetchFn, '/api/v1/system/metrics')
  } catch {
    metrics = { ok: false, reason: 'network' }
  }
  if (metrics.status === 401) return unauthorized()
  if (metrics.ok && !validMetrics(metrics.body)) metrics = { ok: false, reason: 'invalid_response' }
  return {
    connected: true,
    reason: '',
    info: info.body,
    stats: stats.ok ? stats.body : null,
    statsReason: stats.ok ? '' : stats.reason,
    metrics: metrics.ok ? metrics.body : null,
    metricsReason: metrics.ok ? '' : metrics.reason,
  }
}

export function formatBytes(n) {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(1)} ${units[i]}`
}

export function formatUptime(s) {
  if (typeof s !== 'number' || !Number.isFinite(s) || s < 0) return '—'
  const sec = Math.floor(s)
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m ${sec % 60}s`
}

export const reasonText = {
  agent_unavailable: 'The host agent is not reachable. Start axionpanel-agent and check the -agent-socket path.',
  agent_error: 'The host agent reported an error.',
  unauthorized: 'Sign in to view host data.',
  network: 'The panel API could not be reached.',
  invalid_response: 'The panel API returned an unreadable host response.',
}
