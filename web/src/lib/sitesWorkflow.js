import { reactive } from 'vue'

// Website inventory/mutation state. Every value here comes from the panel API;
// failures are states, never substituted examples. Mutations are synchronous up
// to 90s, so a lost response is ambiguous and is never retried automatically.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
const STATUSES = new Set(['provisioning', 'active', 'error', 'deleting', 'deleted'])
const UNKNOWN_OUTCOME = new Set(['manual_reconciliation', 'interrupted_manual_reconciliation', 'network', 'agent_error'])
const ambiguous = err => Boolean(err) && (err.status >= 500 || err.code === 'network' || err.code === 'manual_reconciliation' || (err.status === 200 && err.code === 'invalid_response'))
// Unreadable mutation-response handling is covered by the client integration tests.

export function normalizeDomain(value) {
  return String(value ?? '').trim().toLowerCase()
}

export function domainProblem(value) {
  const domain = normalizeDomain(value)
  if (!domain) return 'Enter a domain, for example app.example.com.'
  if (!DOMAIN_RE.test(domain)) return 'Enter a lowercase DNS domain such as app.example.com.'
  return ''
}

const isText = v => typeof v === 'string' && v.trim() !== ''
const isObject = v => Boolean(v) && typeof v === 'object' && !Array.isArray(v)

export function validSite(site) {
  return isObject(site) && Number.isInteger(site.id) && site.id > 0 &&
    isText(site.domain) && normalizeDomain(site.domain) === site.domain &&
    site.kind === 'static' && typeof site.root === 'string' &&
    STATUSES.has(site.status) &&
    (site.listen === undefined || typeof site.listen === 'string') &&
    typeof site.retained_content === 'boolean' &&
    (site.last_error === undefined || typeof site.last_error === 'string')
}

export function validInventory(body) {
  if (!isObject(body) || !Array.isArray(body.data)) return null
  const seen = new Set()
  for (const site of body.data) {
    if (!validSite(site) || seen.has(site.id)) return null
    seen.add(site.id)
  }
  return { sites: body.data, total: Number.isInteger(body.meta?.total) ? body.meta.total : body.data.length }
}

export function validPlan(body, domain) {
  return isObject(body) && body.domain === domain && isText(body.vhost) && isText(body.root) &&
    isText(body.listen) && typeof body.applied === 'boolean' && typeof body.would_do === 'string'
}

export function validJob(job) {
  return isObject(job) && isText(job.id) && typeof job.status === 'string' &&
    ['queued', 'running', 'succeeded', 'failed', 'cancelled'].includes(job.status)
}

// A status that claims a finished outcome is not the same as an applied change:
// provisioning/deleting mean the durable operation never reached a terminal
// state and the host may have changed. Such rows are surfaced, not auto-retried.
export function needsReconciliation(site) {
  if (!site) return false
  return site.status === 'provisioning' || site.status === 'deleting' ||
    (site.status === 'error' && UNKNOWN_OUTCOME.has(site.last_error || ''))
}

export function siteStatus(site) {
  if (!site) return { label: 'Unknown', tone: 'dim', notice: '' }
  switch (site.status) {
    case 'active': return { label: 'Active', tone: 'ok', notice: '' }
    case 'error': return { label: 'Failed', tone: 'err', notice: needsReconciliation(site) ? 'Outcome unknown — reconcile manually before retrying.' : site.last_error ? `Last attempt failed: ${site.last_error}.` : 'Last attempt failed.' }
    case 'provisioning': return { label: 'Provisioning', tone: 'warn', notice: 'Provisioning did not finish. Check the host before retrying.' }
    case 'deleting': return { label: 'Removing', tone: 'warn', notice: 'Removal did not finish. Check the host before retrying.' }
    case 'deleted': return { label: 'Removed, content retained', tone: 'dim', notice: 'The vhost is gone; the document root was kept.' }
    default: return { label: 'Unknown', tone: 'dim', notice: '' }
  }
}

const errorText = {
  sudo_required: 'Recent password verification is required. Re-authenticate, then review the plan again.',
  agent_unavailable: 'The host agent is not reachable, so nothing was applied. Try again once the agent is running.',
  forbidden_by_policy: 'The agent policy does not allow this operation. Nothing was applied.',
  unsupported: 'The host agent does not support this operation. Nothing was applied.',
  invalid_domain: 'Enter a lowercase DNS domain.',
  domain_conflict: 'That domain is already in use.',
  confirmation_required: 'Type the exact domain to confirm removal.',
  confirmation_mismatch: 'The confirmation does not match this domain exactly.',
  reconciliation_required: 'Unfinished work for this site must be reconciled first.',
  site_deleted: 'This site is already removed; its content is retained.',
  delete_files_forbidden: 'Deleting site content is not supported; content is retained.',
  manual_reconciliation: 'Manual reconciliation is required: the outcome could not be recorded. Inspect the host before retrying, and do not retry.',
  invalid_response: 'The panel returned an unreadable response.',
  network: 'The panel API could not be reached. The request may have reached the server. Do not retry; reconcile first.',
  not_found: 'That site no longer exists. Reload the inventory.',
}

export function describeError(err) {
  if (!err) return ''
  const known = errorText[err.code]
  if (known) return known
  if (isText(err.message)) return err.message
  return 'The request failed.'
}

function jobFailure(job) {
  if (job?.error && UNKNOWN_OUTCOME.has(job.error)) {
    return { text: errorText.manual_reconciliation, reconciliation: true }
  }
  const code = job?.error || ''
  if (errorText[code] && !UNKNOWN_OUTCOME.has(code)) return { text: errorText[code], reconciliation: false }
  return { text: job?.error ? `The host job failed: ${job.error}. Nothing is retried automatically.` : 'The host job failed. Nothing is retried automatically.', reconciliation: false }
}

function nonterminalJob(job) {
  return job?.status === 'queued' || job?.status === 'running'
}

function createSuccess(job, site) {
  return job.status === 'succeeded' && site.status === 'active'
}

function removeSuccess(job, site, retained) {
  return job.status === 'succeeded' && site.status === 'deleted' && retained === true
}

export function createSitesWorkflow({ client, isAdmin = () => false } = {}) {
  const state = reactive({
    loading: true,
    loaded: false,
    inventoryError: '',
    sites: [],
    total: 0,
    capability: 'loading',
    agentReason: '',
    operations: [],
    query: '',
    domain: '',
    plan: null,
    planning: false,
    busy: '',
    error: '',
    notice: '',
    result: null,
    reconciliation: false,
    needsSudo: false,
    removal: null,
    confirmDomain: '',
  })

  const admin = () => Boolean(isAdmin())
  const supports = name => state.capability === 'supported' && state.operations.includes(name)

  function resetPlan() {
    state.plan = null
  }

  function failAmbiguous(message) {
    state.error = message || errorText.manual_reconciliation
    state.reconciliation = true
    resetPlan()
  }

  function clearOutcome() {
    state.result = null
    state.error = ''
    state.notice = ''
    state.reconciliation = false
  }

  async function readInventory() {
    const body = await client.list()
    const parsed = validInventory(body)
    if (!parsed) throw Object.assign(new Error('Inventory response is unreadable.'), { code: 'invalid_response' })
    state.sites = parsed.sites
    state.total = parsed.total
  }

  async function readCapability() {
    let body
    try {
      body = await client.capabilities()
    } catch (err) {
      state.capability = 'unavailable'
      state.agentReason = err?.code || 'agent_error'
      state.operations = []
      return
    }
    if (!isObject(body) || body.connected !== true || !Array.isArray(body.operations) || body.operations.some(op => typeof op !== 'string')) {
      state.capability = 'unavailable'
      state.agentReason = body?.connected === false ? 'agent_unavailable' : 'invalid_response'
      state.operations = []
      return
    }
    state.operations = [...body.operations]
    state.capability = body.operations.includes('site.plan') ? 'supported' : 'unsupported'
    state.agentReason = ''
  }

  async function load() {
    state.loading = true
    state.inventoryError = ''
    const [inventory, capability] = await Promise.allSettled([readInventory(), readCapability()])
    if (inventory.status === 'rejected') {
      // Previous rows stay on screen: a failed refresh must not look like an
      // empty inventory or erase what the operator was inspecting.
      state.inventoryError = `${inventory.reason?.code || 'request_failed'}: ${describeError(inventory.reason)}`
    }
    void capability
    state.loading = false
    state.loaded = true
  }

  function setDomain(value) {
    const next = normalizeDomain(value)
    if (next === state.domain) return
    state.domain = next
    resetPlan()
    state.error = ''
  }

  function canPlan() {
    return admin() && supports('site.plan') && !state.busy && !state.reconciliation && !domainProblem(state.domain)
  }

  async function makePlan() {
    if (state.busy || !canPlan()) return false
    const domain = state.domain
    state.planning = true
    state.error = ''
    resetPlan()
    try {
      const body = await client.plan(domain)
      if (state.domain !== domain) return false
      if (!validPlan(body, domain)) throw Object.assign(new Error('Plan response is unreadable.'), { code: 'invalid_response' })
      state.plan = body
      return true
    } catch (err) {
      if (state.domain === domain) {
        resetPlan()
        state.error = describeError(err)
        if (err?.code === 'agent_unavailable') state.capability = 'unavailable'
      }
      return false
    } finally {
      state.planning = false
    }
  }

  function canCreate() {
    return canPlan() && !state.planning && supports('site.apply') && state.plan !== null &&
      state.plan.domain === state.domain && !state.needsSudo && !state.inventoryError && !state.loading &&
      !state.sites.some(site => site.domain === state.domain) && !state.plan.applied && state.plan.would_do === 'create'
  }

  function adoptResponse(body, expectDomain) {
    if (!isObject(body) || !validSite(body.site) || !validJob(body.job) || body.mode !== 'synchronous') return null
    if (body.site.domain !== expectDomain) return null
    return body
  }

  async function create() {
    if (state.busy || !canCreate()) return false
    const domain = state.domain
    state.busy = 'create'
    clearOutcome()
    let body
    try {
      body = await client.create(domain)
    } catch (err) {
      state.needsSudo = err?.code === 'sudo_required'
      if (ambiguous(err)) {
        failAmbiguous('The request may have reached the server. Do not retry; reconcile the durable operation first.')
      } else {
        state.error = describeError(err)
        if (err?.code === 'agent_unavailable') {
          state.capability = 'unavailable'
          state.reconciliation = true
          state.error = 'The request may have reached the agent. Do not retry; reconcile the durable operation first.'
        }
      }
      state.busy = ''
      return false
    }
    const parsed = adoptResponse(body, domain)
    if (!parsed) {
      // A 200 we cannot read leaves the host outcome unknown.
      state.reconciliation = true
      state.error = errorText.manual_reconciliation
      state.busy = ''
      await load()
      return false
    }
    resetPlan()
    const success = createSuccess(parsed.job, parsed.site)
    state.result = { success, job: parsed.job, site: parsed.site, retainedContent: false }
    if (!success) {
      const failure = nonterminalJob(parsed.job)
        ? { text: 'The synchronous response was not terminal. The host outcome is unknown; do not retry.', reconciliation: true }
        : jobFailure(parsed.job)
      state.error = failure.text
      state.reconciliation = failure.reconciliation || needsReconciliation(parsed.site) || parsed.job.status === 'succeeded'
      if (parsed.job.status === 'succeeded') state.error = errorText.manual_reconciliation
    } else {
      state.notice = `Created ${parsed.site.domain}.`
      state.domain = ''
    }
    state.busy = ''
    await load()
    return state.result.success
  }

  function canRemove(site) {
    return admin() && supports('site.remove') && !state.busy && !state.reconciliation &&
      Boolean(site) && (site.status === 'active' || site.status === 'error') && !needsReconciliation(site)
  }

  function selectRemoval(site) {
    state.removal = site || null
    state.confirmDomain = ''
    state.error = ''
  }

  async function remove() {
    const site = state.removal
    if (state.busy || !canRemove(site)) return false
    // The selected row is a snapshot. A refresh may have revealed an unknown
    // outcome (or removed the site entirely); dispatch only against the row the
    // inventory currently reports, so reconciliation cannot be bypassed.
    const fresh = state.sites.find(row => row.id === site.id && row.domain === site.domain)
    if (!fresh) {
      state.error = errorText.not_found
      state.removal = null
      state.confirmDomain = ''
      await load()
      return false
    }
    if (!canRemove(fresh)) {
      state.reconciliation = needsReconciliation(fresh) || state.reconciliation
      state.error = needsReconciliation(fresh)
        ? errorText.reconciliation_required
        : 'This site changed while the removal form was open. Reload the inventory and try again.'
      await load()
      return false
    }
    if (state.confirmDomain === '' || state.confirmDomain !== fresh.domain) {
      state.error = state.confirmDomain === '' ? errorText.confirmation_required : errorText.confirmation_mismatch
      return false
    }
    state.busy = 'remove'
    clearOutcome()
    let body
    try {
      body = await client.remove(fresh.id, state.confirmDomain)
    } catch (err) {
      state.needsSudo = err?.code === 'sudo_required'
      if (ambiguous(err)) {
        failAmbiguous('The removal may have reached the server. Do not retry; reconcile the durable operation first.')
      } else {
        state.error = describeError(err)
      }
      state.busy = ''
      return false
    }
    const parsed = adoptResponse(body, site.domain)
    if (!parsed) {
      state.reconciliation = true
      state.error = errorText.manual_reconciliation
      state.busy = ''
      await load()
      return false
    }
    const succeeded = removeSuccess(parsed.job, parsed.site, body.retained_content)
    state.result = { success: succeeded, job: parsed.job, site: parsed.site, retainedContent: body.retained_content === true }
    if (!succeeded) {
      if (parsed.job.status === 'succeeded') {
        state.error = 'Removal reported success without confirming that content was retained. Reconcile before retrying.'
        state.reconciliation = true
      } else {
        const failure = nonterminalJob(parsed.job)
          ? { text: 'The synchronous response was not terminal. The host outcome is unknown; do not retry.', reconciliation: true }
          : jobFailure(parsed.job)
        state.error = failure.text
        state.reconciliation = failure.reconciliation || needsReconciliation(parsed.site)
      }
    } else {
      state.notice = `Removed the vhost for ${site.domain}. Content at the document root was retained.`
      state.removal = null
      state.confirmDomain = ''
    }
    state.busy = ''
    await load()
    return succeeded
  }

  async function reauthenticate(payload = {}) {
    if (state.busy) return false
    state.busy = 'reauth'
    state.error = ''
    try {
      const result = await client.reauth(payload)
      if (typeof result?.sudo_until !== 'string' || !Number.isFinite(Date.parse(result.sudo_until))) {
        throw Object.assign(new Error('The panel returned an unreadable verification response.'), { code: 'invalid_response' })
      }
      state.needsSudo = false
      state.notice = 'Verification complete. No website operation was retried.'
      resetPlan()
      return true
    } catch (err) {
      state.needsSudo = true
      state.error = describeError(err)
      return false
    } finally {
      state.busy = ''
    }
  }

  function dismiss() {
    clearOutcome()
    state.needsSudo = false
  }

  return { state, load, setDomain, makePlan, canPlan, canCreate, create, canRemove, selectRemoval, remove, reauthenticate, dismiss, supports, needsReconciliation }
}
