import test from 'node:test'
import assert from 'node:assert/strict'
import { createSitesWorkflow } from '../src/lib/sitesWorkflow.js'

const site = (patch = {}) => ({ id: 1, domain: 'app.example.com', kind: 'static', root: '/isolated/app', listen: '127.0.0.1:18080', status: 'active', retained_content: false, ...patch })
const plan = domain => ({ domain, vhost: '/isolated/config', root: '/isolated/app', listen: '127.0.0.1:18080', applied: false, would_do: 'create' })
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r }); return { promise, resolve } }
function setup(overrides = {}, options = {}) {
  const calls = []
  const client = {
    list: async () => ({ data: [], meta: { total: 0 } }),
    capabilities: async () => ({ connected: true, operations: ['site.plan', 'site.apply', 'site.remove'] }),
    plan: async domain => { calls.push(['plan', domain]); return plan(domain) },
    create: async domain => { calls.push(['create', domain]); return { site: site(), job: { id: 'job-1', status: 'succeeded' }, mode: 'synchronous' } },
    remove: async (id, domain) => { calls.push(['remove', id, domain]); return { site: site({ status: 'deleted', retained_content: true }), job: { id: 'job-2', status: 'succeeded' }, retained_content: true, mode: 'synchronous' } },
    reauth: async payload => { calls.push(['reauth', payload]); return { sudo_until: '2026-01-01T10:00:00Z' } },
    ...overrides,
  }
  return { workflow: createSitesWorkflow({ client, isAdmin: () => true, ...options }), calls }
}

test('inventory starts empty/loading then stays available when agent operations are unsupported', async () => {
  const wait = deferred()
  const { workflow: w } = setup({ list: () => wait.promise, capabilities: async () => ({ connected: true, operations: ['system.info'] }) })
  assert.deepEqual(w.state.sites, [])
  const loading = w.load()
  assert.equal(w.state.loading, true)
  wait.resolve({ data: [site()], meta: { total: 1 } })
  await loading
  assert.equal(w.state.sites.length, 1)
  assert.equal(w.state.capability, 'unsupported')
  assert.equal(w.canPlan(), false)
  assert.equal(w.canCreate(), false)
})

test('failed and malformed inventory loads are not presented as an empty success or erase previous rows', async () => {
  let body = { data: [site()], meta: {} }
  const { workflow: w } = setup({ list: async () => body })
  await w.load()
  body = { data: [{ domain: 'invalid' }] }
  await w.load()
  assert.equal(w.state.sites.length, 1)
  assert.match(w.state.inventoryError, /invalid_response/)
  assert.equal(w.state.loading, false)
})

test('create requires an explicit current plan and a separate operator action; editing invalidates plan', async () => {
  const { workflow: w, calls } = setup()
  await w.load()
  w.setDomain('APP.example.com')
  assert.equal(w.state.domain, 'app.example.com')
  assert.equal(await w.create(), false)
  await w.makePlan()
  assert.equal(w.canCreate(), true)
  assert.equal(calls.filter(c => c[0] === 'create').length, 0)
  w.setDomain('other.example.com')
  assert.equal(w.state.plan, null)
  assert.equal(w.canCreate(), false)
  await w.makePlan()
  // Server canonical domain must match the reviewed request.
  const result = await w.create()
  assert.equal(result, false)
  assert.equal(w.state.reconciliation, true)
})

test('late plans for an edited domain cannot enable creation', async () => {
  const wait = deferred()
  const { workflow: w } = setup({ plan: () => wait.promise })
  await w.load()
  w.setDomain('app.example.com')
  const pending = w.makePlan()
  w.setDomain('other.example.com')
  wait.resolve(plan('app.example.com'))
  await pending
  assert.equal(w.state.plan, null)
  assert.equal(w.canCreate(), false)
})

test('successful create renders the returned job, refreshes inventory, and consumes the plan', async () => {
  let created = false
  const { workflow: w } = setup({ create: async () => { created = true; return { site: site(), job: { id: 'j', status: 'succeeded' }, mode: 'synchronous' } }, list: async () => ({ data: created ? [site()] : [] }) })
  await w.load()
  w.setDomain('app.example.com')
  await w.makePlan()
  assert.equal(await w.create(), true)
  assert.equal(w.state.result.success, true)
  assert.equal(w.state.result.job.id, 'j')
  assert.equal(w.state.sites.length, 1)
  assert.equal(w.canCreate(), false)
})

test('HTTP 200 failed job is a failure and manual reconciliation is prominent', async () => {
  const { workflow: w } = setup({ create: async () => ({ site: site({ status: 'error', last_error: 'interrupted_manual_reconciliation' }), job: { id: 'j', status: 'failed', error: 'interrupted_manual_reconciliation' }, mode: 'synchronous' }) })
  await w.load(); w.setDomain('app.example.com'); await w.makePlan()
  assert.equal(await w.create(), false)
  assert.equal(w.state.result.success, false)
  assert.equal(w.state.result.job.status, 'failed')
  assert.equal(w.state.reconciliation, true)
  assert.match(w.state.error, /manual reconciliation/i)
})

test('removal requires byte-exact domain confirmation and reports content retained only on success', async () => {
  const { workflow: w, calls } = setup({ list: async () => ({ data: [site()] }) })
  await w.load()
  w.selectRemoval(w.state.sites[0])
  for (const value of ['', 'APP.example.com', 'app.example.com ']) {
    w.state.confirmDomain = value
    assert.equal(await w.remove(), false)
  }
  assert.equal(calls.length, 0)
  w.state.confirmDomain = 'app.example.com'
  assert.equal(await w.remove(), true)
  assert.deepEqual(calls[0], ['remove', 1, 'app.example.com'])
  assert.equal(w.state.result.retainedContent, true)
})

test('sudo_required opens reauthentication without replaying the mutation', async () => {
  const { workflow: w, calls } = setup({ create: async () => { calls.push(['denied']); throw Object.assign(new Error('Recent password verification required.'), { code: 'sudo_required', status: 403 }) } })
  await w.load(); w.setDomain('app.example.com'); await w.makePlan()
  await w.create()
  assert.equal(w.state.needsSudo, true)
  assert.equal(w.state.reconciliation, false)
  assert.equal(await w.reauthenticate({ password: 'test-only' }), true)
  assert.equal(w.state.needsSudo, false)
  assert.equal(calls.filter(c => c[0] === 'denied').length, 1)
  assert.equal(w.state.plan, null)
})

test('lost mutation response blocks automatic retry and requires manual reconciliation', async () => {
  const { workflow: w } = setup({ create: async () => { throw Object.assign(new Error('offline'), { code: 'network', status: 0 }) } })
  await w.load(); w.setDomain('app.example.com'); await w.makePlan()
  await w.create()
  assert.equal(w.state.reconciliation, true)
  assert.match(w.state.error, /Do not retry/i)
  assert.equal(w.canPlan(), false)
})

test('in-flight mutation prevents duplicate dispatch until synchronous job completes', async () => {
  const wait = deferred()
  const { workflow: w } = setup({ create: () => wait.promise })
  await w.load(); w.setDomain('app.example.com'); await w.makePlan()
  const pending = w.create()
  assert.equal(w.state.busy, 'create')
  assert.equal(await w.create(), false)
  wait.resolve({ site: site(), job: { id: 'j', status: 'succeeded' }, mode: 'synchronous' })
  await pending
  assert.equal(w.state.busy, '')
})

test('non-admin and incomplete capability catalogs fail closed', async () => {
  const { workflow: w } = setup({}, { isAdmin: () => false })
  await w.load(); w.setDomain('app.example.com'); await w.makePlan()
  assert.equal(w.canCreate(), false)
  assert.equal(w.canRemove(site()), false)
  const { workflow: missing } = setup({ capabilities: async () => ({ connected: true }) })
  await missing.load()
  assert.equal(missing.state.capability, 'unavailable')
  assert.equal(missing.canPlan(), false)
})
