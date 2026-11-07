import test from 'node:test'
import assert from 'node:assert/strict'
import { createSitesWorkflow, needsReconciliation, siteStatus, domainProblem } from '../src/lib/sitesWorkflow.js'

const site = { id: 1, domain: 'app.example.com', kind: 'static', root: '/isolated/app', listen: '127.0.0.1:18080', status: 'active', retained_content: false }
const plan = { domain: site.domain, vhost: '/isolated/config', root: site.root, listen: site.listen, applied: false, would_do: 'create' }
function setup(overrides = {}) {
  let mutations = 0
  const client = {
    list: async () => ({ data: [] }),
    capabilities: async () => ({ connected: true, operations: ['site.plan', 'site.apply', 'site.remove'] }),
    plan: async () => plan,
    create: async () => { mutations++; return { site, job: { id: 'j', status: 'succeeded' }, mode: 'synchronous' } },
    remove: async () => { mutations++; return { site: { ...site, status: 'deleted', retained_content: true }, job: { id: 'j', status: 'succeeded' }, mode: 'synchronous', retained_content: true } },
    ...overrides,
  }
  return { w: createSitesWorkflow({ client, isAdmin: () => true }), count: () => mutations }
}
async function ready(overrides) {
  const setupResult = setup(overrides)
  await setupResult.w.load()
  setupResult.w.setDomain(site.domain)
  await setupResult.w.makePlan()
  return setupResult
}

test('a dispatch consumes the reviewed plan even on a definite job failure', async () => {
  const { w } = await ready({ create: async () => ({ site: { ...site, status: 'error' }, job: { id: 'j', status: 'failed', error: 'config_test_failed' }, mode: 'synchronous' }) })
  assert.equal(await w.create(), false)
  assert.equal(w.state.plan, null)
  assert.equal(w.canCreate(), false)
})

test('nonterminal jobs in a synchronous response require reconciliation', async () => {
  for (const status of ['queued', 'running']) {
    const { w } = await ready({ create: async () => ({ site: { ...site, status: 'error' }, job: { id: 'j', status }, mode: 'synchronous' }) })
    await w.create()
    assert.equal(w.state.reconciliation, true, status)
    assert.equal(w.canPlan(), false)
  }
})

test('server failure after dispatch is ambiguous rather than safe to retry', async () => {
  for (const code of ['internal', 'invalid_response', 'agent_error']) {
    const { w } = await ready({ create: async () => { throw Object.assign(new Error('failed'), { code, status: 500 }) } })
    await w.create()
    assert.equal(w.state.reconciliation, true, code)
    assert.match(w.state.error, /Do not retry/i)
  }
})

test('unknown host job failures and uncertain site rows require reconciliation before removal', async () => {
  const { w } = await ready({ create: async () => ({ site: { ...site, status: 'error', last_error: 'agent_error' }, job: { id: 'j', status: 'failed', error: 'agent_error' }, mode: 'synchronous' }) })
  await w.create()
  assert.equal(w.state.reconciliation, true)
  for (const last_error of ['agent_error', 'manual_reconciliation', 'interrupted_manual_reconciliation']) {
    const uncertain = { ...site, status: 'error', last_error }
    assert.equal(needsReconciliation(uncertain), true, last_error)
    assert.match(siteStatus(uncertain).notice, /reconcile/i)
    const { w: other } = setup()
    await other.load()
    assert.equal(other.canRemove(uncertain), false, last_error)
  }
})

test('replanning invalidates the previous plan and prevents creation until the read finishes', async () => {
  let resolve
  let read = 0
  const { w } = await ready({ plan: async () => { if (++read === 1) return plan; return new Promise(r => { resolve = r }) } })
  const pending = w.makePlan()
  assert.equal(w.state.plan, null)
  assert.equal(w.canCreate(), false)
  resolve(plan)
  await pending
  assert.equal(w.canCreate(), true)
})

test('only consistent successful terminal outcomes can be called success', async () => {
  const { w } = await ready({ create: async () => ({ site: { ...site, status: 'error' }, job: { id: 'j', status: 'succeeded' }, mode: 'synchronous' }) })
  assert.equal(await w.create(), false)
  assert.equal(w.state.reconciliation, true)
  const { w: removal } = setup({ list: async () => ({ data: [site] }), remove: async () => ({ site, job: { id: 'j', status: 'succeeded' }, mode: 'synchronous', retained_content: true }) })
  await removal.load(); removal.selectRemoval(removal.state.sites[0]); removal.state.confirmDomain = site.domain
  assert.equal(await removal.remove(), false)
  assert.equal(removal.state.reconciliation, true)
})

test('a removal selected from a stale inventory is refused after the row changes', async () => {
  // Selection captures the row; a later refresh can reveal an unknown outcome
  // or a vanished site. Dispatching from the stale copy would skip the
  // reconciliation gate that the fresh row requires.
  let dispatched = 0
  let rows = [site]
  const client = {
    list: async () => ({ data: rows }),
    capabilities: async () => ({ connected: true, operations: ['site.plan', 'site.remove'] }),
    plan: async () => plan,
    remove: async () => { dispatched++; return { site: { ...site, status: 'deleted' }, job: { id: 'j', status: 'succeeded' }, mode: 'synchronous', retained_content: true } },
  }
  const w = createSitesWorkflow({ client, isAdmin: () => true })
  await w.load()
  w.selectRemoval(w.state.sites[0])
  w.state.confirmDomain = site.domain
  rows = [{ ...site, status: 'error', last_error: 'agent_error' }]
  await w.load()
  assert.equal(await w.remove(), false)
  assert.equal(dispatched, 0)
  assert.equal(w.state.reconciliation, true)

  rows = []
  await w.load()
  w.selectRemoval(site)
  w.state.confirmDomain = site.domain
  assert.equal(await w.remove(), false)
  assert.equal(dispatched, 0)
})

test('domain validation rejects paths, wildcards, URLs and local-only names before requesting a plan', () => {
  for (const invalid of ['', 'http://app.example.com', '*.example.com', '../example.com', 'localhost', 'app..example.com', 'a'.repeat(64) + '.example.com']) assert.ok(domainProblem(invalid), invalid)
  assert.equal(domainProblem('app.example.com'), '')
})
