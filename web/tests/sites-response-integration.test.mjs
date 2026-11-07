import test from 'node:test'
import assert from 'node:assert/strict'
import { createSitesClient } from '../src/lib/sitesClient.js'
import { createSitesWorkflow } from '../src/lib/sitesWorkflow.js'

const site = { id: 1, domain: 'app.example.com', kind: 'static', root: '/isolated/app', status: 'active', retained_content: false }
const plan = { domain: site.domain, vhost: '/isolated/config', root: site.root, listen: '127.0.0.1:18080', applied: false, would_do: 'create' }

for (const method of ['create', 'remove']) {
  for (const [label, payload] of [['invalid JSON', '{'], ['null', 'null'], ['array', '[]']]) {
    test(`${method}: unreadable HTTP 200 (${label}) blocks redispatch through real client`, async () => {
      let dispatches = 0
      const client = createSitesClient({ fetchImpl: async (url, options) => {
        if (options.method !== 'GET') {
          dispatches++
          return new Response(payload, { status: 200 })
        }
        const body = url.includes('/system/info')
          ? { connected: true, operations: ['site.plan', 'site.apply', 'site.remove'] }
          : url.includes('/plan?') ? plan : { data: method === 'remove' ? [site] : [] }
        return new Response(JSON.stringify(body), { status: 200 })
      } })
      const w = createSitesWorkflow({ client, isAdmin: () => true })
      await w.load()
      if (method === 'create') {
        w.setDomain(site.domain)
        await w.makePlan()
        assert.equal(w.canCreate(), true)
      } else {
        w.selectRemoval(w.state.sites[0])
        w.state.confirmDomain = site.domain
      }
      assert.equal(await w[method](), false)
      assert.equal(w.state.reconciliation, true)
      assert.equal(w.canPlan(), false)
      assert.equal(w.state.plan, null)
      assert.match(w.state.error, /Do not retry/i)
      assert.equal(await w[method](), false)
      assert.equal(dispatches, 1)
    })
  }
}
