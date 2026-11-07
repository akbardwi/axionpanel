import test from 'node:test'
import assert from 'node:assert/strict'
import { createSitesWorkflow } from '../src/lib/sitesWorkflow.js'

function make(client) { return createSitesWorkflow({ client, isAdmin: () => true }) }

test('unreadable sudo response never claims verification succeeded', async () => {
  const w = make({ reauth: async () => ({}) })
  w.state.needsSudo = true
  assert.equal(await w.reauthenticate({ password: 'test-only' }), false)
  assert.equal(w.state.needsSudo, true)
  assert.match(w.state.error, /unreadable/i)
})
