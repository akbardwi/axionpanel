import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
const read = p => readFileSync(new URL('../' + p, import.meta.url), 'utf8')
test('design shell identifies simulated operations and supplies routes', () => {
  assert.ok(existsSync(new URL('../src/App.vue', import.meta.url)), 'Vue design shell must exist')
  const app = read('src/App.vue')
  assert.match(app, /Design preview/)
  assert.match(app, /No server operations/)
  for (const route of ['websites','databases','ssl','files','cron','settings','containers','security','terminal','nodes','overview','login']) {
    assert.ok(read('src/router.js').includes('/' + route), `missing /${route}`)
  }
})
test('overview shows real host data separately from the design sample', () => {
  const src = read('src/views/OverviewView.vue')
  assert.match(src, /loadHost/)
  assert.match(src, /Host data \(live\)/)
  assert.match(src, /static design sample/i)
  assert.match(src, /reasonText/)
  // The design preview build must never call the API.
  assert.match(src, /isDesignPreview\(\)/)
})
test('production shell distinguishes live host reads from example screens', () => {
  const app = read('src/App.vue')
  const banner = app.match(/<template v-else>([^<]*)<\/template>/)?.[1]
  assert.ok(banner)
  assert.match(banner, /Host data.*live/i)
  assert.match(banner, /Sample screens/)
  assert.doesNotMatch(banner, /All values are example data|No server operations are executed/)
})

test('reference screens are adopted without remote scripts or fake live timers', () => {
  for (const page of ['Overview','Containers','Security','Terminal']) {
    const source = read(`src/views/${page}View.vue`)
    assert.doesNotMatch(source, /<script[^>]+src=|setInterval\(|onclick=|NexusVPS|Raft Consensus/)
    assert.match(source, /<template>/)
  }
})
