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
test('overview reuses original live cards with an explicit read-only example boundary', () => {
  const src = read('src/views/OverviewView.vue')
  assert.match(src, /loadHost/)
  assert.doesNotMatch(src, /Host data \(live\)/)
  assert.match(src, /Example data.*read-only/i)
  assert.match(src, /reasonText/)
  assert.match(src, /grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-gutter/)
  assert.match(src, /isDesignPreview\(\)/)
  assert.match(src, /1 \/ 5 \/ 15 min/)
  assert.doesNotMatch(src, /5s sample/)
  assert.doesNotMatch(src, /<main v-pre/)
  assert.match(src, /v-pre/)
  assert.doesNotMatch(src, /cpuGrad|Past 1 Hour|AMD EPYC|DDR5 ECC|SGP-DC-02|203\.0\.113\.10|99\.98%/)
})

test('all overview example controls are visibly unavailable and disabled', () => {
  const src = read('src/views/OverviewView.vue')
  for (const button of src.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)) {
    if (button[0].includes('@click="refreshHost"') || button[0].includes('notice')) continue
    assert.match(button[0], /\bdisabled\b/)
    assert.match(button[0], /unavailable/i)
  }
})
test('production shell distinguishes live host reads from example screens', () => {
  const app = read('src/App.vue')
  const banner = app.match(/<template v-else>([^<]*)<\/template>/)?.[1]
  assert.ok(banner)
  assert.match(banner, /Live metrics/i)
  assert.match(banner, /Sample screens/)
  assert.doesNotMatch(banner, /All values are example data|No server operations are executed/)
})

test('reference screens are adopted without remote scripts or fake live timers', () => {
  for (const page of ['Overview','Containers','Security','Terminal']) {
    const source = read(`src/views/${page}View.vue`)
    assert.doesNotMatch(source, /<script[^>]+src=|onclick=|NexusVPS|Raft Consensus/)
    if (page !== 'Overview') assert.doesNotMatch(source, /setInterval\(/)
    else {
      // Overview's timer only ages real observations; it never makes up metrics.
      assert.match(source, /setInterval\(\(\) => \{ now\.value = Date\.now\(\) \}, 1000\)/)
      assert.match(source, /clearInterval\(clock\)/)
    }
    assert.match(source, /<template>/)
  }
})
