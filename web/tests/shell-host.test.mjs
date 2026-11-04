import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
const read = p => readFileSync(new URL('../' + p, import.meta.url), 'utf8')

test('shell sidebar shows live host values instead of sample node specs', () => {
  const app = read('src/App.vue')
  assert.match(app, /from '\.\/system\/host\.js'/, 'shell must reuse host formatting')
  assert.match(app, /'axp:host'/, 'shell must subscribe to overview host results')
  assert.match(app, /hostName|hostRam|hostUptime/, 'shell must render live host fields')
  assert.doesNotMatch(app, /node-01/, 'sample node name must not be rendered')
  assert.doesNotMatch(app, /vCPU: <span[^>]*>4</, 'sample vCPU count must not be rendered')
  assert.doesNotMatch(app, /Memory: <span[^>]*>8 GB</, 'sample memory size must not be rendered')
  assert.doesNotMatch(app, /example host data/, 'sidebar must not claim example host data')
})

test('overview publishes each host result so the shell stays in sync without polling twice', () => {
  const view = read('src/views/OverviewView.vue')
  assert.match(view, /new CustomEvent\('axp:host'/, 'overview must broadcast host results')
})

test('shell banner names the live metrics without claiming other screens are live', () => {
  const app = read('src/App.vue')
  const banner = app.match(/<template v-else>([^<]*)<\/template>/)?.[1]
  assert.ok(banner, 'production banner must exist')
  assert.match(banner, /Live metrics/i)
  assert.match(banner, /read-only/i)
  assert.match(banner, /Sample screens/i)
  assert.doesNotMatch(banner, /Host data \(live\)/)
})
