import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
const read = p => readFileSync(new URL(p, import.meta.url), 'utf8')

test('router uses real path history, not fragment routing', () => {
  const src = read('../src/router.js')
  assert.match(src, /history:\s*createWebHistory\(/)
  assert.doesNotMatch(src, /createWebHashHistory/)
})

test('server shell route allowlist matches frontend routes', () => {
  const src = read('../src/router.js')
  const routes = [...src.matchAll(/path: '([^']+)'/g)].map(m => m[1]).filter(p => p !== '/' && !p.startsWith('/:'))
  const server = read('../../internal/webui/webui.go')
  const block = server.match(/(?:ClientRoutes|clientRoutes) = \[\]string\{([\s\S]*?)\n\}/)[1]
  const served = [...block.matchAll(/"([^"]+)"/g)].map(m => m[1])
  assert.deepEqual(served.sort(), routes.sort())
})

test('view links never use fragment placeholders', () => {
  for (const name of readdirSync(new URL('../src/views/', import.meta.url))) {
    if (!name.endsWith('.vue')) continue
    assert.doesNotMatch(read('../src/views/' + name), /href=["']#/, name)
  }
  assert.doesNotMatch(read('../src/App.vue'), /href=["']#/)
})
