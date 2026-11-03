import { test } from 'node:test'
import assert from 'node:assert/strict'
import config from '../vite.config.js'

// The panel's CSP is font-src 'self'. Vite inlines small assets as data: URLs
// by default, which that policy blocks. Fonts must always be emitted as files.
test('build never inlines fonts as data: URLs (CSP font-src self)', () => {
  const limit = config.build?.assetsInlineLimit
  assert.equal(typeof limit, 'function', 'assetsInlineLimit must decide per file')
  for (const f of ['a.woff2', 'b.woff', 'c.ttf', 'd.otf']) {
    assert.equal(limit(f, Buffer.alloc(10)), false, `${f} must not be inlined`)
  }
})
