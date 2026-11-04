import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHostPoller, POLL_INTERVAL_MS } from '../src/system/poller.js'

function fakeClock() {
  const timers = []
  let nextId = 1
  return {
    timers,
    setTimer(fn, ms) { const t = { id: nextId++, fn, ms, cleared: false }; timers.push(t); return t.id },
    clearTimer(id) { const t = timers.find(x => x.id === id); if (t) t.cleared = true },
    pending() { return timers.filter(t => !t.cleared) },
    async fire() {
      const t = this.pending()[0]
      assert.ok(t, 'expected a pending timer')
      t.cleared = true
      t.fn()
      await new Promise(resolve => setImmediate(resolve))
      return t
    },
  }
}

function deferred() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

test('poll interval is five seconds', () => {
  assert.equal(POLL_INTERVAL_MS, 5000)
})

test('start loads immediately and schedules the next poll only after it settles', async () => {
  const clock = fakeClock()
  const d = deferred()
  const results = []
  let calls = 0
  const poller = createHostPoller({
    load: () => { calls++; return d.promise },
    setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    onResult: r => results.push(r),
  })
  poller.start()
  assert.equal(calls, 1)
  assert.equal(clock.pending().length, 0, 'no timer while a read is in flight')
  d.resolve({ connected: true })
  await poller.idle()
  assert.deepEqual(results, [{ connected: true }])
  assert.equal(clock.pending().length, 1)
  assert.equal(clock.pending()[0].ms, 5000)
  poller.stop()
})

test('overlapping refresh shares the in-flight read instead of firing another', async () => {
  const clock = fakeClock()
  const d = deferred()
  let calls = 0
  const poller = createHostPoller({ load: () => { calls++; return d.promise }, setTimer: clock.setTimer, clearTimer: clock.clearTimer })
  const first = poller.refresh()
  const second = poller.refresh()
  assert.equal(calls, 1)
  assert.equal(first, second)
  d.resolve({ connected: true })
  await first
  poller.stop()
})

test('each completed poll schedules exactly one next poll', async () => {
  const clock = fakeClock()
  let calls = 0
  const poller = createHostPoller({ load: async () => ({ connected: true, n: ++calls }), setTimer: clock.setTimer, clearTimer: clock.clearTimer })
  poller.start()
  await poller.idle()
  assert.equal(clock.pending().length, 1)
  await clock.fire()
  assert.equal(calls, 2)
  assert.equal(clock.pending().length, 1)
  await clock.fire()
  assert.equal(calls, 3)
  poller.stop()
})

test('stop cancels the timer and drops a late result without rescheduling', async () => {
  const clock = fakeClock()
  const d = deferred()
  let applied = 0
  const poller = createHostPoller({
    load: () => d.promise, setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    onResult: () => { applied++ },
  })
  poller.start()
  const pending = poller.idle()
  poller.stop()
  assert.equal(clock.pending().length, 0)
  d.resolve({ connected: true })
  await pending
  assert.equal(applied, 0, 'unmounted view must not receive late data')
  assert.equal(clock.pending().length, 0)
})

test('stop is idempotent and safe before start', () => {
  const clock = fakeClock()
  const poller = createHostPoller({ load: async () => ({}), setTimer: clock.setTimer, clearTimer: clock.clearTimer })
  poller.stop()
  poller.stop()
  assert.equal(clock.pending().length, 0)
})

test('unauthorized stops polling and never schedules again', async () => {
  const clock = fakeClock()
  let calls = 0
  const results = []
  const poller = createHostPoller({
    load: async () => { calls++; return { connected: false, reason: 'unauthorized', info: null, stats: null } },
    setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    onResult: r => results.push(r),
  })
  poller.start()
  await poller.idle()
  assert.equal(results[0].reason, 'unauthorized')
  assert.equal(clock.pending().length, 0)
  assert.equal(calls, 1)
  assert.equal(poller.running, false)
})

test('a failed read clears state and keeps polling for recovery', async () => {
  const clock = fakeClock()
  const seen = []
  let attempt = 0
  const poller = createHostPoller({
    load: async () => { if (++attempt === 1) throw new Error('offline'); return { connected: true } },
    setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    onResult: r => seen.push(r),
  })
  poller.start()
  await poller.idle()
  assert.deepEqual(seen, [{ connected: false, reason: 'network', info: null, stats: null }])
  assert.equal(clock.pending().length, 1)
  await clock.fire()
  assert.equal(seen.length, 2)
  assert.equal(seen[1].connected, true)
  poller.stop()
})

test('restart after stop resumes a single poll loop', async () => {
  const clock = fakeClock()
  let calls = 0
  const poller = createHostPoller({ load: async () => ({ connected: true, n: ++calls }), setTimer: clock.setTimer, clearTimer: clock.clearTimer })
  poller.start()
  await poller.idle()
  poller.stop()
  poller.start()
  await poller.idle()
  assert.equal(calls, 2)
  assert.equal(clock.pending().length, 1)
  poller.stop()
})

test('synchronous loader exceptions also clear state and recover', async () => {
  const clock = fakeClock()
  const seen = []
  let calls = 0
  const poller = createHostPoller({ load: () => { calls++; throw new Error('offline') }, onResult: r => seen.push(r), setTimer: clock.setTimer, clearTimer: clock.clearTimer })
  poller.start()
  await poller.idle()
  assert.equal(seen[0]?.reason, 'network')
  assert.equal(clock.pending().length, 1)
  await clock.fire()
  assert.equal(calls, 2)
  assert.equal(clock.pending().length, 1)
  poller.stop()
})

test('restart during an old request never overlaps or applies its late response', async () => {
  const clock = fakeClock()
  const d = deferred()
  let calls = 0
  const seen = []
  const poller = createHostPoller({
    load: () => ++calls === 1 ? d.promise : Promise.resolve({ connected: true, hostname: 'new' }),
    onResult: r => seen.push(r), setTimer: clock.setTimer, clearTimer: clock.clearTimer,
  })
  poller.start()
  const pending = poller.idle()
  poller.stop()
  poller.start()
  assert.equal(calls, 1)
  d.resolve({ connected: true, hostname: 'old' })
  await pending
  assert.deepEqual(seen, [])
  await clock.fire()
  assert.equal(seen[0].hostname, 'new')
  assert.equal(calls, 2)
  poller.stop()
})
