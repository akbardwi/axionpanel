// Single-flight poller for the Overview host read. One read is in flight at a
// time — including across stop()/start() — and the next poll is scheduled
// only after the previous read settles, so slow agents never stack requests.
// stop() (unmount) drops late results.
import { POLL_INTERVAL_MS } from './overview.js'

export { POLL_INTERVAL_MS }

const networkFailure = () => ({ connected: false, reason: 'network', info: null, stats: null })

export function createHostPoller({
  load,
  onResult = () => {},
  interval = POLL_INTERVAL_MS,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = id => clearTimeout(id),
}) {
  let running = false
  let generation = 0
  let timer = null
  let inflight = null

  function cancelTimer() {
    if (timer !== null) clearTimer(timer)
    timer = null
  }

  function schedule(ms) {
    cancelTimer()
    if (running) timer = setTimer(refresh, ms)
  }

  function afterSettle(gen, result) {
    inflight = null
    if (gen !== generation) {
      // stop()/start() while this read settled: let the new mount poll now
      // that no request is outstanding, and discard the stale result.
      schedule(0)
      return
    }
    onResult(result)
    if (result?.reason === 'unauthorized') {
      // The session is being revalidated; polling resumes only when the view
      // is mounted again after sign-in.
      running = false
      cancelTimer()
    } else {
      schedule(interval)
    }
  }

  function refresh() {
    if (inflight) return inflight
    cancelTimer()
    const gen = generation
    let p
    try { p = Promise.resolve(load()) } catch { p = Promise.resolve(networkFailure()) }
    inflight = p.then(
      result => { afterSettle(gen, result); return result },
      () => { const failure = networkFailure(); afterSettle(gen, failure); return failure },
    )
    return inflight
  }

  return {
    refresh,
    start() {
      if (running) return
      running = true
      if (!inflight) refresh()
    },
    stop() {
      running = false
      generation++
      cancelTimer()
    },
    idle() { return inflight ? inflight.then(() => {}, () => {}) : Promise.resolve() },
    get running() { return running },
  }
}
