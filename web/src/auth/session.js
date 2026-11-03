import { reactive } from 'vue'
import { authClient, AuthError } from './client.js'

// Identity and challenge state live in memory only. Cookies belong to the API.
export function createSessionStore({ client = authClient } = {}) {
  const state = reactive({ status: 'unknown', user: null, sudoUntil: null, csrfToken: '', error: '' })
  let pending
  // Monotonic generation: expire() and apply() invalidate any refresh()
  // already in flight so stale /me results cannot restore an old identity
  // or clear a newly authenticated session.
  let generation = 0

  function expire() {
    generation++
    state.status = 'unauthenticated'
    state.user = null
    state.sudoUntil = null
    state.csrfToken = ''
  }

  function apply(data) {
    generation++
    state.csrfToken = data.csrfToken || ''
    state.user = data.mfaRequired ? null : data.user
    state.status = data.mfaRequired ? 'unauthenticated' : 'authenticated'
    state.sudoUntil = null
    state.error = ''
    return data
  }

  async function refresh() {
    const gen = generation
    try {
      const data = await client.me()
      if (gen !== generation) return state.status
      state.user = data.user
      state.sudoUntil = data.sudoUntil
      state.status = 'authenticated'
      state.error = ''
    } catch (err) {
      if (gen !== generation) return state.status
      expire()
      state.error = err.status === 401 ? '' : err.message
    }
    return state.status
  }

  return {
    state,
    expire,
    refresh,
    check: refresh,
    async ensure() {
      if (state.status !== 'unknown') return state.status
      if (!pending) pending = refresh().finally(() => { pending = null })
      return pending
    },
    async login(username, password) {
      expire()
      try {
        return apply(await client.login(username, password))
      } catch (err) {
        expire()
        throw err
      }
    },
    async mfaLogin(payload = {}) {
      if (Boolean(payload.code) === Boolean(payload.recoveryCode)) {
        throw new AuthError('invalid_request', 'Provide exactly one of code or recovery code.', 400)
      }
      return apply(await client.loginMfa(payload, state.csrfToken || client.csrfFromCookie()))
    },
    async logout() {
      state.error = ''
      try {
        await client.logout(client.csrfFromCookie() || state.csrfToken)
      } catch (err) {
        // Clear local identity, but never claim remote logout succeeded.
        if (err.status !== 401) state.error = 'Sign-out could not be confirmed. Your server session may still be active. Try signing out again when connected.'
      } finally {
        expire()
      }
    },
  }
}

export const session = createSessionStore()
