import { ref, reactive } from 'vue'
import { AuthError } from './client.js'

// Login state machine for the real sign-in UI: password step, optional MFA
// step, done. Secrets are cleared the moment they are no longer needed.
export function createLoginFlow(session) {
  const stage = ref('password') // 'password' | 'mfa' | 'done'
  const busy = ref(false)
  const error = ref('')
  const factor = ref('')
  const useRecovery = ref(false)
  const form = reactive({ username: '', password: '' })

  function fail(message) {
    error.value = message
    return false
  }

  function handle(err) {
    if (err instanceof AuthError && err.code === 'mfa_challenge') {
      stage.value = 'password'
    }
    return fail(err.message || 'Sign in failed. Try again.')
  }

  return {
    stage,
    busy,
    error,
    factor,
    useRecovery,
    form,

    async submitPassword() {
      if (busy.value) return false
      error.value = ''
      const username = form.username.trim()
      const password = form.password
      form.password = ''
      if (!username || !password) return fail('Enter a username and password.')
      busy.value = true
      try {
        const result = await session.login(username, password)
        if (result.mfaRequired) {
          stage.value = 'mfa'
          return false
        }
        stage.value = 'done'
        return true
      } catch (err) {
        return handle(err)
      } finally {
        busy.value = false
      }
    },

    async submitMfa() {
      if (busy.value) return false
      error.value = ''
      const value = factor.value.trim()
      factor.value = ''
      if (useRecovery.value) {
        if (!value) return fail('Enter a recovery code.')
      } else if (!/^\d{6}$/.test(value)) {
        return fail('Enter the 6-digit code from your authenticator app.')
      }
      busy.value = true
      try {
        await session.mfaLogin(useRecovery.value ? { recoveryCode: value } : { code: value })
        stage.value = 'done'
        return true
      } catch (err) {
        return handle(err)
      } finally {
        busy.value = false
      }
    },

    toggleRecovery() {
      useRecovery.value = !useRecovery.value
      factor.value = ''
      error.value = ''
    },

    reset() {
      stage.value = 'password'
      error.value = ''
      factor.value = ''
      useRecovery.value = false
      form.password = ''
    },
  }
}
