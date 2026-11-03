// Reusable same-origin auth client for the AxionPanel API.
// Never touches browser storage; session/MFA cookies stay HttpOnly
// and the CSRF token is recovered from the readable axp_csrf cookie.

export class AuthError extends Error {
  constructor(code, message, status) {
    super(message)
    this.name = 'AuthError'
    this.code = code
    this.status = status
  }
}

export function parseCookies(header) {
  const out = {}
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=')
    if (i <= 0) continue
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim()
  }
  return out
}

export function csrfFromCookie(header) {
  return parseCookies(header)['axp_csrf'] || ''
}

export function createAuthClient({ fetchImpl, getCookie } = {}) {
  const doFetch = fetchImpl || ((...args) => globalThis.fetch(...args))
  const readCookie = getCookie || (() => (typeof document !== 'undefined' ? document.cookie : ''))
  const tokenFromCookie = () => csrfFromCookie(readCookie())

  async function request(path, { method = 'GET', body, csrf } = {}) {
    const headers = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const token = csrf || tokenFromCookie()
    if (token) headers['X-CSRF-Token'] = token
    let res
    try {
      res = await doFetch('/api/v1/auth' + path, {
        method,
        credentials: 'same-origin',
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      })
    } catch {
      throw new AuthError('network', 'Cannot reach the panel backend.', 0)
    }
    let data = {}
    try {
      data = await res.json()
    } catch {
      data = {}
    }
    if (!res.ok) {
      const e = data && data.error ? data.error : {}
      throw new AuthError(e.code || 'request_failed', e.message || 'Request failed.', res.status)
    }
    return data
  }

  function requireIdentity(data) {
    if (!data || typeof data.user?.username !== 'string' || !data.user.username || typeof data.user?.role !== 'string' || !data.user.role) {
      throw new AuthError('invalid_response', 'Invalid response from the panel backend. Sign in again.', 0)
    }
  }

  function loginResult(data, allowChallenge) {
    const token = data?.mfa_required ? data.csrf_token : (data?.csrf_token || tokenFromCookie())
    if (!data || typeof data.mfa_required !== 'boolean' || typeof token !== 'string' || !token) {
      throw new AuthError('invalid_response', 'Invalid response from the panel backend. Sign in again.', 0)
    }
    if (!allowChallenge || !data.mfa_required) requireIdentity(data)
    if (!allowChallenge && data.mfa_required) {
      throw new AuthError('invalid_response', 'Invalid response from the panel backend. Sign in again.', 0)
    }
    return { user: data.mfa_required ? null : data.user, csrfToken: token, mfaRequired: data.mfa_required }
  }

  return {
    csrfFromCookie: tokenFromCookie,

    async login(username, password) {
      const data = await request('/login', { method: 'POST', body: { username, password } })
      return loginResult(data, true)
    },

    async loginMfa({ code, recoveryCode } = {}, csrf) {
      const hasCode = typeof code === 'string' && code !== ''
      const hasRecovery = typeof recoveryCode === 'string' && recoveryCode !== ''
      if (hasCode === hasRecovery) {
        throw new AuthError('invalid_request', 'Provide exactly one of code or recovery code.', 400)
      }
      const body = hasCode ? { code } : { recovery_code: recoveryCode }
      const data = await request('/login/mfa', { method: 'POST', body, csrf })
      return loginResult(data, false)
    },

    async me() {
      const data = await request('/me')
      requireIdentity(data)
      return { user: data.user, sudoUntil: data.sudo_until ?? null }
    },

    async logout(csrf) {
      // Current cookie wins; the fallback only covers a missing readable cookie.
      await request('/logout', { method: 'POST', csrf: tokenFromCookie() || csrf })
    },
  }
}

export const authClient = createAuthClient()
