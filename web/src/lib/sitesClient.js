import { AuthError, csrfFromCookie } from '../auth/client.js'

// Same origin and the existing session/CSRF protocol. Mutations can take 90s;
// do not cancel or retry them automatically: a lost response is ambiguous.
export function createSitesClient({ fetchImpl = (...args) => globalThis.fetch(...args), getCookie = () => typeof document === 'undefined' ? '' : document.cookie, getCSRF = () => '', onUnauthorized = async () => {} } = {}) {
  async function request(url, method = 'GET', body) {
    const headers = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (method !== 'GET') {
      const token = csrfFromCookie(getCookie()) || getCSRF()
      if (token) headers['X-CSRF-Token'] = token
    }
    let response
    try {
      response = await fetchImpl(url, { method, credentials: 'same-origin', cache: 'no-store', headers, body: body === undefined ? undefined : JSON.stringify(body) })
    } catch {
      throw new AuthError('network', 'Cannot reach the panel backend.', 0)
    }
    let data
    try { data = await response.json() } catch { data = null }
    if (!response.ok) {
      if (response.status === 401) await onUnauthorized()
      throw new AuthError(data?.error?.code || 'request_failed', data?.error?.message || 'Request failed.', response.status)
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new AuthError('invalid_response', 'The panel returned an unreadable response.', response.status)
    return data
  }
  return {
    list: () => request('/api/v1/sites'),
    capabilities: () => request('/api/v1/system/info'),
    plan: domain => request('/api/v1/sites/plan?domain=' + encodeURIComponent(domain)),
    create: domain => request('/api/v1/sites', 'POST', { domain }),
    remove: (id, domain) => request('/api/v1/sites/' + encodeURIComponent(id), 'DELETE', { confirm_domain: domain }),
    reauth: payload => request('/api/v1/auth/reauth', 'POST', payload),
  }
}
