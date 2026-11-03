import { test, expect } from '@playwright/test'
// Test-only API interception. Actual app always calls the same-origin backend.
const validInfo = { connected: true, hostname: 'node-01', os: 'Ubuntu 26.04', arch: 'amd64', kernel: '7.0.0', version: '0.1.0-dev', protocol: 1, detected_tools: {}, capabilities: {}, capability_revision: 'rev1', observed_at: '2026-11-03T10:00:00Z', operations: ['system.stats'] }
const validStats = { load1: 0.5, load5: 0.4, load15: 0.3, mem_total_bytes: 1024, mem_available_bytes: 512, uptime_seconds: 90, observed_at: '2026-11-03T10:00:00Z' }
const hostCard = page => page.locator('section', { has: page.getByRole('heading', { name: 'Host data (live)' }) }).first()
const user = { id: 7, username: 'ada', role: 'operator' }
const error = (code = 'unauthorized', message = 'Sign in required.') => ({ error: { code, message } })
async function api(page, handler) {
  await page.route('**/api/v1/system/**', route => route.fulfill({ json: route.request().url().endsWith('/info') ? validInfo : validStats }))
  await page.route('**/api/v1/auth/**', async route => {
    const path = new URL(route.request().url()).pathname.split('/auth/')[1]
    const result = await handler(path, route.request())
    await route.fulfill({ status: result.status || 200, json: result.body })
  })
}
async function password(page) {
  await page.getByLabel('Username', { exact: true }).fill('ada')
  await page.getByLabel('Password', { exact: true }).fill('not-a-real-password')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

test('protected views redirect login; password-only login shows real identity; logout uses live cookie', async ({ page, context }) => {
  let signedIn = false
  let logoutHeader
  await api(page, async (path, request) => {
    if (path === 'me') return signedIn ? { body: { user, sudo_until: null } } : { status: 401, body: error() }
    if (path === 'login') {
      expect(request.postDataJSON()).toEqual({ username: 'ada', password: 'not-a-real-password' })
      signedIn = true
      return { body: { user, csrf_token: 'memory-token', mfa_required: false } }
    }
    if (path === 'logout') {
      logoutHeader = request.headers()['x-csrf-token']
      signedIn = false
      return { body: { ok: true } }
    }
    throw new Error(`Unexpected API path ${path}`)
  })
  await page.goto('/#/websites')
  await expect(page).toHaveURL(/#\/login$/)
  await expect(page.locator('aside')).toHaveCount(0)
  await password(page)
  await expect(page).toHaveURL(/#\/overview$/)
  await expect(page.locator('header')).toContainText('ada')
  await expect(page.locator('header')).toContainText('operator')
  await expect(page.getByText('SAMPLE SCREENS', { exact: true })).toBeVisible()
  await page.reload()
  await expect(page.locator('header')).toContainText('ada')
  await context.addCookies([{ name: 'axp_csrf', value: 'live-cookie', url: 'http://127.0.0.1:15175', sameSite: 'Strict' }])
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(page).toHaveURL(/#\/login$/)
  expect(logoutHeader).toBe('live-cookie')
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0])
})

for (const recovery of [false, true]) {
  test(`conditional MFA ${recovery ? 'recovery' : 'authenticator'} uses challenge CSRF and no secrets persist`, async ({ page }) => {
    const factors = []
    let signedIn = false
    await api(page, async (path, request) => {
      if (path === 'me') return signedIn ? { body: { user, sudo_until: null } } : { status: 401, body: error() }
      if (path === 'login') return { body: { mfa_required: true, csrf_token: 'challenge-token' } }
      if (path === 'login/mfa') {
        expect(request.headers()['x-csrf-token']).toBe('challenge-token')
        factors.push(request.postDataJSON())
        if (factors.length === 1) return { status: 401, body: error('invalid_credentials', 'Invalid credentials.') }
        signedIn = true
        return { body: { user, csrf_token: 'session-token', mfa_required: false } }
      }
      throw new Error(path)
    })
    await page.goto('/#/login')
    await password(page)
    await expect(page.getByRole('heading', { name: 'Verify your identity' })).toBeVisible()
    await expect(page.locator('#login-password')).toHaveCount(0)
    if (recovery) await page.getByRole('button', { name: 'Use a recovery code', exact: true }).click()
    const input = page.getByLabel(recovery ? 'Recovery code' : 'Authenticator code', { exact: true })
    await input.fill(recovery ? 'abcd-efgh' : '123456')
    await page.getByRole('button', { name: 'Verify', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('Invalid credentials.')
    await expect(input).toHaveValue('')
    expect(factors[0]).toEqual(recovery ? { recovery_code: 'abcd-efgh' } : { code: '123456' })
    await input.fill(recovery ? 'ijkl-mnop' : '654321')
    await page.getByRole('button', { name: 'Verify', exact: true }).click()
    await expect(page).toHaveURL(/#\/overview$/)
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0])
  })
}

test('password clears on error and duplicate requests blocked while busy', async ({ page }) => {
  let requests = 0
  let release
  const gate = new Promise(resolve => { release = resolve })
  await api(page, async path => {
    if (path === 'me') return { status: 401, body: error() }
    requests++
    await gate
    return { status: 429, body: error('rate_limited', 'Too many failed attempts. Try again later.') }
  })
  await page.goto('/#/login')
  await password(page)
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('')
  await expect(page.getByRole('button', { name: 'Signing in…', exact: true })).toBeDisabled()
  expect(requests).toBe(1)
  release()
  await expect(page.getByRole('alert')).toContainText('Too many failed attempts.')
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeEnabled()
})

test('backend network failure never opens protected screens', async ({ page }) => {
  await page.route('**/api/**', route => route.abort())
  await page.goto('/#/overview')
  await expect(page).toHaveURL(/#\/login$/)
  await expect(page.locator('aside')).toHaveCount(0)
  await password(page)
  await expect(page.getByRole('alert')).toContainText('Cannot reach the panel backend.')
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('')
  await expect(page).toHaveURL(/#\/login$/)
})

test('expired session redirects login on protected navigation', async ({ page }) => {
  let expired = false
  await api(page, async path => {
    expect(path).toBe('me')
    return expired ? { status: 401, body: error() } : { body: { user, sudo_until: null } }
  })
  await page.goto('/#/overview')
  await expect(page.locator('header')).toContainText('ada')
  expired = true
  await page.getByRole('link', { name: 'Websites', exact: true }).click()
  await expect(page).toHaveURL(/#\/login$/)
  await expect(page.locator('aside')).toHaveCount(0)
})

for (const [name, body] of [['invalid JSON', '{'], ['null', 'null'], ['missing hostname', JSON.stringify({ ...validInfo, hostname: null })]]) {
  test(`overview rejects malformed info: ${name}`, async ({ page }) => {
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await api(page, async () => ({ body: { user, sudo_until: null } }))
    await page.route('**/api/v1/system/info', route => route.fulfill({ contentType: 'application/json', body }))
    await page.goto('/#/overview')
    await expect(hostCard(page)).toContainText('invalid_response')
    await expect(hostCard(page)).not.toContainText('agent connected')
    await expect(hostCard(page).locator('dl')).toHaveCount(0)
    expect(errors).toEqual([])
  })
}

for (const [name, body] of [
  ['invalid JSON', '{'], ['null', 'null'], ['partial', '{"load1":1}'],
  ['nonnumeric', JSON.stringify({ ...validStats, load5: 'bad' })],
  ['negative', JSON.stringify({ ...validStats, uptime_seconds: -1 })],
  ['inconsistent memory', JSON.stringify({ ...validStats, mem_available_bytes: 2048 })],
]) {
  test(`overview rejects malformed stats: ${name}`, async ({ page }) => {
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await api(page, async () => ({ body: { user, sudo_until: null } }))
    await page.route('**/api/v1/system/stats', route => route.fulfill({ contentType: 'application/json', body }))
    await page.goto('/#/overview')
    await expect(hostCard(page)).toContainText('stats unavailable: invalid_response')
    await expect(hostCard(page)).toContainText('node-01')
    await expect(hostCard(page)).not.toContainText(/undefined|NaN|Infinity|-%/)
    for (const label of ['load 1 / 5 / 15', 'memory used', 'memory free', 'uptime']) {
      await expect(hostCard(page).locator('dl div').filter({ has: page.getByText(label, { exact: true }) }).locator('dd')).toHaveText('—')
    }
    expect(errors).toEqual([])
  })
}

for (const endpoint of ['info', 'stats']) {
  test(`overview ${endpoint} HTTP 401 expires session and clears protected host details`, async ({ page }) => {
    let expired = false
    await api(page, async path => {
      expect(path).toBe('me')
      return expired ? { status: 401, body: error() } : { body: { user, sudo_until: null } }
    })
    await page.goto('/#/overview')
    await expect(hostCard(page)).toContainText('agent connected')
    await page.route(`**/api/v1/system/${endpoint}`, route => {
      expired = true
      return route.fulfill({ status: 401, contentType: 'application/json', body: '{' })
    })
    await hostCard(page).getByRole('button', { name: 'Refresh', exact: true }).click()
    await expect(page).toHaveURL(/#\/login$/)
    await expect(page.locator('aside')).toHaveCount(0)
    await expect(page.getByTestId('session-username')).toHaveCount(0)
    await expect(hostCard(page)).toHaveCount(0)
  })
}

test('system 401 hides previous host details while session recheck is pending', async ({ page }) => {
  let checking = false
  let release
  const gate = new Promise(resolve => { release = resolve })
  await api(page, async () => {
    if (checking) { await gate; return { status: 401, body: error() } }
    return { body: { user, sudo_until: null } }
  })
  await page.goto('/#/overview')
  await expect(hostCard(page)).toContainText('agent connected')
  await page.route('**/api/v1/system/stats', route => {
    checking = true
    return route.fulfill({ status: 401, json: error() })
  })
  await hostCard(page).getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect.poll(() => checking).toBe(true)
  try {
    await expect(hostCard(page).locator('dl')).toHaveCount(0)
  } finally { release() }
  await expect(page).toHaveURL(/#\/login$/)
})

for (const endpoint of ['info', 'stats']) {
  test(`stale ${endpoint} 401 after a newer login cannot expire the new identity`, async ({ page }) => {
    let signedIn = true
    let currentUser = user
    let meChecks = 0
    let hold = true
    let release
    let requested = false
    const gate = new Promise(resolve => { release = resolve })
    await api(page, async path => {
      if (path === 'me') { meChecks++; return signedIn ? { body: { user: currentUser, sudo_until: null } } : { status: 401, body: error() } }
      if (path === 'logout') { signedIn = false; return { body: { ok: true } } }
      if (path === 'login') { signedIn = true; currentUser = { ...user, username: 'new-user' }; return { body: { user: currentUser, csrf_token: 'new-token', mfa_required: false } } }
      throw new Error(path)
    })
    await page.route(`**/api/v1/system/${endpoint}`, async route => {
      if (!hold) return route.fulfill({ json: endpoint === 'info' ? validInfo : validStats })
      requested = true
      await gate
      return route.fulfill({ status: 401, json: error() })
    })
    await page.goto('/#/overview')
    await expect.poll(() => requested).toBe(true)
    await page.getByRole('button', { name: 'Sign out', exact: true }).click()
    await expect(page).toHaveURL(/#\/login$/)
    hold = false
    await password(page)
    await expect(page.getByTestId('session-username')).toHaveText('new-user')
    const before = meChecks
    const rechecked = page.waitForResponse(response => response.url().endsWith('/auth/me'))
    release()
    await rechecked
    await expect.poll(() => meChecks).toBeGreaterThan(before)
    // Current /me stays authenticated; stale host error cannot call expire().
    await expect(page.getByTestId('session-username')).toHaveText('new-user')
    await expect(hostCard(page)).toContainText('agent connected')
    await expect(page).toHaveURL(/#\/overview$/)
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible()
  })
}

test('shell labels live host reads separately from sample controls', async ({ page }) => {
  await api(page, async () => ({ body: { user, sudo_until: null } }))
  await page.goto('/#/overview')
  await expect(hostCard(page)).toContainText('agent connected')
  const banner = page.locator('.design-banner')
  await expect(banner).toContainText('Host data (live)')
  await expect(banner).toContainText('read-only')
  await expect(banner).not.toContainText('All values are example data')
  await expect(banner).not.toContainText('No server operations are executed')
  await expect(page.getByText('SAMPLE SCREENS', { exact: true })).toHaveAttribute('title', /Host data.*live/)
  await expect(page.getByText('Host link: Nominal', { exact: true })).toHaveCount(0)
})

for (const agentUp of [true, false]) {
  test(`overview host card ${agentUp ? 'shows live agent data' : 'reports an unreachable agent without values'}`, async ({ page }) => {
    const systemCalls = []
    await api(page, async path => {
      if (path === 'me') return { body: { user, sudo_until: null } }
      throw new Error(`Unexpected API path ${path}`)
    })
    await page.route('**/api/v1/system/**', async route => {
      const name = new URL(route.request().url()).pathname.split('/system/')[1]
      systemCalls.push(name)
      if (!agentUp) return route.fulfill({ status: 503, json: error('agent_unavailable', 'The host agent is not reachable.') })
      if (name === 'info') return route.fulfill({ json: { ...validInfo, hostname: 'live-node-77', kernel: '7.0.0-test' } })
      if (name === 'stats') return route.fulfill({ json: { ...validStats, load1: 0.25, load5: 0.5, load15: 0.75, mem_total_bytes: 8 * 1024 ** 3, mem_available_bytes: 2 * 1024 ** 3, uptime_seconds: 3700 } })
      throw new Error(`Unexpected system path ${name}`)
    })
    await page.goto('/#/overview')
    const card = page.locator('section', { has: page.getByRole('heading', { name: 'Host data (live)' }) }).first()
    await expect(card).toBeVisible()
    if (agentUp) {
      await expect(card).toContainText('agent connected')
      await expect(card).toContainText('live-node-77')
      await expect(card).toContainText('0.25 / 0.5 / 0.75')
      await expect(card).toContainText('75%')
      await expect(card).toContainText('8.0 GiB')
      await expect(card).toContainText('1h 1m')
      expect(systemCalls).toEqual(['info', 'stats'])
    } else {
      await expect(card).toContainText('agent unavailable')
      await expect(card).toContainText('agent_unavailable')
      await expect(card).not.toContainText('hostname')
      expect(systemCalls).toEqual(['info'])
    }
  })
}
