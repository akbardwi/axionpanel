import { test, expect } from '@playwright/test'
// Test-only API interception. Actual app always calls the same-origin backend.
const validInfo = { connected: true, hostname: 'node-01', os: 'Ubuntu 26.04', arch: 'amd64', kernel: '7.0.0', version: '0.1.0-dev', protocol: 1, detected_tools: {}, capabilities: {}, capability_revision: 'rev1', observed_at: '2026-11-03T10:00:00Z', operations: ['system.stats', 'system.metrics'] }
const validStats = { load1: 0.5, load5: 0.4, load15: 0.3, mem_total_bytes: 1024, mem_available_bytes: 512, uptime_seconds: 90, observed_at: '2026-11-03T10:00:00Z' }
const validMetrics = () => ({
  observed_at: new Date().toISOString(),
  cpu: { usage_percent: 23.7, logical_cpus: 6 }, cpu_reason: '',
  disk: { mount: '/', total_bytes: 100 * 1024 ** 3, used_bytes: 35 * 1024 ** 3, available_bytes: 65 * 1024 ** 3 }, disk_reason: '',
  network: { interface: 'eth-live-7', rx_bytes_per_second: 2048, tx_bytes_per_second: 1024 }, network_reason: '',
})
const systemBody = endpoint => ({ info: validInfo, stats: validStats, metrics: validMetrics() })[endpoint]
const main = page => page.locator('main')
const cards = page => main(page).locator('.grid.grid-cols-1 > div')
const card = (page, label) => cards(page).filter({ has: page.getByText(label, { exact: true }) })
const cpuCard = page => card(page, 'Processor Load')
const ramCard = page => card(page, 'RAM Memory')
const diskCard = page => card(page, 'Root filesystem (/)')
const netCard = page => card(page, /^Interface /)
const user = { id: 7, username: 'ada', role: 'operator' }
const error = (code = 'unauthorized', message = 'Sign in required.') => ({ error: { code, message } })
async function api(page, handler) {
  await page.route('**/api/v1/system/**', route => {
    const endpoint = new URL(route.request().url()).pathname.split('/').at(-1)
    const body = systemBody(endpoint)
    if (!body) throw new Error(`Unexpected system path ${endpoint}`)
    return route.fulfill({ json: body })
  })
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
async function expectLive(page) {
  await expect(main(page)).toContainText('node-01')
  await expect(main(page).getByText('LIVE / ACTIVE', { exact: true })).toBeVisible()
  await expect(cpuCard(page)).toContainText('23.7%')
  await expect(ramCard(page)).toContainText('512 B')
  await expect(diskCard(page)).toContainText('35.0 GiB')
  await expect(netCard(page)).toContainText('eth-live-7')
}
async function expectResourcesUnavailable(page, reason) {
  await expect(cards(page)).toHaveCount(4)
  for (const resource of [cpuCard(page), ramCard(page), diskCard(page), netCard(page)]) {
    await expect(resource).toContainText(`unavailable: ${reason}`)
    await expect(resource).toContainText('—')
  }
  await expect(cpuCard(page)).not.toContainText('23.7%')
  await expect(ramCard(page)).not.toContainText('512 B')
  await expect(diskCard(page)).not.toContainText('35.0 GiB')
  await expect(netCard(page)).not.toContainText('eth-live-7')
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
  await page.goto('/websites')
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.locator('aside')).toHaveCount(0)
  await password(page)
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.locator('header')).toContainText('ada')
  await expect(page.locator('header')).toContainText('operator')
  await expect(page.getByText('SAMPLE SCREENS', { exact: true })).toBeVisible()
  await page.reload()
  await expect(page.locator('header')).toContainText('ada')
  await context.addCookies([{ name: 'axp_csrf', value: 'live-cookie', url: 'http://127.0.0.1:15175', sameSite: 'Strict' }])
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(page).toHaveURL(/\/login$/)
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
    await page.goto('/login')
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
    await expect(page).toHaveURL(/\/overview$/)
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
  await page.goto('/login')
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
  await page.goto('/overview')
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.locator('aside')).toHaveCount(0)
  await password(page)
  await expect(page.getByRole('alert')).toContainText('Cannot reach the panel backend.')
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('')
  await expect(page).toHaveURL(/\/login$/)
})

test('expired session redirects login on protected navigation', async ({ page }) => {
  let expired = false
  await api(page, async path => {
    expect(path).toBe('me')
    return expired ? { status: 401, body: error() } : { body: { user, sudo_until: null } }
  })
  await page.goto('/overview')
  await expect(page.locator('header')).toContainText('ada')
  expired = true
  await page.getByRole('link', { name: 'Websites', exact: true }).click()
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.locator('aside')).toHaveCount(0)
})

for (const [name, body] of [['invalid JSON', '{'], ['null', 'null'], ['missing hostname', JSON.stringify({ ...validInfo, hostname: null })]]) {
  test(`overview rejects malformed info: ${name}`, async ({ page }) => {
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await api(page, async () => ({ body: { user, sudo_until: null } }))
    await page.route('**/api/v1/system/info', route => route.fulfill({ contentType: 'application/json', body }))
    await page.goto('/overview')
    await expectResourcesUnavailable(page, 'invalid_response')
    await expect(main(page)).toContainText('AGENT UNAVAILABLE')
    await expect(main(page)).not.toContainText('LIVE / ACTIVE')
    await expect(main(page)).not.toContainText('node-01')
    await expect(main(page)).toContainText('Uptime: —')
    await expect(main(page)).toContainText('RAM: —')
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
    await page.goto('/overview')
    await expect(ramCard(page)).toContainText('unavailable: invalid_response')
    await expect(ramCard(page)).toContainText('— / —')
    await expect(ramCard(page)).not.toContainText('512 B')
    await expect(main(page)).toContainText('node-01')
    await expect(main(page)).toContainText('Uptime: —')
    await expect(main(page)).toContainText('RAM: —')
    await expect(cpuCard(page).getByText('Load:', { exact: true }).locator('..').locator('span.font-mono')).toHaveText('—')
    // A stats failure must not discard the independent metrics response.
    await expect(cpuCard(page)).toContainText('23.7%')
    await expect(diskCard(page)).toContainText('35.0 GiB')
    await expect(netCard(page)).toContainText('eth-live-7')
    await expect(main(page)).not.toContainText(/undefined|NaN|Infinity|-%/)
    expect(errors).toEqual([])
  })
}

for (const [name, body] of [
  ['invalid JSON', '{'], ['null', 'null'], ['partial', '{"cpu":null}'],
  ['nonnumeric CPU', JSON.stringify({ ...validMetrics(), cpu: { usage_percent: 'bad', logical_cpus: 6 } })],
  ['out-of-range CPU', JSON.stringify({ ...validMetrics(), cpu: { usage_percent: 101, logical_cpus: 6 } })],
  ['inconsistent disk', JSON.stringify({ ...validMetrics(), disk: { mount: '/', total_bytes: 10, used_bytes: 8, available_bytes: 8 } })],
  ['negative network', JSON.stringify({ ...validMetrics(), network: { interface: 'eth-live-7', rx_bytes_per_second: -1, tx_bytes_per_second: 0 } })],
  ['bad observation', JSON.stringify({ ...validMetrics(), observed_at: 'yesterday' })],
]) {
  test(`overview rejects malformed metrics: ${name}`, async ({ page }) => {
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await api(page, async () => ({ body: { user, sudo_until: null } }))
    await page.route('**/api/v1/system/metrics', route => route.fulfill({ contentType: 'application/json', body }))
    await page.goto('/overview')
    for (const resource of [cpuCard(page), diskCard(page), netCard(page)]) {
      await expect(resource).toContainText('unavailable: invalid_response')
      await expect(resource).toContainText('—')
    }
    await expect(cpuCard(page)).not.toContainText('23.7%')
    await expect(diskCard(page)).not.toContainText('35.0 GiB')
    await expect(netCard(page)).not.toContainText('eth-live-7')
    await expect(ramCard(page)).toContainText('512 B')
    await expect(cpuCard(page)).toContainText('0.50 / 0.40 / 0.30')
    await expect(main(page)).toContainText('node-01')
    await expect(main(page)).toContainText('Uptime: 1m 30s')
    await expect(main(page)).not.toContainText(/undefined|NaN|Infinity|-%/)
    expect(errors).toEqual([])
  })
}

for (const endpoint of ['info', 'stats', 'metrics']) {
  test(`overview ${endpoint} HTTP 401 expires session and clears protected host details`, async ({ page }) => {
    let expired = false
    await api(page, async path => {
      expect(path).toBe('me')
      return expired ? { status: 401, body: error() } : { body: { user, sudo_until: null } }
    })
    await page.goto('/overview')
    await expectLive(page)
    await page.route(`**/api/v1/system/${endpoint}`, route => {
      expired = true
      return route.fulfill({ status: 401, contentType: 'application/json', body: '{' })
    })
    await main(page).getByRole('button', { name: 'Refresh', exact: true }).click()
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.locator('aside')).toHaveCount(0)
    await expect(page.getByTestId('session-username')).toHaveCount(0)
    await expect(cards(page)).toHaveCount(0)
    await expect(page.locator('body')).not.toContainText(/node-01|23\.7%|512 B|35\.0 GiB|eth-live-7/)
  })

  test(`system ${endpoint} 401 hides previous host details while session recheck is pending`, async ({ page }) => {
    let checking = false
    let release
    const gate = new Promise(resolve => { release = resolve })
    await api(page, async () => {
      if (checking) { await gate; return { status: 401, body: error() } }
      return { body: { user, sudo_until: null } }
    })
    await page.goto('/overview')
    await expectLive(page)
    await page.route(`**/api/v1/system/${endpoint}`, route => {
      checking = true
      return route.fulfill({ status: 401, json: error() })
    })
    await main(page).getByRole('button', { name: 'Refresh', exact: true }).click()
    await expect.poll(() => checking).toBe(true)
    try {
      // /me is held: values must clear before navigation, not merely unmount.
      await expect(page).toHaveURL(/\/overview$/)
      await expect(cards(page)).toHaveCount(4)
      await expect(main(page)).not.toContainText(/node-01|23\.7%|512 B|35\.0 GiB|eth-live-7/)
      for (const resource of [cpuCard(page), ramCard(page), diskCard(page), netCard(page)]) await expect(resource).toContainText('—')
      await expect(main(page)).toContainText('Uptime: —')
      await expect(main(page)).toContainText('RAM: —')
    } finally { release() }
    await expect(page).toHaveURL(/\/login$/)
  })

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
      if (!hold) return route.fulfill({ json: systemBody(endpoint) })
      requested = true
      await gate
      return route.fulfill({ status: 401, json: error() })
    })
    await page.goto('/overview')
    await expect.poll(() => requested).toBe(true)
    await page.getByRole('button', { name: 'Sign out', exact: true }).click()
    await expect(page).toHaveURL(/\/login$/)
    hold = false
    await password(page)
    await expect(page.getByTestId('session-username')).toHaveText('new-user')
    await expectLive(page)
    const before = meChecks
    const oldResponse = page.waitForResponse(response => response.url().endsWith('/system/' + endpoint) && response.status() === 401)
    release()
    await (await oldResponse).finished()
    // Drain the fetch continuation. An unmounted view must neither recheck
    // identity nor publish its null result into the new Overview instance.
    await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 100)))
    expect(meChecks).toBe(before)
    await expect(page.getByTestId('session-username')).toHaveText('new-user')
    await expectLive(page)
    await expect(page).toHaveURL(/\/overview$/)
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible()
  })
}

test('shell labels live Overview metrics separately from sample controls', async ({ page }) => {
  await api(page, async () => ({ body: { user, sudo_until: null } }))
  await page.goto('/overview')
  await expectLive(page)
  const banner = page.locator('.design-banner')
  await expect(banner).toContainText(/Overview/i)
  await expect(banner).toContainText(/metrics/i)
  await expect(banner).toContainText('read-only')
  await expect(banner).toContainText('local agent')
  await expect(banner).toContainText(/screens.*example/i)
  await expect(banner).not.toContainText('All values are example data')
  await expect(banner).not.toContainText('No server operations are executed')
  await expect(page.getByText('SAMPLE SCREENS', { exact: true })).toHaveAttribute('title', /Overview metrics.*local agent.*other.*screens/i)
  await expect(page.getByText('Host link: Nominal', { exact: true })).toHaveCount(0)
})

for (const agentUp of [true, false]) {
  test(`overview existing resource cards ${agentUp ? 'show live agent data' : 'report an unreachable agent without values'}`, async ({ page }) => {
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
      if (name === 'metrics') return route.fulfill({ json: validMetrics() })
      throw new Error(`Unexpected system path ${name}`)
    })
    await page.goto('/overview')
    await expect(main(page)).toBeVisible()
    await expect(cards(page)).toHaveCount(4)
    await expect(page.getByRole('heading', { name: 'Host data (live)' })).toHaveCount(0)
    await expect(main(page)).not.toContainText('Host data (live)')
    if (agentUp) {
      await expect(main(page)).toContainText('LIVE / ACTIVE')
      await expect(main(page)).toContainText('live-node-77')
      await expect(main(page)).toContainText('Ubuntu 26.04 (7.0.0-test)')
      await expect(main(page)).toContainText('amd64')
      await expect(main(page)).toContainText('Uptime: 1h 1m')
      await expect(main(page)).toContainText('RAM: 8.0 GiB')
      await expect(cpuCard(page)).toContainText('0.25 / 0.50 / 0.75')
      await expect(cpuCard(page)).toContainText('23.7%')
      await expect(cpuCard(page)).toContainText('6 logical CPUs')
      await expect(ramCard(page)).toContainText('6.0 GiB / 8.0 GiB')
      await expect(ramCard(page)).toContainText('75.0%')
      await expect(ramCard(page).getByText('2.0 GiB', { exact: true })).toBeVisible()
      await expect(diskCard(page)).toContainText('35.0 GiB / 100.0 GiB')
      await expect(diskCard(page)).toContainText('35.0%')
      await expect(diskCard(page)).toContainText('65.0 GiB free')
      await expect(netCard(page)).toContainText('Interface eth-live-7')
      await expect(netCard(page)).toContainText('3.0 KiB/s')
      await expect(netCard(page).locator('div').filter({ hasText: 'Inbound (RX)' }).last()).toContainText('2.0 KiB/s')
      await expect(netCard(page).locator('div').filter({ hasText: 'Outbound (TX)' }).last()).toContainText('1.0 KiB/s')
      expect(systemCalls).toEqual(['info', 'stats', 'metrics'])
    } else {
      await expectResourcesUnavailable(page, 'agent_unavailable')
      await expect(main(page)).toContainText('AGENT UNAVAILABLE')
      await expect(main(page)).not.toContainText('live-node-77')
      await expect(main(page)).not.toContainText('LIVE / ACTIVE')
      await expect(main(page)).toContainText('OS unavailable')
      await expect(main(page)).toContainText('Uptime: —')
      await expect(main(page)).toContainText('RAM: —')
      expect(systemCalls).toEqual(['info'])
    }
  })
}
