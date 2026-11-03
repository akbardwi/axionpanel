import { test, expect } from '@playwright/test'
// Test-only API interception. Actual app always calls the same-origin backend.
const user = { id: 7, username: 'ada', role: 'operator' }
const error = (code = 'unauthorized', message = 'Sign in required.') => ({ error: { code, message } })
async function api(page, handler) {
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
