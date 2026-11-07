import { test, expect } from '@playwright/test'

const info = { connected: true, hostname: 'lifecycle-host', os: 'Debian 13', arch: 'amd64', kernel: '6.12', version: 'dev', protocol: 1, capability_revision: 'r' }
const stats = { load1: 0, load5: 1, load15: 2, mem_total_bytes: 8192, mem_available_bytes: 4096, uptime_seconds: 120 }
const metrics = observed_at => ({
  observed_at,
  cpu: { usage_percent: 12.5, logical_cpus: 2 }, cpu_reason: '',
  disk: { mount: '/', total_bytes: 8192, used_bytes: 4096, available_bytes: 4096 }, disk_reason: '',
  network: { interface: 'eth0', rx_bytes_per_second: 15.98082301238514, tx_bytes_per_second: 0 }, network_reason: '',
})
async function setup(page, handler) {
  await page.addInitScript(() => {
    window.hostEvents = []
    window.addEventListener('axp:host', event => window.hostEvents.push(event.detail))
  })
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user: { username: 'tester', role: 'admin' }, csrf_token: 'test' } }))
  await page.route('**/api/v1/system/**', async route => {
    const name = new URL(route.request().url()).pathname.split('/').at(-1)
    if (handler && await handler(route, name)) return
    const observed = await page.evaluate(() => new Date().toISOString())
    await route.fulfill({ json: name === 'info' ? info : name === 'stats' ? stats : metrics(observed) })
  })
}
const sidebar = page => page.locator('aside').filter({ hasText: 'Host specs' })
const leaveOverview = async page => {
  // Websites now legitimately reads system/info for its operation catalog.
  // Use an inert design screen to isolate Overview poller teardown.
  await page.getByRole('link', { name: 'Databases', exact: true }).click()
  await expect(page).toHaveURL(/\/databases$/)
}

test('Overview unmount clears sidebar LIVE through existing host event', async ({ page }) => {
  await setup(page)
  await page.goto('/overview')
  await expect(sidebar(page)).toContainText('lifecycle-host')
  await expect(sidebar(page).getByText('LIVE', { exact: true })).toBeVisible()
  await leaveOverview(page)
  await expect(sidebar(page).getByText('LIVE', { exact: true })).toHaveCount(0)
  await expect(sidebar(page)).not.toContainText('lifecycle-host')
  await expect(sidebar(page)).toContainText('UNAVAILABLE')
  expect(await page.evaluate(() => window.hostEvents.at(-1))).toBeNull()
})

test('hung poll still ages existing metrics on reactive browser clock', async ({ page }) => {
  const start = new Date('2026-11-04T12:00:00Z')
  await page.clock.install({ time: start })
  let infoReads = 0
  let stalled
  await setup(page, async (route, name) => {
    if (name === 'info' && ++infoReads > 1) {
      stalled = route
      return true
    }
  })
  await page.goto('/overview')
  await expect(page.locator('main')).toContainText('live · updates every 5s')
  await expect(page.locator('main')).not.toContainText('15.98082301238514')
  await page.clock.runFor(5000)
  await expect.poll(() => Boolean(stalled)).toBe(true)
  await page.clock.runFor(11000)
  await expect(page.locator('main')).toContainText('live · values may be stale')
  await expect(page.locator('main')).toContainText('12.5')
  expect(infoReads).toBe(2)
  await leaveOverview(page)
  await stalled.abort()
  await page.clock.runFor(30000)
  expect(infoReads).toBe(2)
  expect(await page.evaluate(() => window.hostEvents.at(-1))).toBeNull()
})

for (const endpoint of ['info', 'stats', 'metrics']) {
  test(`late ${endpoint} 401 from abandoned Overview cannot clear a fresh instance`, async ({ page }) => {
    await page.clock.install()
    let authCalls = 0
    page.on('request', req => { if (req.url().includes('/api/v1/auth/me')) authCalls++ })
    let deferEndpoint = true
    let held
    await setup(page, async (route, name) => {
      if (name === endpoint && deferEndpoint) {
        deferEndpoint = false
        held = route
        return true
      }
    })
    await page.goto('/overview')
    await expect.poll(() => Boolean(held)).toBe(true)
    await leaveOverview(page)
    await page.getByRole('link', { name: 'Overview & Metrics', exact: true }).click()
    await expect(page).toHaveURL(/\/overview$/)
    await expect(sidebar(page)).toContainText('lifecycle-host')
    const authBefore = authCalls
    const eventsBefore = await page.evaluate(() => window.hostEvents)
    const response = page.waitForResponse(r => r.url().endsWith('/system/' + endpoint) && r.status() === 401)
    await held.fulfill({ status: 401, json: {} })
    await (await response).finished()
    await page.clock.runFor(1000)
    await expect(sidebar(page)).toContainText('lifecycle-host')
    await expect(sidebar(page).getByText('LIVE', { exact: true })).toBeVisible()
    await expect(page.locator('main')).toContainText('12.5')
    expect(await page.evaluate(() => window.hostEvents)).toEqual(eventsBefore)
    expect(authCalls).toBe(authBefore)
  })
}
