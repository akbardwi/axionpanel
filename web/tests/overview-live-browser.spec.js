import { test, expect } from '@playwright/test'
const info = { connected: true, hostname: 'prod-real-7', os: 'Debian 13', arch: 'amd64', kernel: '6.12-real', version: 'dev', protocol: 1, capability_revision: 'r' }
const stats = { load1: 0, load5: 1, load15: 2, mem_total_bytes: 8 * 1024 ** 3, mem_available_bytes: 2 * 1024 ** 3, uptime_seconds: 90061 }
const metrics = () => ({
  cpu: { usage_percent: 12.5, logical_cpus: 2 }, cpu_reason: '',
  disk: { mount: '/', total_bytes: 100 * 1024 ** 3, used_bytes: 40 * 1024 ** 3, available_bytes: 60 * 1024 ** 3 }, disk_reason: '',
  network: { interface: 'ens5', rx_bytes_per_second: 2048, tx_bytes_per_second: 1024 }, network_reason: '', observed_at: new Date().toISOString(),
})
async function setup(page, handler) {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user: { username: 'real-user', role: 'admin' }, csrf_token: 'test' } }))
  await page.route('**/api/v1/system/**', async route => {
    const name = new URL(route.request().url()).pathname.split('/').at(-1)
    if (handler && await handler(route, name)) return
    await route.fulfill({ json: name === 'info' ? info : name === 'stats' ? stats : metrics() })
  })
}
const main = page => page.locator('main')

test('original cards show live data and clear only failed metrics on next poll', async ({ page }) => {
  await page.clock.install()
  let fail = false
  const calls = []
  await setup(page, async (route, name) => {
    calls.push(name)
    if (fail && name === 'metrics') { await route.fulfill({ status: 503, json: { error: { code: 'agent_unavailable' } } }); return true }
  })
  await page.goto('/overview')
  await expect(main(page)).toContainText('prod-real-7')
  await expect(main(page)).toContainText('Debian 13 (6.12-real)')
  await expect(main(page)).toContainText('1d 1h')
  await expect(main(page)).toContainText('12.5')
  await expect(main(page)).toContainText('2 logical CPUs')
  await expect(main(page)).toContainText('6.0 GiB')
  await expect(main(page)).toContainText('40.0 GiB')
  await expect(main(page)).toContainText('ens5')
  await expect(main(page)).toContainText('2.0 KiB/s')
  expect(calls).toEqual(['info', 'stats', 'metrics'])
  fail = true
  await page.clock.runFor(5000)
  await expect(main(page)).toContainText('unavailable: agent_unavailable')
  await expect(main(page)).not.toContainText('12.5')
  await expect(main(page)).not.toContainText('ens5')
  await expect(main(page)).toContainText('6.0 GiB')
  expect(calls).toEqual(['info', 'stats', 'metrics', 'info', 'stats', 'metrics'])
})

test('401 on metrics rechecks identity and redirects without stale values', async ({ page }) => {
  let unauthorized = false
  await setup(page, async (route, name) => {
    if (unauthorized && name === 'metrics') { await route.fulfill({ status: 401, json: {} }); return true }
  })
  await page.goto('/overview')
  await expect(main(page)).toContainText('prod-real-7')
  unauthorized = true
  await page.route('**/api/v1/auth/me', route => route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: 'Expired' } } }))
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.locator('body')).not.toContainText('prod-real-7')
})

test('design preview never loads or labels metrics as perpetually loading', async ({ page }) => {
  test.skip(!process.env.TEST_DESIGN_PREVIEW, 'preview server only')
  const calls = []
  page.on('request', req => { if (req.url().includes('/api/')) calls.push(req.url()) })
  await page.goto('/overview')
  await expect(main(page)).toContainText('not loaded in design preview')
  await expect(main(page)).not.toContainText('unavailable: loading')
  expect(calls).toEqual([])
})
