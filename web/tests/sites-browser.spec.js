import { test, expect } from '@playwright/test'

// Browser smoke for the live Websites screen. API responses are mocked so the
// test exercises the real Vue state machine without touching host Nginx.
const info = { connected: true, hostname: 'integration-real', os: 'Debian 13', arch: 'arm64', kernel: '6.12-integration', version: 'dev', protocol: 1, capability_revision: 'r' }
async function setup(page, { supported = true, sites = [], plan = null, create = null } = {}) {
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user: { username: 'operator', role: 'admin' }, csrf_token: 'test-csrf' } }))
  await page.route('**/api/v1/system/info', route => {
    if (supported) return route.fulfill({ json: { ...info, operations: ['site.plan', 'site.apply', 'site.remove', 'site.status'] } })
    return route.fulfill({ json: { ...info, operations: ['system.info'] } })
  })
  await page.route('**/api/v1/sites/plan*', async route => {
    await route.fulfill({ json: plan ?? { domain: new URL(route.request().url()).searchParams.get('domain'), vhost: '/conf/test.conf', root: '/var/www/sites', listen: '127.0.0.1:8081', applied: false, would_do: 'create' } })
  })
  await page.route('**/api/v1/sites', route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: { data: sites, meta: { total: sites.length } } })
    if (!create && !sites.length) sites.push({ id: 9, domain: 'new.example', kind: 'static', listen: '127.0.0.1:8081', root: '/var/www/sites/new.example', status: 'active', last_error: '', retained_content: false })
    return route.fulfill({ status: create?.status ?? 200, json: create?.body ?? { site: { id: 9, domain: 'new.example', kind: 'static', listen: '127.0.0.1:8081', root: '/var/www/sites/new.example', status: 'active', last_error: '', created_at: '2026-11-07T00:00:00Z', updated_at: '2026-11-07T00:00:00Z', retained_content: false }, job: { id: 'a'.repeat(32), status: 'succeeded', target_type: 'static_site', target_id: 9, error: '', created_at: '2026-11-07T00:00:00Z' }, mode: 'synchronous' } })
  })
}

test('unsupported agent keeps inventory visible but create explicitly unavailable', async ({ page }) => {
  await setup(page, { supported: false, sites: [{ id: 1, domain: 'kept.example', kind: 'static', listen: '127.0.0.1:8080', root: '/var/www/sites/kept.example', status: 'active', last_error: '', created_at: 'now', updated_at: 'now', retained_content: false }] })
  await page.goto('/websites')
  await expect(page.getByRole('heading', { name: 'Websites' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'kept.example' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'kept.example' }).locator('..').getByRole('button', { name: 'Remove' })).toBeDisabled()
  await expect(page.getByText('Website operations are opt-in and disabled by default.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create website' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Review plan' })).toBeDisabled()
})

test('plan-gated creation renders a succeeded host job and refreshes the inventory', async ({ page }) => {
  await setup(page, { sites: [], plan: { domain: 'new.example', vhost: '/var/www/sites/new.example.conf', root: '/var/www/sites/new.example', listen: '127.0.0.1:8081', applied: false, would_do: 'create' } })
  await page.goto('/websites')
  await expect(page.getByText('No static websites are recorded')).toBeVisible()
  await page.getByLabel('Domain', { exact: true }).fill('new.example')
  await page.getByRole('button', { name: 'Review plan' }).click()
  await expect(page.getByText('Host configuration has not changed by this plan.')).toBeVisible()
  await page.getByRole('button', { name: 'Create website' }).click()
  await expect(page.getByText('succeeded', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Refresh inventory' }).click()
  await expect(page.getByRole('cell', { name: 'new.example' })).toBeVisible()
  await expect(page.getByText('Site content was retained at /var/www/sites/new.example')).toHaveCount(0)
})

test('HTTP 200 failed job is a failure, not a silent success', async ({ page }) => {
  const failedCreate = { status: 200, body: { site: { id: 9, domain: 'new.example', kind: 'static', listen: '', root: '', status: 'error', last_error: 'operation interrupted', created_at: 'now', updated_at: 'now', retained_content: false }, job: { id: 'b'.repeat(32), status: 'failed', target_type: 'static_site', target_id: 9, error: 'isolated nginx failed', created_at: 'now' }, mode: 'synchronous' } }
  await setup(page, { sites: [], create: failedCreate })
  await page.goto('/websites')
  await page.getByLabel('Domain', { exact: true }).fill('new.example')
  await page.getByRole('button', { name: 'Review plan' }).click()
  await page.getByRole('button', { name: 'Create website' }).click()
  await expect(page.getByText('failed', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('isolated nginx failed', { exact: true })).toBeVisible()
})
